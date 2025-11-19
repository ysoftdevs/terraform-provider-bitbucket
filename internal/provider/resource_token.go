package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ProviderData contains configuration passed from the provider to the resource.
type ProviderData struct {
	AuthHeader    string
	ServerURL     string
	TLSSkipVerify bool
}

// BitbucketTokenResource manages Bitbucket repository access tokens.
type BitbucketTokenResource struct {
	authHeader    string
	serverURL     string
	tlsSkipVerify bool
}

func NewBitbucketTokenResource() resource.Resource {
	return &BitbucketTokenResource{}
}

// BitbucketTokenResourceModel maps Terraform schema attributes to Go fields.
type BitbucketTokenResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	TokenName          types.String `tfsdk:"token_name"` // prefix provided by user
	ProjectName        types.String `tfsdk:"project_name"`
	RepositoryName     types.String `tfsdk:"repository_name"`
	Token              types.String `tfsdk:"token"`                // secret; returned only on creation; preserved from state
	CurrentTokenName   types.String `tfsdk:"current_token_name"`   // actual token identifier (prefix-epoch)
	CurrentTokenExpiry types.Int64  `tfsdk:"current_token_expiry"` // ms since epoch
}

// Metadata defines the Terraform resource type name.
func (r *BitbucketTokenResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "bitbucket_token"
}

// Schema defines the Terraform resource schema.
func (r *BitbucketTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Bitbucket access tokens for a repository. The token secret is only returned when created and is preserved in state for reuse while valid.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"token_name": schema.StringAttribute{
				Description: "Name prefix for the Bitbucket access token. Actual token will be created as '<prefix>-<epoch_ms>'.",
				Required:    true,
			},
			"project_name": schema.StringAttribute{
				Description: "Name/key of the Bitbucket project.",
				Required:    true,
			},
			"repository_name": schema.StringAttribute{
				Description: "Slug/name of the Bitbucket repository.",
				Required:    true,
			},
			"token": schema.StringAttribute{
				Description: "Bitbucket access token secret (only returned on creation; preserved from state if still valid).",
				Computed:    true,
				Sensitive:   true,
			},
			"current_token_name": schema.StringAttribute{
				Description: "Identifier of the currently managed token (e.g., '<prefix>-<epoch_ms>').",
				Computed:    true,
			},
			"current_token_expiry": schema.Int64Attribute{
				Description: "Expiry of the current token in milliseconds since epoch.",
				Computed:    true,
			},
		},
	}
}

// Configure sets up provider-level data for the resource.
func (r *BitbucketTokenResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("Expected *ProviderData, got: %T", req.ProviderData),
		)
		return
	}

	if providerData.ServerURL == "" {
		resp.Diagnostics.AddError(
			"Invalid Provider Configuration",
			"The 'server_url' cannot be empty.",
		)
		return
	}

	r.authHeader = providerData.AuthHeader
	r.serverURL = providerData.ServerURL
	r.tlsSkipVerify = providerData.TLSSkipVerify
}

// httpClient creates a custom HTTP client with optional TLS skip verification.
func (r *BitbucketTokenResource) httpClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: r.tlsSkipVerify}, // #nosec G402 - intentional per user config
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
	}
}

// tokenInfo describes an access token returned by listing API.
type tokenInfo struct {
	Name        string
	ExpiryMs    int64
	Permissions []string
}

// listTokens lists all tokens for a repo and filters by prefix; returns all matches.
func (r *BitbucketTokenResource) listTokens(auth, baseURL, project, repo, prefix string) ([]tokenInfo, error) {
	apiURL := fmt.Sprintf("%s/rest/access-tokens/latest/projects/%s/repos/%s?limit=10000", baseURL, project, repo)
	client := r.httpClient()

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Bitbucket API returned %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	var jsonResp map[string]interface{}
	_ = json.Unmarshal(body, &jsonResp)

	values, _ := jsonResp["values"].([]interface{})
	var out []tokenInfo
	for _, v := range values {
		obj, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		if len(name) < len(prefix) || name[:len(prefix)] != prefix {
			continue
		}
		exp, _ := obj["expiryDate"].(float64) // ms since epoch
		expMs := int64(exp)

		var perms []string
		if ps, ok := obj["permissions"].([]interface{}); ok {
			for _, p := range ps {
				if s, ok := p.(string); ok {
					perms = append(perms, s)
				}
			}
		}
		out = append(out, tokenInfo{
			Name:        name,
			ExpiryMs:    expMs,
			Permissions: perms,
		})
	}
	return out, nil
}

// getTokenByName searches list results for an exact name.
func getTokenByName(tokens []tokenInfo, name string) *tokenInfo {
	for i := range tokens {
		if tokens[i].Name == name {
			return &tokens[i]
		}
	}
	return nil
}

// createToken creates a new access token and returns (secret, name, expiryMs).
func (r *BitbucketTokenResource) createToken(auth, baseURL, project, repo, prefix string) (string, string, int64, error) {
	putURL := fmt.Sprintf("%s/rest/access-tokens/latest/projects/%s/repos/%s", baseURL, project, repo)
	payload := map[string]interface{}{
		"expiryDays":  90,
		"name":        fmt.Sprintf("%s-%d", prefix, time.Now().UnixMilli()),
		"permissions": []string{"REPO_READ"},
	}
	bodyBytes, _ := json.Marshal(payload)

	client := r.httpClient()
	req, _ := http.NewRequest("PUT", putURL, bytes.NewReader(bodyBytes))
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", "", 0, fmt.Errorf("Bitbucket API returned %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	var jsonResp map[string]interface{}
	_ = json.Unmarshal(body, &jsonResp)

	secret, _ := jsonResp["token"].(string)
	name, _ := jsonResp["name"].(string)
	exp, _ := jsonResp["expiryDate"].(float64)
	expMs := int64(exp)

	if secret == "" || name == "" || expMs == 0 {
		return "", "", 0, fmt.Errorf("API response missing fields (token/name/expiryDate): %s", string(body))
	}

	return secret, name, expMs, nil
}

// deleteToken removes a token by name.
func (r *BitbucketTokenResource) deleteToken(auth, baseURL, project, repo, name string) error {
	client := r.httpClient()
	delURL := fmt.Sprintf("%s/rest/access-tokens/latest/projects/%s/repos/%s/%s", baseURL, project, repo, name)

	req, _ := http.NewRequest("DELETE", delURL, nil)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Bitbucket returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ensureToken ensures we end with a valid token secret in state.
// If state has a valid token → keep its secret.
// If missing/expired → delete expired (if any) and create a fresh one.
func (r *BitbucketTokenResource) ensureToken(data *BitbucketTokenResourceModel) (*BitbucketTokenResourceModel, error) {
	project := data.ProjectName.ValueString()
	repo := data.RepositoryName.ValueString()
	prefix := data.TokenName.ValueString()

	tokens, err := r.listTokens(r.authHeader, r.serverURL, project, repo, prefix)
	if err != nil {
		return nil, err
	}

	nowMs := time.Now().UnixMilli()
	thresholdMs := int64(30 * 24 * time.Hour / time.Millisecond)

	stateName := data.CurrentTokenName.ValueString()
	stateSecret := data.Token.ValueString()

	if stateName != "" && stateSecret != "" {
		if t := getTokenByName(tokens, stateName); t != nil {
			timeLeft := t.ExpiryMs - nowMs
			if timeLeft > thresholdMs {
				data.Token = types.StringValue(stateSecret)
				data.CurrentTokenName = types.StringValue(t.Name)
				data.CurrentTokenExpiry = types.Int64Value(t.ExpiryMs)
				return data, nil
			}
			_ = r.deleteToken(r.authHeader, r.serverURL, project, repo, stateName)
		}
	}

	for _, t := range tokens {
		if t.ExpiryMs <= nowMs {
			_ = r.deleteToken(r.authHeader, r.serverURL, project, repo, t.Name)
		}
	}

	secret, newName, expiry, err := r.createToken(r.authHeader, r.serverURL, project, repo, prefix)
	if err != nil {
		return nil, err
	}

	data.Token = types.StringValue(secret)
	data.CurrentTokenName = types.StringValue(newName)
	data.CurrentTokenExpiry = types.Int64Value(expiry)

	return data, nil
}

// Create — always produces a token value. Since no prior state exists,
// we create a fresh token (after cleaning up any expired ones for the prefix).
func (r *BitbucketTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.ensureToken(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error ensuring token", err.Error())
		return
	}

	out.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", out.ProjectName.ValueString(), out.RepositoryName.ValueString(), out.TokenName.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, out)...)
}

// Read — does not create new tokens (to keep Read side-effect free).
// If the tracked token is missing or expired, remove from state so the next Apply will recreate it.
func (r *BitbucketTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	project := data.ProjectName.ValueString()
	repo := data.RepositoryName.ValueString()
	prefix := data.TokenName.ValueString()

	tokens, err := r.listTokens(r.authHeader, r.serverURL, project, repo, prefix)
	if err != nil {
		resp.Diagnostics.AddError("Error listing tokens", err.Error())
		return
	}

	nowMs := time.Now().UnixMilli()
	thresholdMs := int64(30 * 24 * time.Hour / time.Millisecond)

	stateName := data.CurrentTokenName.ValueString()
	var valid bool

	if stateName != "" {
		if t := getTokenByName(tokens, stateName); t != nil {
			timeLeft := t.ExpiryMs - nowMs
			if timeLeft > thresholdMs {
				data.CurrentTokenExpiry = types.Int64Value(t.ExpiryMs)
				valid = true
			}
		}
	}

	if !valid {
		// Not present or expired -> remove from state; next Apply will create a new one in Create/Update paths.
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update — same semantics as Create: ensure we output a valid token value.
// If state has a valid token, reuse its secret; otherwise delete expired and create new.
func (r *BitbucketTokenResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Carry over prior state (for secret) if present.
	var state BitbucketTokenResourceModel
	_ = req.State.Get(ctx, &state)

	// Start from plan but keep any state-held secret/name/expiry for reuse.
	if !state.Token.IsNull() && !state.Token.IsUnknown() {
		plan.Token = state.Token
	}
	if !state.CurrentTokenName.IsNull() && !state.CurrentTokenName.IsUnknown() {
		plan.CurrentTokenName = state.CurrentTokenName
	}
	if !state.CurrentTokenExpiry.IsNull() && !state.CurrentTokenExpiry.IsUnknown() {
		plan.CurrentTokenExpiry = state.CurrentTokenExpiry
	}

	out, err := r.ensureToken(&plan)
	if err != nil {
		resp.Diagnostics.AddError("Error ensuring token on update", err.Error())
		return
	}

	out.ID = types.StringValue(fmt.Sprintf("%s/%s/%s", out.ProjectName.ValueString(), out.RepositoryName.ValueString(), out.TokenName.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, out)...)
}

// Delete removes the tracked token if it still exists.
func (r *BitbucketTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	project := data.ProjectName.ValueString()
	repo := data.RepositoryName.ValueString()
	name := data.CurrentTokenName.ValueString()

	if name != "" {
		if err := r.deleteToken(r.authHeader, r.serverURL, project, repo, name); err != nil {
			resp.Diagnostics.AddWarning("Error deleting token", err.Error())
		}
	}

	resp.State.RemoveResource(ctx)
}
