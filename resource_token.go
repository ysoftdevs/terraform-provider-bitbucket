package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ProviderData struct {
	AuthHeader string
	ServerURL  string
}

type BitbucketTokenResource struct {
	authHeader string
	serverURL  string
}

func NewBitbucketTokenResource() resource.Resource {
	return &BitbucketTokenResource{}
}

type BitbucketTokenResourceModel struct {
	ID             types.String `tfsdk:"id"`
	TokenName      types.String `tfsdk:"token_name"`
	ProjectName    types.String `tfsdk:"project_name"`
	RepositoryName types.String `tfsdk:"repository_name"`
	Token          types.String `tfsdk:"token"`
}

func (r *BitbucketTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "bitbucket_token"
}

func (r *BitbucketTokenResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Bitbucket access tokens for a repository.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"token_name": schema.StringAttribute{
				Description: "Name prefix for the Bitbucket access token.",
				Required:    true,
			},
			"project_name": schema.StringAttribute{
				Description: "Name of the Bitbucket project.",
				Required:    true,
			},
			"repository_name": schema.StringAttribute{
				Description: "Name of the Bitbucket repository.",
				Required:    true,
			},
			"token": schema.StringAttribute{
				Description: "Generated Bitbucket access token (sensitive).",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func (r *BitbucketTokenResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		resp.Diagnostics.AddError(
			"Missing provider configuration",
			"The Bitbucket provider was not configured before using this resource.",
		)
		return
	}

	providerData, ok := req.ProviderData.(ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("Expected ProviderData, got: %T", req.ProviderData),
		)
		return
	}

	if providerData.ServerURL == "" {
		resp.Diagnostics.AddError(
			"Invalid provider configuration",
			"The 'server_url' in provider configuration cannot be empty.",
		)
		return
	}

	r.authHeader = providerData.AuthHeader
	r.serverURL = providerData.ServerURL
}

func (r *BitbucketTokenResource) getExistingToken(auth, baseURL, project, repo, name string) (string, error) {
	apiURL := fmt.Sprintf("%s/rest/access-tokens/latest/projects/%s/repos/%s?limit=10000", baseURL, project, repo)
	client := &http.Client{Timeout: 15 * time.Second}

	reqGet, _ := http.NewRequest("GET", apiURL, nil)
	reqGet.Header.Add("Authorization", "Basic "+auth)
	respGet, err := client.Do(reqGet)
	if err != nil {
		return "", err
	}
	defer respGet.Body.Close()

	body, _ := io.ReadAll(respGet.Body)
	var respJSON map[string]interface{}
	_ = json.Unmarshal(body, &respJSON)

	values, _ := respJSON["values"].([]interface{})
	now := time.Now().UnixMilli()
	var latestExpiry int64
	var latestToken string

	for _, v := range values {
		obj, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		n, _ := obj["name"].(string)
		eFloat, _ := obj["expiryDate"].(float64)
		e := int64(eFloat) * 1000
		if len(n) >= len(name) && n[:len(name)] == name && e > now && e > latestExpiry {
			latestExpiry = e
			latestToken = n
		}
	}

	if latestToken == "" {
		return "", nil
	}
	return latestToken, nil
}

func (r *BitbucketTokenResource) createToken(auth, baseURL, project, repo, name string) (string, error) {
	now := time.Now().UnixMilli()
	putURL := fmt.Sprintf("%s/rest/access-tokens/latest/projects/%s/repos/%s", baseURL, project, repo)
	payload := map[string]interface{}{
		"expiryDays":  90,
		"name":        fmt.Sprintf("%s-%d", name, now),
		"permissions": []string{"REPO_READ"},
	}

	payloadBytes, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 15 * time.Second}
	reqPut, _ := http.NewRequest("PUT", putURL, bytes.NewReader(payloadBytes))
	reqPut.Header.Add("Authorization", "Basic "+auth)
	reqPut.Header.Add("Content-Type", "application/json")

	respPut, err := client.Do(reqPut)
	if err != nil {
		return "", err
	}
	defer respPut.Body.Close()

	bodyPut, _ := io.ReadAll(respPut.Body)
	var putJSON map[string]interface{}
	_ = json.Unmarshal(bodyPut, &putJSON)

	tok, _ := putJSON["token"].(string)
	if tok == "" {
		return "", fmt.Errorf("failed to obtain token from API response: %s", string(bodyPut))
	}

	return tok, nil
}

// Create resource
func (r *BitbucketTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	existing, err := r.getExistingToken(
		r.authHeader,
		r.serverURL,
		data.ProjectName.ValueString(),
		data.RepositoryName.ValueString(),
		data.TokenName.ValueString(),
	)
	if err != nil {
		resp.Diagnostics.AddError("Error checking existing token", err.Error())
		return
	}

	if existing != "" {
		data.Token = types.StringValue(existing)
	} else {
		token, err := r.createToken(
			r.authHeader,
			r.serverURL,
			data.ProjectName.ValueString(),
			data.RepositoryName.ValueString(),
			data.TokenName.ValueString(),
		)
		if err != nil {
			resp.Diagnostics.AddError("Error creating new token", err.Error())
			return
		}
		data.Token = types.StringValue(token)
	}

	data.ID = types.StringValue(fmt.Sprintf("%s/%s/%s",
		data.ProjectName.ValueString(),
		data.RepositoryName.ValueString(),
		data.TokenName.ValueString(),
	))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *BitbucketTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	existing, err := r.getExistingToken(
		r.authHeader,
		r.serverURL,
		data.ProjectName.ValueString(),
		data.RepositoryName.ValueString(),
		data.TokenName.ValueString(),
	)
	if err != nil {
		resp.Diagnostics.AddError("Error reading token", err.Error())
		return
	}

	if existing == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *BitbucketTokenResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	existing, err := r.getExistingToken(
		r.authHeader,
		r.serverURL,
		data.ProjectName.ValueString(),
		data.RepositoryName.ValueString(),
		data.TokenName.ValueString(),
	)
	if err != nil {
		resp.Diagnostics.AddError("Error checking existing token", err.Error())
		return
	}

	if existing != "" {
		data.Token = types.StringValue(existing)
	} else {
		token, err := r.createToken(
			r.authHeader,
			r.serverURL,
			data.ProjectName.ValueString(),
			data.RepositoryName.ValueString(),
			data.TokenName.ValueString(),
		)
		if err != nil {
			resp.Diagnostics.AddError("Error creating new token", err.Error())
			return
		}
		data.Token = types.StringValue(token)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *BitbucketTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data BitbucketTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	auth := r.authHeader
	project := data.ProjectName.ValueString()
	repo := data.RepositoryName.ValueString()
	name := data.TokenName.ValueString()
	baseURL := r.serverURL

	client := &http.Client{Timeout: 15 * time.Second}

	tokenID, err := r.getExistingToken(auth, baseURL, project, repo, name)
	if err != nil {
		resp.Diagnostics.AddWarning("Failed to verify token before deletion", err.Error())
	} else if tokenID != "" {
		apiURL := fmt.Sprintf("%s/rest/access-tokens/latest/projects/%s/repos/%s/%s", baseURL, project, repo, tokenID)
		reqDel, _ := http.NewRequest("DELETE", apiURL, nil)
		reqDel.Header.Add("Authorization", "Basic "+auth)

		respDel, err := client.Do(reqDel)
		if err != nil {
			resp.Diagnostics.AddWarning("Error deleting token", err.Error())
		} else {
			defer respDel.Body.Close()
			if respDel.StatusCode >= 400 {
				body, _ := io.ReadAll(respDel.Body)
				resp.Diagnostics.AddWarning(
					"Bitbucket returned error during delete",
					fmt.Sprintf("Status: %s\nBody: %s", respDel.Status, string(body)),
				)
			}
		}
	}

	resp.State.RemoveResource(ctx)
}
