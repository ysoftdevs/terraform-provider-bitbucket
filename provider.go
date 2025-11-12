package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewProvider() provider.Provider {
	return &bitbucketTokenProvider{}
}

type bitbucketTokenProvider struct{}

type bitbucketTokenProviderModel struct {
	AuthHeader    types.String `tfsdk:"auth_header"`
	ServerURL     types.String `tfsdk:"server_url"`
	TLSSkipVerify types.Bool   `tfsdk:"tls_skip_verify"`
}

func (p *bitbucketTokenProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "bitbucket"
}

func (p *bitbucketTokenProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Custom provider for Bitbucket token management.",
		Attributes: map[string]schema.Attribute{
			"auth_header": schema.StringAttribute{
				Description: "Base64 encoded Basic Auth header or personal access token.",
				Required:    true,
				Sensitive:   true,
			},
			"server_url": schema.StringAttribute{
				Description: "Base URL of the Bitbucket server (e.g. https://stash.example.com). Must not end with a slash.",
				Required:    true,
			},
			"tls_skip_verify": schema.BoolAttribute{
				Description: "If true, disables TLS certificate verification. Use only for testing or internal servers.",
				Optional:    true,
			},
		},
	}
}

func (p *bitbucketTokenProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config bitbucketTokenProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.ServerURL.IsNull() || config.ServerURL.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing server URL",
			"The provider requires a 'server_url' to be specified.",
		)
		return
	}

	if config.AuthHeader.IsNull() || config.AuthHeader.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing authentication header",
			"The provider requires an 'auth_header' to be specified.",
		)
		return
	}

	providerData := &ProviderData{
		AuthHeader:    config.AuthHeader.ValueString(),
		ServerURL:     config.ServerURL.ValueString(),
		TLSSkipVerify: config.TLSSkipVerify.ValueBool(), // <-- passes TLS flag through
	}

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *bitbucketTokenProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *bitbucketTokenProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewBitbucketTokenResource,
	}
}
