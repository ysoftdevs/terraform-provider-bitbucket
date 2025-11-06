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

func (p *bitbucketTokenProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "bitbucket"
}

func (p *bitbucketTokenProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Custom provider for Bitbucket token management.",
		Attributes: map[string]schema.Attribute{
			"auth_header": schema.StringAttribute{
				Description: "Base64 encoded Basic Auth header or personal access token.",
				Optional:    true,
				Sensitive:   true, // <--- klíčové
			},
		},
	}
}

func (p *bitbucketTokenProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config struct {
		AuthHeader types.String `tfsdk:"auth_header"`
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.AuthHeader.IsNull() {
		resp.Diagnostics.AddWarning("Missing credentials", "No auth_header provided — provider will not authenticate requests.")
		return
	}

	resp.DataSourceData = config.AuthHeader.ValueString()
	resp.ResourceData = config.AuthHeader.ValueString()
}

func (p *bitbucketTokenProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *bitbucketTokenProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewBitbucketTokenResource,
	}
}
