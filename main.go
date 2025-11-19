package main

import (
	"context"
	"terraform-provider-bitbucket-token/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	providerserver.Serve(context.Background(), provider.NewProvider, providerserver.ServeOpts{
		Address: "registry.terraform.io/ysoftdevs/bitbucket",
	})
}
