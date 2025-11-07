package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	providerserver.Serve(context.Background(), NewProvider, providerserver.ServeOpts{
		Address: "ysoftdevs/bitbucket",
	})
}
