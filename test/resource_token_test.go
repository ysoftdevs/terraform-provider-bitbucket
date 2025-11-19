package test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	provider "terraform-provider-bitbucket-token/internal/provider"
	mock "terraform-provider-bitbucket-token/mock_server"
)

// Acceptance test provider factories for protocol v6
var testAccProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"bitbucket": providerserver.NewProtocol6WithError(provider.NewProvider()),
}

func TestAccBitbucketToken_CRUD(t *testing.T) {
	server := mock.NewMockBitbucketServer()

	if err := server.Start(); err != nil {
		t.Fatalf("server start error: %v", err)
	}

	resourceName := "bitbucket_token.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             testAccCheckBitbucketTokenDestroy(server),
		Steps: []resource.TestStep{
			{
				// CREATE
				Config: testAccBitbucketTokenConfig(server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "current_token_name"),
					resource.TestCheckResourceAttrSet(resourceName, "current_token_expiry"),
					resource.TestCheckResourceAttrSet(resourceName, "token"),
				),
			},
			{
				// READ (no drift) – apply the same config again; plan should stay empty
				Config: testAccBitbucketTokenConfig(server.URL),
			},
		},
	})
}

//
// -------- Helper Functions --------
//

// Basic test configuration for the provider + resource
func testAccBitbucketTokenConfig(url string) string {
	return fmt.Sprintf(`
provider "bitbucket" {
  server_url      = "%s"
  auth_header     = "dummy"
  tls_skip_verify = true
}

resource "bitbucket_token" "test" {
  project_name    = "proj"
  repository_name = "repo"
  token_name      = "prefix"
}
`, url)
}

// Ensures Terraform acceptance test environment is correct
func testAccPreCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}
}

// Verifies that all tokens were removed by Delete()
func testAccCheckBitbucketTokenDestroy(server *mock.MockBitbucketServer) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		server.Mu.Lock()
		defer server.Mu.Unlock()

		// server.Tokens should be empty after resource.Delete()
		for _, tokens := range server.Tokens {
			if len(tokens) != 0 {
				return fmt.Errorf("expected no tokens, but found: %#v", server.Tokens)
			}
		}
		return nil
	}
}
