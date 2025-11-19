package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	provider "terraform-provider-bitbucket-token/internal/provider"
	mock "terraform-provider-bitbucket-token/mock_server"
)

var testAccProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"bitbucket": providerserver.NewProtocol6WithError(provider.NewProvider()),
}

func TestAccBitbucketToken_AllScenarios(t *testing.T) {
	// Split into focused tests to validate specific behaviors.
	resourceName := "bitbucket_token.test"

	// Helper to start a fresh server for each test.
	startServer := func(t *testing.T) *mock.MockBitbucketServer {
		srv := mock.NewMockBitbucketServer()
		if err := srv.Start(); err != nil {
			t.Fatalf("server start error: %v", err)
		}
		return srv
	}

	t.Run("CreateWhenNone", func(t *testing.T) {
		server := startServer(t)
		defer func() { _ = server }()

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccBitbucketTokenConfig(server.URL),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(resourceName, "id"),
						resource.TestCheckResourceAttrSet(resourceName, "token"),
						resource.TestCheckResourceAttrSet(resourceName, "current_token_name"),
						resource.TestCheckResourceAttrSet(resourceName, "current_token_expiry"),
						testAccCheckServerHasTokens(server, "proj/repo", 1),
					),
				},
			},
		})
	})

	t.Run("ReuseStateWhenSecondaryExists", func(t *testing.T) {
		server := startServer(t)
		defer func() { _ = server }()

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccProviderFactories,
			Steps: []resource.TestStep{
				// 1) create initial token and capture state
				{
					Config: testAccBitbucketTokenConfig(server.URL),
				},
				// 2) Add a secondary token on the server, expect no changes (reuse)
				{
					PreConfig: func() {
						server.Mu.Lock()
						server.Tokens["proj/repo"] = append(server.Tokens["proj/repo"], mock.Token{
							Name:       "prefix-secondary",
							Token:      "secret-secondary",
							ExpiryDate: time.Now().Add(24 * time.Hour).UnixMilli(),
						})
						server.Mu.Unlock()
					},
					Config:   testAccBitbucketTokenConfig(server.URL),
					PlanOnly: true,
				},
			},
		})
	})

	t.Run("RecreateWhenExpired", func(t *testing.T) {
		server := startServer(t)
		defer func() { _ = server }()

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccProviderFactories,
			CheckDestroy:             testAccCheckBitbucketTokenDestroy(server),
			Steps: []resource.TestStep{
				// 1) create initial token
				{
					Config: testAccBitbucketTokenConfig(server.URL),
				},
				// 2) expire token on server and refresh state; expect a non-empty plan
				{
					PreConfig: func() {
						server.SetExpiredToken("proj/repo")
					},
					RefreshState:        true,
					ExpectNonEmptyPlan:  true,
				},
			},
		})
	})
}

//
// ---------- Helper Configs ----------
//

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

func testAccBitbucketTokenConfigPrefix(url, prefix string) string {
	return fmt.Sprintf(`
provider "bitbucket" {
  server_url      = "%s"
  auth_header     = "dummy"
  tls_skip_verify = true
}

resource "bitbucket_token" "test" {
  project_name    = "proj"
  repository_name = "repo"
  token_name      = "%s"
}
`, url, prefix)
}

//
// ---------- Environment ----------
//

func testAccPreCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance tests in short mode")
	}
}

func testAccCheckBitbucketTokenDestroy(server *mock.MockBitbucketServer) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		server.Mu.Lock()
		defer server.Mu.Unlock()

		for _, tok := range server.Tokens {
			if len(tok) != 0 {
				return fmt.Errorf("tokens still exist: %#v", server.Tokens)
			}
		}
		return nil
	}
}

// testAccCheckServerHasTokens asserts that the mock server contains exactly
// `expected` tokens for the given repo key (e.g. "proj/repo").
func testAccCheckServerHasTokens(server *mock.MockBitbucketServer, key string, expected int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		server.Mu.Lock()
		defer server.Mu.Unlock()

		toks := server.Tokens[key]
		if len(toks) != expected {
			return fmt.Errorf("expected %d tokens for %s, got %d: %#v", expected, key, len(toks), toks)
		}
		return nil
	}
}
