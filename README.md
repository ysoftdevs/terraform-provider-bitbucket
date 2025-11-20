# Terraform Provider for Bitbucket (ysoftdevs/bitbucket)

This project implements a custom Terraform provider for managing Bitbucket repository access tokens. It is designed for use with Bitbucket Server/Data Center and supports automated token lifecycle management.

## Features

- Create, read, update, and delete Bitbucket repository access tokens
- Token secret is only returned on creation and preserved in state for reuse while valid
- Handles token expiration and drift scenarios
- Acceptance tests with a built-in mock Bitbucket server

## Usage

### Provider Block

```
provider "bitbucket" {
  server_url      = "http://your-bitbucket-server"
  auth_header     = "<base64 basic auth or personal access token>"
  tls_skip_verify = true # for testing only
}
```

### Resource Block

```
resource "bitbucket_token" "test" {
  project_name    = "proj"
  repository_name = "repo"
  token_name      = "prefix"
}
```

## Development

### Requirements

- Go 1.24+
- [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework)
- [Terraform Plugin Testing](https://github.com/hashicorp/terraform-plugin-testing)

Install dependencies:

```
go mod tidy
```

### Build

To build the provider binary:

```
go build -o terraform-provider-bitbucket-token main.go
```

### Release & OpenTofu Registry

Releases are managed via `goreleaser.yml` and published automatically to the OpenTofu registry.

**How it works:**

- Each time a new version tag (e.g., `v1.2.3`) is pushed to the repository, a release is built and published.
- The provider is automatically registered with the OpenTofu registry at `registry.opentofu.org/ysoftdevs/bitbucket`.
- After publishing, the registry will automatically promote the new version within a few hours (usually up to 2 hours).
- No manual steps are required for registry promotion—users will see the new version available for installation after the delay.

**User workflow:**

1. Wait for the new tag to be promoted (check registry for latest version).
2. Reference the desired version in your Terraform/OpenTofu configuration:
   ```hcl
   terraform {
     required_providers {
       bitbucket = {
         source  = "ysoftdevs/bitbucket"
         version = "~> 1.2.3"
       }
     }
   }
   ```
3. Run `tofu init` to install the provider.

See [GoReleaser](https://goreleaser.com/) for build details and `terraform-registry-manifest.json` for protocol info.

### Registry Manifest

The provider is registry-compatible. See `terraform-registry-manifest.json` for protocol version info.

## Testing

### Acceptance Tests

Acceptance tests use a mock Bitbucket server and cover:

- Token creation when none exist
- Reuse of state token when a secondary token exists
- Token recreation when expired

To run acceptance tests:

```
$env:TF_ACC = '1'; go test ./test -v
```

### Test Structure

- `test/resource_token_test.go`: Acceptance tests
- `mock_server/mock_server.go`: In-memory Bitbucket API mock
- `internal/provider/resource_token.go`: Resource implementation
- `internal/provider/provider.go`: Provider implementation
