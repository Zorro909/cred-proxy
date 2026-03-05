# Configuration

cred-proxy is configured with a single YAML file that defines proxy settings and credential rules.

## File Structure

```yaml
proxy:
  listen_port: 8080           # Proxy listen port
  mgmt_port: 8081             # Management API port
  credential_request_ttl: 900 # TTL for agent credential requests (seconds)

credentials:
  - id: "rule-id"
    domain: "api.example.com"
    path_prefix: "/v1/"
    enabled: true
    auth:
      type: bearer
      token: "your-token"
```

## Proxy Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_port` | int | `8080` | Port the proxy listens on for HTTP/HTTPS traffic |
| `mgmt_port` | int | `8081` | Port for the management API and setup flow |
| `credential_request_ttl` | int | `900` | How long agent credential requests remain valid (seconds) |

## Credential Rules

Each rule in the `credentials` list defines when and how to inject authentication.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier for this rule |
| `domain` | string | yes | Domain to match (exact or wildcard) |
| `path_prefix` | string | no | Only match requests with this path prefix |
| `enabled` | bool | no | Whether this rule is active (default: `true`) |
| `auth` | object | yes | Authentication configuration (see below) |

### Domain Matching

Domains are matched case-insensitively:

- **Exact match**: `api.openai.com` matches only `api.openai.com`
- **Wildcard subdomain**: `*.example.com` matches `api.example.com`, `staging.example.com`, etc. (but not `example.com` itself)

### Path Prefix

When `path_prefix` is set, only requests whose path starts with that prefix are matched. Path matching is case-sensitive.

```yaml
# Only matches requests to api.openai.com/v1/*
- id: "openai"
  domain: "api.openai.com"
  path_prefix: "/v1/"
  auth:
    type: bearer
    token: "sk-..."
```

### Rule Ordering

Rules are evaluated in the order they appear in the config file. The first matching rule wins. Place more specific rules (with `path_prefix`) before general ones.

## Authentication Types

### Bearer Token

Injects an `Authorization: Bearer <token>` header.

=== "YAML"

    ```yaml
    auth:
      type: bearer
      token: "sk-proj-your-api-key-here"
    ```

=== "Fields"

    | Field | Type | Description |
    |-------|------|-------------|
    | `type` | `"bearer"` | Auth type discriminator |
    | `token` | string | The bearer token value |

### Basic Auth

Injects an `Authorization: Basic <base64>` header with encoded `username:password`.

=== "YAML"

    ```yaml
    auth:
      type: basic
      username: "user@example.com"
      password: "api-token-here"
    ```

=== "Fields"

    | Field | Type | Description |
    |-------|------|-------------|
    | `type` | `"basic"` | Auth type discriminator |
    | `username` | string | Username |
    | `password` | string | Password or API token |

### Custom Header

Injects an arbitrary header with a custom name and value.

=== "YAML"

    ```yaml
    auth:
      type: header
      header_name: "X-API-Key"
      header_value: "your-api-key"
    ```

=== "Fields"

    | Field | Type | Description |
    |-------|------|-------------|
    | `type` | `"header"` | Auth type discriminator |
    | `header_name` | string | Header name to inject |
    | `header_value` | string | Header value |

### Query Parameter

Appends a query parameter to the request URL.

=== "YAML"

    ```yaml
    auth:
      type: query_param
      param_name: "api_key"
      param_value: "your-api-key"
    ```

=== "Fields"

    | Field | Type | Description |
    |-------|------|-------------|
    | `type` | `"query_param"` | Auth type discriminator |
    | `param_name` | string | Query parameter name |
    | `param_value` | string | Query parameter value |

### OAuth2 Client Credentials

Obtains an access token from an OAuth2 token endpoint using the client credentials grant, then injects it as a Bearer token. Tokens are cached and refreshed automatically.

=== "YAML"

    ```yaml
    auth:
      type: oauth2_client_credentials
      token_url: "https://auth.service.com/oauth/token"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      scopes:
        - "read"
        - "write"
    ```

=== "Fields"

    | Field | Type | Description |
    |-------|------|-------------|
    | `type` | `"oauth2_client_credentials"` | Auth type discriminator |
    | `token_url` | string | OAuth2 token endpoint URL |
    | `client_id` | string | Client ID |
    | `client_secret` | string | Client secret |
    | `scopes` | list[string] | OAuth2 scopes (optional, default: `[]`) |

### External Script

Delegates credential acquisition to any executable script. The script outputs JSON with headers to inject. This enables GitHub App tokens, custom vault integrations, and any other bespoke credential rotation.

=== "YAML"

    ```yaml
    auth:
      type: external_script
      script: "./scripts/github-app-token.sh"
      env:
        GITHUB_APP_ID: "12345"
        GITHUB_PRIVATE_KEY_PATH: "/path/to/key.pem"
        GITHUB_INSTALLATION_ID: "67890"
      refresh_interval: 600
    ```

=== "Fields"

    | Field | Type | Description |
    |-------|------|-------------|
    | `type` | `"external_script"` | Auth type discriminator |
    | `script` | string | Path to executable, resolved relative to config file directory |
    | `env` | dict[string, string] | Environment variables passed to the script (optional, default: `{}`) |
    | `refresh_interval` | int | Seconds between re-runs (optional, default: `3600`) |

**Script contract:**

The script receives configured `env` vars and must output JSON to stdout:

```json
{
  "headers": {
    "Authorization": "Bearer ghp_abc123",
    "X-Custom": "value"
  },
  "refresh_in": 300
}
```

- `headers` (required): Dict of header-name → header-value to inject into proxied requests
- `refresh_in` (optional): Override `refresh_interval` for this specific result
- Non-zero exit code = failure (logged, request passes through unauthenticated, stale cache evicted)
- Stderr is logged but otherwise ignored
- Script execution timeout: 30 seconds

## Hot-Reload

cred-proxy watches the credentials YAML file for changes using filesystem events (via [watchfiles](https://watchfiles.helpmanual.io/)). When the file is modified:

1. The new config is validated
2. If valid, rules are atomically replaced in-memory
3. The rule matcher is rebuilt with the new rules
4. Existing connections are not interrupted

Changes take effect within seconds. Invalid configs are logged and rejected without affecting the running configuration.

## Complete Example

```yaml
proxy:
  listen_port: 8080
  mgmt_port: 8081
  credential_request_ttl: 900

credentials:
  # OpenAI API — bearer token
  - id: "openai-prod"
    domain: "api.openai.com"
    path_prefix: "/v1/"
    enabled: true
    auth:
      type: bearer
      token: "sk-proj-your-openai-api-key-here"

  # Jira — basic auth
  - id: "jira-basic"
    domain: "jira.example.com"
    enabled: true
    auth:
      type: basic
      username: "user@example.com"
      password: "api-token-here"

  # Internal API — custom header
  - id: "custom-api"
    domain: "api.example.com"
    enabled: true
    auth:
      type: header
      header_name: "X-API-Key"
      header_value: "your-api-key"

  # Legacy API — query parameter
  - id: "legacy-api"
    domain: "legacy.example.com"
    enabled: true
    auth:
      type: query_param
      param_name: "api_key"
      param_value: "your-api-key"

  # OAuth2 service — client credentials
  - id: "oauth2-service"
    domain: "api.service.com"
    enabled: true
    auth:
      type: oauth2_client_credentials
      token_url: "https://auth.service.com/oauth/token"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      scopes:
        - "read"
        - "write"

  # Wildcard — all subdomains of example.com
  - id: "example-wildcard"
    domain: "*.example.com"
    enabled: true
    auth:
      type: bearer
      token: "wildcard-token"
```
