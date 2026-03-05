# Management API

The management API runs on port `8081` (configurable) and provides REST endpoints for credential management, status monitoring, and the credential setup flow.

## Status

### `GET /api/status`

Returns proxy health and credential counts.

**Response:**

```json
{
  "status": "ok",
  "uptime_seconds": 123.4,
  "total_rules": 5,
  "enabled_rules": 4,
  "total_access_rules": 3,
  "access_rule_groups": 2
}
```

The `total_access_rules` and `access_rule_groups` fields are included when access rules are configured.

**Example:**

```bash
curl http://localhost:8081/api/status
```

## Credentials

All credential endpoints mask secret values in responses. For example, a bearer token `sk-proj-abc123xyz789` is returned as `sk-***789`.

### `GET /api/credentials`

List all credential rules (secrets masked).

**Response:** `200 OK`

```json
[
  {
    "id": "openai-prod",
    "domain": "api.openai.com",
    "path_prefix": "/v1/",
    "enabled": true,
    "auth": {
      "type": "bearer",
      "token": "sk-***789"
    }
  }
]
```

**Example:**

```bash
curl http://localhost:8081/api/credentials
```

### `POST /api/credentials`

Create a new credential rule.

**Request body:**

```json
{
  "id": "github-api",
  "domain": "api.github.com",
  "path_prefix": null,
  "enabled": true,
  "auth": {
    "type": "bearer",
    "token": "ghp_xxxxxxxxxxxx"
  }
}
```

**Response:** `201 Created` — returns the created rule (secrets masked).

**Errors:**

| Status | Reason |
|--------|--------|
| `400` | Invalid request body or auth config |
| `409` | Rule with this `id` already exists |

**Example:**

```bash
curl -X POST http://localhost:8081/api/credentials \
  -H "Content-Type: application/json" \
  -d '{
    "id": "github-api",
    "domain": "api.github.com",
    "enabled": true,
    "auth": {"type": "bearer", "token": "ghp_xxxxxxxxxxxx"}
  }'
```

### `PUT /api/credentials/{rule_id}`

Update an existing credential rule. Only provided fields are updated; omitted fields retain their current values. The `id` cannot be changed.

**Request body** (all fields optional):

```json
{
  "domain": "api.github.com",
  "path_prefix": "/v2/",
  "enabled": false,
  "auth": {
    "type": "bearer",
    "token": "ghp_new_token"
  }
}
```

**Response:** `200 OK` — returns the updated rule (secrets masked).

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Rule not found |

**Example:**

```bash
curl -X PUT http://localhost:8081/api/credentials/github-api \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### `DELETE /api/credentials/{rule_id}`

Delete a credential rule.

**Response:** `204 No Content`

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Rule not found |

**Example:**

```bash
curl -X DELETE http://localhost:8081/api/credentials/github-api
```

### `POST /api/credentials/{rule_id}/test`

Test a credential rule by making a HEAD request to the configured domain.

**Response:** `200 OK`

```json
{
  "status_code": 200,
  "success": true
}
```

If the request fails:

```json
{
  "status_code": 0,
  "success": false,
  "error": "Connection refused"
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Rule not found |

**Example:**

```bash
curl -X POST http://localhost:8081/api/credentials/openai-prod/test
```

## Setup Flow

The setup flow is a browser-based form that allows users to provide credentials when an agent requests them. See the [Agent API](agent.md) for how agents initiate this flow.

### `GET /setup/{token}`

Renders an HTML form for credential entry. The form is pre-populated with the domain and auth type from the agent's request.

**Response:** `200 OK` — HTML page

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Unknown setup token |
| `410` | Token expired or already used |

### `POST /setup/{token}`

Submits the credential form. Creates the credential rule and marks the pending request as fulfilled.

**Request body:** HTML form data with fields depending on auth type (`auth_type`, `token`, `username`, `password`, `header_name`, `header_value`, `param_name`, `param_value`, `token_url`, `client_id`, `client_secret`, `scopes`).

**Response:** `200 OK` — HTML success page

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Unknown setup token |
| `410` | Token expired or already used |

## Secret Masking

All credential API responses mask secret values to prevent accidental exposure:

| Auth Type | Visible Fields | Masked Fields |
|-----------|---------------|---------------|
| Bearer | — | `token` → `sk-***789` |
| Basic | `username` | `password` → `***` |
| Header | `header_name` | `header_value` → `X-***key` |
| Query Param | `param_name` | `param_value` → `yo-***key` |
| OAuth2 | `client_id`, `token_url`, `scopes` | `client_secret` → `se-***ret` |

The masking format keeps the last 3 characters visible and preserves any prefix before the first separator (`-`, `_`, `.`).

## Access Rules

CRUD endpoints for managing URL access rules. See [Configuration — Access Rules](../configuration.md#access-rules) for the config file format.

### `GET /api/access-rules`

List all access rules, grouped by file.

**Response:** `200 OK`

```json
{
  "groups": {
    "default": [
      {
        "id": "openai-denylist",
        "domain": "api.openai.com",
        "mode": "deny",
        "paths": ["^/v1/files", "^/v1/fine_tuning"]
      }
    ],
    "github": [
      {
        "id": "github-allowlist",
        "domain": "api.github.com",
        "mode": "allow",
        "paths": ["^/repos/", "^/user$"]
      }
    ]
  }
}
```

### `GET /api/access-rules/{rule_id}`

Get a single access rule with its group.

**Response:** `200 OK`

```json
{
  "group": "github",
  "rule": {
    "id": "github-allowlist",
    "domain": "api.github.com",
    "mode": "allow",
    "paths": ["^/repos/", "^/user$"]
  }
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Rule not found |

### `POST /api/access-rules`

Create a new access rule.

**Request body:**

```json
{
  "id": "slack-allowlist",
  "domain": "slack.com",
  "mode": "allow",
  "paths": ["^/api/chat\\.postMessage"],
  "group": "slack"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique rule identifier |
| `domain` | string | yes | Domain to match |
| `mode` | `"allow"` / `"deny"` | yes | Access control mode |
| `paths` | list[string] | no | Regex path patterns (default: `[]`) |
| `group` | string | no | File group name (default: `"default"`) |

**Response:** `201 Created`

**Errors:**

| Status | Reason |
|--------|--------|
| `400` | Invalid group name |
| `409` | Duplicate ID or domain |
| `422` | Invalid mode or regex pattern |

### `PUT /api/access-rules/{rule_id}`

Update an existing access rule. Only provided fields are changed. The `id` cannot be changed.

**Request body** (all fields optional):

```json
{
  "mode": "deny",
  "paths": ["^/admin"]
}
```

**Response:** `200 OK`

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Rule not found |

### `DELETE /api/access-rules/{rule_id}`

Delete an access rule. If this was the last rule in its group file, the file is deleted.

**Response:** `204 No Content`

**Errors:**

| Status | Reason |
|--------|--------|
| `404` | Rule not found |
