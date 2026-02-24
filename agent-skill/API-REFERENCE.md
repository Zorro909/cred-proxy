# cred-proxy Agent API Reference

The `/__auth/*` endpoints are intercepted by the proxy itself — they never reach the upstream server. You can send these requests to **any** host through the proxy.

## `GET /__auth/credentials`

List configured credential rules.

### Query Parameters

| Param | Type | Description |
|-------|------|-------------|
| `domain` | string (optional) | Filter results to rules whose domain contains this substring (case-insensitive) |

### Response `200 OK`

```json
[
  {
    "id": "github-api",
    "domain": "api.github.com",
    "enabled": true
  },
  {
    "id": "npm-registry",
    "domain": "registry.npmjs.org",
    "enabled": true
  }
]
```

Each object contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Rule identifier |
| `domain` | string | Domain pattern this rule matches |
| `enabled` | boolean | Whether the rule is active |

---

## `POST /__auth/request`

Request credentials for a domain that doesn't have a rule yet. The human operator will be notified and can configure credentials through the management UI.

### Request Body

```json
{
  "domain": "api.example.com",
  "auth_type": "bearer",
  "reason": "Need to fetch repository metadata"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | yes | Fully-qualified domain name (validated against `^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`) |
| `auth_type` | string | no | Hint for the operator. One of: `bearer`, `basic`, `header`, `query_param`, `oauth2_client_credentials` |
| `reason` | string | no | Why you need access (max 500 characters) |

### Response `200 OK`

```json
{
  "setup_url": "http://localhost:8081/setup/abc123...",
  "token": "abc123...",
  "expires_in": 3600
}
```

| Field | Type | Description |
|-------|------|-------------|
| `setup_url` | string | URL for the human operator to configure credentials |
| `token` | string | Opaque token to poll for status |
| `expires_in` | integer | TTL in seconds before the request expires |

### Errors

| Status | Body | Cause |
|--------|------|-------|
| `400` | `{"error": "Invalid JSON"}` | Request body is not valid JSON |
| `400` | `{"error": "Invalid domain"}` | Missing or malformed domain |
| `400` | `{"error": "Reason must be 500 characters or less"}` | Reason too long |
| `400` | `{"error": "Invalid auth_type. Must be one of: ..."}` | Unknown auth type |
| `429` | `{"error": "Rate limit exceeded"}` | Too many requests in the time window |

---

## `GET /__auth/request/{token}/status`

Poll the status of a credential request.

### Path Parameters

| Param | Type | Description |
|-------|------|-------------|
| `token` | string | The token returned by `POST /__auth/request` |

### Response `200 OK`

```json
{
  "status": "pending"
}
```

| Status value | Meaning |
|-------------|---------|
| `pending` | Operator has not yet configured credentials |
| `fulfilled` | Credentials are now active — retry your original request |
| `expired` | The request timed out; submit a new one if still needed |

### Errors

| Status | Body | Cause |
|--------|------|-------|
| `404` | `{"error": "Unknown request token"}` | Token not found or already cleaned up |

---

## Example: Requesting and Waiting for Credentials

```python
import httpx
import time

# 1. Request credentials
resp = httpx.post(
    "http://any-host/__auth/request",
    json={"domain": "api.example.com", "reason": "Fetch user data"},
)
data = resp.json()
token = data["token"]
print(f"Ask operator to visit: {data['setup_url']}")

# 2. Poll until fulfilled or expired
while True:
    status_resp = httpx.get(f"http://any-host/__auth/request/{token}/status")
    status = status_resp.json()["status"]
    if status == "fulfilled":
        print("Credentials ready — retrying request")
        break
    elif status == "expired":
        print("Request expired — submit a new one")
        break
    time.sleep(5)
```
