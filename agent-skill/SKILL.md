---
name: cred-proxy
description: Transparent authentication proxy — injects credentials into HTTP traffic automatically
user-invocable: false
---

# cred-proxy

All outbound HTTP traffic from this environment flows through **cred-proxy**, a transparent authentication injection proxy. When a request matches a configured domain, the proxy automatically adds the correct credentials on the wire. You do not need to manage secrets yourself.

## Rules

- **Use placeholder credentials** — when CLI tools or config files require explicit credentials (e.g. `gh auth login`, `~/.npmrc`, curl `Authorization` header), use `placeholder` or `PLACEHOLDER_TOKEN`. The proxy overwrites them before the request reaches the upstream server.
- **Don't set auth headers manually** — the proxy injects `Authorization` and other auth mechanisms. Manual headers may conflict.
- **Don't bypass the proxy** — all HTTP traffic must flow through it for credential injection to work.
- **Don't log or print credential values** — even if you discover them, treat them as opaque.

## Discovering Available Credentials

To check which domains have credentials configured:

```
GET http://any-host/__auth/credentials
```

Returns a JSON array of `{"id", "domain", "enabled"}` objects. You can filter by domain with `?domain=example.com`.

## Requesting New Credentials

If you need credentials for a domain that isn't configured yet:

```
POST http://any-host/__auth/request
Content-Type: application/json

{"domain": "api.example.com", "reason": "Need to fetch user data"}
```

The response includes a `setup_url` for the human operator and a `token` to poll for status:

```
GET http://any-host/__auth/request/{token}/status
```

Poll until `status` is `"fulfilled"` or `"expired"`.

## Reference

See [API-REFERENCE.md](API-REFERENCE.md) for full `/__auth/*` endpoint details including request/response schemas and error codes.
