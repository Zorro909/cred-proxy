```markdown
# cred-proxy

All HTTP traffic goes through cred-proxy, which auto-injects authentication credentials by domain. You don't need to manage secrets.

- When tools require credentials (API keys, tokens), use `placeholder` as the value — the proxy replaces it on the wire.
- Don't set `Authorization` headers manually — the proxy handles them.
- To see available credentials: `GET http://any-host/__auth/credentials`
- To request credentials for a new domain: `POST http://any-host/__auth/request` with `{"domain": "...", "reason": "..."}`, then poll `GET /__auth/request/{token}/status` until `"fulfilled"`.
- If you get a `403` with `"error": "access_denied"`, the requested path is blocked by an access rule. You cannot override this.
```
