# Codebase Report: mitmproxy 12.x Python Addon API
Generated: 2026-02-22

> Note: The installed version is **12.2.1** (not 11.x as asked — 12.x is the current stable).
> The API is backward-compatible with 11.x for all features described here.
> Source location: `/home/zorro/.cache/uv/archive-v0/DGHXlAkOBiFqbpUzzNVgk/mitmproxy/`

---

## Summary

mitmproxy addons are Python classes (or modules) registered in an `addons` global list. They
respond to named event hooks by implementing methods with matching names. The `request` and
`response` hooks receive `mitmproxy.http.HTTPFlow` objects and can mutate them in-place. To
serve a synthetic response without forwarding upstream, assign `flow.response = http.Response.make(...)`.
mitmproxy includes a built-in `asgiapp.ASGIApp` addon that routes an ASGI/WSGI app at a virtual
host, which is the right way to host FastAPI in-process. Custom options are declared via the
`load(loader)` hook and `loader.add_option(...)`, then read from `ctx.options`.

---

## 1. Addon Anatomy

### 1.1 Class-based addon (canonical form)

```python
import logging
from mitmproxy import http, ctx

class MyAddon:
    def __init__(self):
        pass

    def load(self, loader):
        """Called on addon load. Register custom options here."""
        loader.add_option(
            name="config_path",
            typespec=str,
            default="/data/config/credentials.yaml",
            help="Path to credentials YAML config file.",
        )

    def configure(self, updates):
        """Called when options change (including on startup with defaults)."""
        if "config_path" in updates:
            self._load_config(ctx.options.config_path)

    def request(self, flow: http.HTTPFlow) -> None:
        """Called after full request is read, before forwarding to server."""
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        """Called after full response is read, before forwarding to client."""
        pass

addons = [MyAddon()]
```

### 1.2 Module-level abbreviated syntax (shorthand)

```python
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    flow.request.headers["X-Injected"] = "value"
```

### 1.3 Invocation

```bash
# Basic
mitmdump -s addon.py

# With custom --set options
mitmdump -s addon.py --set config_path=/data/config/credentials.yaml

# With port and cert directory
mitmdump \
  --listen-port 8080 \
  --set confdir=/data/certs \
  --set block_global=false \
  -s src/auth_injection_proxy/addon.py \
  --set config_path=/data/config/credentials.yaml
```

**Key `--set` options built into mitmproxy:**
- `confdir` — CA cert storage directory (default `~/.mitmproxy`)
- `listen_port` — proxy listen port (default `8080`)
- `listen_host` — bind address
- `block_global` — block access to global/loopback (default `true`, set `false` in Docker)
- `ignore_hosts` — regex list of hosts to pass through without TLS interception
- `ssl_insecure` — skip upstream cert verification

---

## 2. HTTP Hook Ordering and Signatures

All hooks are defined in:
`mitmproxy/proxy/layers/http/_hooks.py`

| Method name | When called | Can set response? |
|-------------|-------------|-------------------|
| `requestheaders(flow)` | After request headers received, body empty | Yes — kills upstream connection |
| `request(flow)` | After full request body read | Yes — kills upstream connection |
| `responseheaders(flow)` | After response headers received, body empty | Yes — replaces response |
| `response(flow)` | After full response body read | Yes — replaces response |
| `error(flow)` | On connection/protocol error | No |
| `http_connect(flow)` | On CONNECT tunnel request (proxy mode) | Yes — can reject |
| `http_connected(flow)` | After CONNECT succeeded | No |

**Key rule:** Setting `flow.response` in `request` or `requestheaders` prevents mitmproxy from
contacting the upstream server entirely. The response is returned directly to the client.

### Async hooks

Hooks may be `async def` to avoid blocking the event loop:

```python
async def request(self, flow: http.HTTPFlow) -> None:
    token = await self._get_oauth_token()  # non-blocking
    flow.request.headers["Authorization"] = f"Bearer {token}"
```

Or use `@concurrent` decorator for thread-based execution (opens concurrency risks):

```python
from mitmproxy.script import concurrent

@concurrent
def request(self, flow: http.HTTPFlow) -> None:
    ...
```

---

## 3. `mitmproxy.http.HTTPFlow` API

**Source:** `mitmproxy/http.py`, line 1210

```python
class HTTPFlow(flow.Flow):
    request: Request          # always present
    response: Response | None # present after server reply (or if set by addon)
    error: flow.Error | None  # connection/protocol error
    websocket: WebSocketData | None
    live: bool                # True if connection is active
    intercepted: bool         # True if flow is paused waiting for user action
```

### 3.1 `flow.request` properties

```python
flow.request.host          # str  — "api.openai.com"
flow.request.port          # int  — 443
flow.request.scheme        # str  — "https"
flow.request.method        # str  — "GET", "POST", etc.
flow.request.path          # str  — "/v1/chat/completions?param=1"
flow.request.url           # str  — full URL
flow.request.pretty_host   # str  — host from Host header (preferred in forward proxy mode)
flow.request.pretty_url    # str  — full URL using pretty_host
flow.request.headers       # Headers — dict-like, case-insensitive
flow.request.content       # bytes | None — decompressed body
flow.request.text          # str | None — decoded body
flow.request.query         # MultiDictView[str,str] — mutable view on query string
flow.request.cookies       # MultiDictView[str,str]
flow.request.http_version  # str — "HTTP/1.1"
```

### 3.2 Modifying request headers

```python
# Set or replace a header
flow.request.headers["Authorization"] = "Bearer sk-..."

# Delete a header
del flow.request.headers["Authorization"]

# Check existence
if "Authorization" in flow.request.headers:
    ...

# Append (do not fold) — use set_all for cookies
flow.request.headers.set_all("X-Multi", ["value1", "value2"])
```

### 3.3 Modifying query parameters

```python
# Set a query param (replaces if exists, adds if not)
flow.request.query["api_key"] = "key123"

# Delete a param
del flow.request.query["api_key"]

# Check existing
existing = flow.request.query.get("api_key")

# Modify URL directly (escaping handled automatically)
flow.request.url = "https://api.example.com/v1/data?api_key=key123&page=1"

# Or manipulate path (includes query string)
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl
parsed = urlparse(flow.request.url)
params = dict(parse_qsl(parsed.query))
params["api_key"] = "key123"
flow.request.path = urlunparse(('','', parsed.path, parsed.params, urlencode(params), ''))
```

### 3.4 `flow.response` properties

```python
flow.response.status_code  # int — 200
flow.response.reason       # str — "OK"
flow.response.headers      # Headers
flow.response.content      # bytes | None
flow.response.text         # str | None
```

---

## 4. Serving Synthetic Responses (`/__auth/*`)

To intercept a request and return a response without forwarding upstream, assign
`flow.response` in the `request` hook:

```python
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_host == "proxy.internal" and \
       flow.request.path.startswith("/__auth/"):
        handle_agent_request(flow)

def handle_agent_request(flow: http.HTTPFlow) -> None:
    path = flow.request.path

    if path == "/__auth/credentials" and flow.request.method == "GET":
        body = json.dumps([{"id": "openai", "domain": "api.openai.com", "enabled": True}])
        flow.response = http.Response.make(
            200,
            body.encode(),
            {"Content-Type": "application/json"},
        )
    elif path == "/__auth/request" and flow.request.method == "POST":
        # ... parse body, create pending request ...
        flow.response = http.Response.make(
            201,
            json.dumps({"setup_url": "...", "token": "...", "expires_in": 900}).encode(),
            {"Content-Type": "application/json"},
        )
    else:
        flow.response = http.Response.make(404, b"Not Found")
```

### `http.Response.make` signature

```python
@classmethod
def make(
    cls,
    status_code: int = 200,
    content: bytes | str = b"",
    headers: Headers | dict | Iterable[tuple[bytes, bytes]] = (),
) -> "Response":
    ...
```

**Important**: When `flow.response` is set in the `request` hook, mitmproxy skips the
upstream connection entirely. The `response` hook still fires so other addons can observe
the synthetic response.

---

## 5. Running FastAPI Alongside mitmproxy (In-Process)

### Option A: `mitmproxy.addons.asgiapp.ASGIApp` (built-in, recommended)

This is the canonical way. It intercepts requests to a virtual host:port and serves an ASGI app.

```python
# addon.py
import uvicorn
import asyncio
import threading

from mitmproxy.addons import asgiapp
from fastapi import FastAPI

# Create FastAPI app
app = FastAPI()

@app.get("/api/status")
async def status():
    return {"status": "ok"}

# Register as mitmproxy addon — intercepts requests to mgmt.local:8081
addons = [
    asgiapp.ASGIApp(app, "mgmt.local", 8081),
]
```

**Limitation of ASGIApp built-in**: It intercepts requests that come *through the proxy to a
specific virtual host*. This works perfectly if the management API is accessed as a proxy request,
but the management port `:8081` must be a separate listener, not handled through mitmproxy's `:8080`.

### Option B: Separate uvicorn thread (recommended for cred-proxy)

Since the management API needs its own TCP port (`:8081`), the right approach is to start uvicorn
in a separate thread from the mitmproxy addon's `running()` lifecycle hook:

```python
import asyncio
import threading
import uvicorn
import logging

from mitmproxy import ctx
from mitmproxy.addons import asgiapp

class AuthInjectionAddon:
    def __init__(self, mgmt_app, mgmt_port: int = 8081):
        self._mgmt_app = mgmt_app
        self._mgmt_port = mgmt_port
        self._uvicorn_thread: threading.Thread | None = None
        self._uvicorn_server: uvicorn.Server | None = None

    def load(self, loader):
        loader.add_option("config_path", str, "/data/config/credentials.yaml", "Config path")
        loader.add_option("mgmt_port", int, 8081, "Management API port")

    def running(self):
        """Called when mitmproxy is fully started. Start uvicorn here."""
        port = ctx.options.mgmt_port
        config = uvicorn.Config(
            self._mgmt_app,
            host="0.0.0.0",
            port=port,
            log_level="info",
        )
        self._uvicorn_server = uvicorn.Server(config)

        def run_server():
            # uvicorn runs its own event loop in this thread
            asyncio.run(self._uvicorn_server.serve())

        self._uvicorn_thread = threading.Thread(target=run_server, daemon=True)
        self._uvicorn_thread.start()
        logging.info(f"Management API started on port {port}")

    def done(self):
        """Called on shutdown."""
        if self._uvicorn_server:
            self._uvicorn_server.should_exit = True
        if self._uvicorn_thread:
            self._uvicorn_thread.join(timeout=5)

    def request(self, flow):
        ...

    def response(self, flow):
        ...
```

**Critical note about asyncio**: mitmproxy 11+ runs fully async on asyncio. The `request` and
`response` hooks can be `async def` and run on mitmproxy's event loop. Uvicorn needs its own event
loop (run in a separate thread). Do NOT share event loops between mitmproxy and uvicorn.

**Alternative: use `asyncio.get_event_loop()` from `running()` to schedule uvicorn as a task**:

```python
def running(self):
    # Get mitmproxy's running event loop and schedule uvicorn as a coroutine
    loop = asyncio.get_event_loop()
    config = uvicorn.Config(self._mgmt_app, host="0.0.0.0", port=8081)
    server = uvicorn.Server(config)
    loop.create_task(server.serve())
```

This shares mitmproxy's event loop. It works but uvicorn's startup time is on mitmproxy's loop.
The threading approach is more isolated and avoids potential interference.

---

## 6. Custom Options (`mitmproxy.ctx.options`)

```python
from mitmproxy import ctx

class MyAddon:
    def load(self, loader):
        loader.add_option(
            name="config_path",      # option name (also used as --set config_path=...)
            typespec=str,            # str | int | float | bool | Optional[T] | Sequence[T]
            default="/etc/creds.yaml",
            help="Path to credentials YAML",
        )

    def configure(self, updates):
        # `updates` is a set of option names that changed
        if "config_path" in updates:
            new_path = ctx.options.config_path
            self._reload_config(new_path)
        # Raise exceptions.OptionsError to reject invalid values
```

**Reading options anywhere**:
```python
from mitmproxy import ctx
path = ctx.options.config_path  # always up-to-date
```

**`ctx.master`** — gives access to the running Master object (use `ctx.master.commands.call(...)`)

---

## 7. HTTPS CONNECT Tunneling and TLS Interception

### How it works (verified from docs.mitmproxy.org/stable/concepts/how-mitmproxy-works/)

1. Client sends `CONNECT api.openai.com:443 HTTP/1.1` to mitmproxy
2. mitmproxy fires `http_connect` hook — addon can reject (set non-2xx response)
3. mitmproxy replies `200 Connection Established` to client
4. Client starts TLS handshake (using SNI `api.openai.com`)
5. mitmproxy pauses, connects to upstream `api.openai.com:443` using that SNI
6. mitmproxy reads upstream cert (CN + SANs), generates a forged cert signed by its CA
7. mitmproxy completes TLS handshake with client using forged cert
8. Subsequent requests arrive as plaintext to the addon — `request`/`response` hooks fire normally

**Result**: From the addon's perspective, HTTPS and HTTP look identical. `flow.request.scheme`
will be `"https"` and `flow.request.host` will be the real upstream hostname. No special handling
needed in addon code.

### CA certificate

Generated on first run at `{confdir}/mitmproxy-ca.pem`. Agent containers must trust
`{confdir}/mitmproxy-ca-cert.pem` (PEM format, no private key). Set via:
- `REQUESTS_CA_BUNDLE=/path/to/mitmproxy-ca-cert.pem` (Python requests/httpx)
- `SSL_CERT_FILE=/path/to/mitmproxy-ca-cert.pem` (OpenSSL-based tools)
- `NODE_EXTRA_CA_CERTS=/path/to/mitmproxy-ca-cert.pem` (Node.js)
- `update-ca-certificates` after copying to `/usr/local/share/ca-certificates/`

### Bypassing TLS interception for specific hosts

To avoid intercepting the proxy's own OAuth2 token requests (FR-5.5):

```bash
mitmdump --set ignore_hosts="auth.example.com" -s addon.py
```

Or dynamically from an addon using the `tls_start_client` hook or by marking the flow in
`http_connect`. Simpler: use `httpx` with direct TCP bypassing the proxy for token acquisition.

---

## 8. Testing with `mitmproxy.test.tflow`

**Source:** `mitmproxy/test/tflow.py`, `mitmproxy/test/tutils.py`

```python
from mitmproxy.test import tflow, tutils
from mitmproxy import http

# Create a basic GET flow
flow = tflow.tflow()                          # GET http://address:22/path
flow = tflow.tflow(resp=True)                 # with a 200 OK response

# Create flow with specific request attributes
flow = tflow.tflow(
    req=tutils.treq(
        host="api.openai.com",
        port=443,
        method=b"POST",
        scheme=b"https",
        path=b"/v1/chat/completions",
        headers=http.Headers(
            (b"content-type", b"application/json"),
            (b"content-length", b"42"),
        ),
        content=b'{"model":"gpt-4"}',
    )
)

# Create flow with a pre-set response
flow = tflow.tflow(
    req=tutils.treq(host="api.openai.com", path=b"/__auth/credentials"),
    resp=tutils.tresp(status_code=200, content=b'[]'),
)

# Test an addon hook directly
addon = MyAddon()
addon.request(flow)
assert flow.request.headers.get("Authorization") == "Bearer sk-test"

# Test with response
addon.response(flow)
assert "sk-test" not in (flow.response.text or "")
```

### `treq` defaults
```python
treq(
    host="address",
    port=22,
    method=b"GET",
    scheme=b"http",
    authority=b"",
    path=b"/path",
    http_version=b"HTTP/1.1",
    headers=http.Headers(((b"header", b"qvalue"), (b"content-length", b"7"))),
    content=b"content",
    trailers=None,
    timestamp_start=946681200,
    timestamp_end=946681201,
)
```

### `tresp` defaults
```python
tresp(
    http_version=b"HTTP/1.1",
    status_code=200,
    reason=b"OK",
    headers=http.Headers(
        ((b"header-response", b"svalue"), (b"content-length", b"7"))
    ),
    content=b"message",
    trailers=None,
    timestamp_start=946681202,
    timestamp_end=946681203,
)
```

---

## 9. Complete Addon Pattern for cred-proxy

Putting it all together — the pattern for `addon.py`:

```python
"""Auth injection proxy mitmproxy addon."""

import asyncio
import logging
import threading
from typing import Optional

import uvicorn

from mitmproxy import ctx, http
from mitmproxy.proxy.layers.http import HttpConnectHook

class AuthInjectionAddon:
    """
    Main mitmproxy addon. Wires together rule matching, auth injection,
    response stripping, agent API, and management API.
    """

    def __init__(self, store, pending_store, mgmt_app):
        self._store = store
        self._pending = pending_store
        self._mgmt_app = mgmt_app
        self._uvicorn_server: Optional[uvicorn.Server] = None

    # -----------------------------------------------------------------
    # Lifecycle hooks
    # -----------------------------------------------------------------

    def load(self, loader):
        loader.add_option("config_path", str, "/data/config/credentials.yaml", "Config YAML path")
        loader.add_option("mgmt_port", int, 8081, "Management API listen port")

    def configure(self, updates):
        if "config_path" in updates:
            self._store.reload(ctx.options.config_path)

    def running(self):
        """Start management API uvicorn in a background thread."""
        port = ctx.options.mgmt_port
        config = uvicorn.Config(self._mgmt_app, host="0.0.0.0", port=port, log_level="warning")
        self._uvicorn_server = uvicorn.Server(config)
        t = threading.Thread(target=lambda: asyncio.run(self._uvicorn_server.serve()), daemon=True)
        t.start()
        logging.info("Management API started on port %d", port)

    def done(self):
        if self._uvicorn_server:
            self._uvicorn_server.should_exit = True

    # -----------------------------------------------------------------
    # Proxy hooks
    # -----------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        # 1. Intercept /__auth/* (agent-facing API on the proxy port)
        if flow.request.pretty_host in ("proxy", "localhost", "") and \
           flow.request.path.startswith("/__auth/"):
            self._handle_agent_api(flow)
            return

        # 2. Match credential rule
        rule = self._store.match(flow)
        if rule is None:
            return  # passthrough

        # 3. Inject auth
        self._inject_auth(flow, rule)

    def response(self, flow: http.HTTPFlow) -> None:
        # Strip injected secrets from responses
        rule = getattr(flow, "_matched_rule", None)
        if rule and flow.response:
            self._strip_secrets(flow, rule)

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _handle_agent_api(self, flow: http.HTTPFlow) -> None:
        """Serve synthetic response for /__auth/* requests."""
        from auth_injection_proxy.agent_api.handlers import handle_agent_request
        handle_agent_request(flow, self._store, self._pending)

    def _inject_auth(self, flow: http.HTTPFlow, rule) -> None:
        from auth_injection_proxy.injection.injector import inject_auth
        inject_auth(flow, rule)
        flow._matched_rule = rule  # stash for response hook

    def _strip_secrets(self, flow: http.HTTPFlow, rule) -> None:
        from auth_injection_proxy.stripping.response_strip import strip_secrets
        strip_secrets(flow, rule)


# Entry point for mitmdump -s addon.py
def make_addon():
    from auth_injection_proxy.store.yaml_store import YamlCredentialStore
    from auth_injection_proxy.requests.pending import PendingRequestStore
    from auth_injection_proxy.mgmt.app import create_app

    store = YamlCredentialStore()
    pending = PendingRequestStore()
    mgmt_app = create_app(store, pending)
    return AuthInjectionAddon(store, pending, mgmt_app)

addons = [make_addon()]
```

---

## 10. Key Files and API Summary Table

| Import | Key Classes/Functions | Purpose |
|--------|-----------------------|---------|
| `mitmproxy.http` | `HTTPFlow`, `Request`, `Response`, `Headers` | Core HTTP data model |
| `mitmproxy.ctx` | `ctx.options`, `ctx.master` | Global context |
| `mitmproxy.addons.asgiapp` | `ASGIApp`, `WSGIApp` | In-proxy ASGI/WSGI host |
| `mitmproxy.test.tflow` | `tflow()`, `tclient_conn()`, `tserver_conn()` | Test flow factories |
| `mitmproxy.test.tutils` | `treq()`, `tresp()` | Test request/response factories |
| `mitmproxy.script` | `concurrent` | Thread-based async decorator |
| `mitmproxy.exceptions` | `OptionsError` | Reject invalid option values |

### `Request` key properties (verified from source)

| Property | Type | Description |
|----------|------|-------------|
| `host` | `str` | Target server hostname |
| `pretty_host` | `str` | Host from Host header (preferred in forward proxy) |
| `port` | `int` | Target port |
| `scheme` | `str` | `"http"` or `"https"` |
| `method` | `str` | `"GET"`, `"POST"`, etc. |
| `path` | `str` | Path + query string (e.g. `/v1/foo?k=v`) |
| `url` | `str` | Full URL |
| `pretty_url` | `str` | Full URL using pretty_host |
| `headers` | `Headers` | Case-insensitive dict-like |
| `query` | `MultiDictView[str,str]` | Mutable query param view |
| `content` | `bytes | None` | Decompressed body |
| `text` | `str | None` | Decoded body |

### `Response.make` signature (verified from source, line ~1050)

```python
http.Response.make(
    status_code: int = 200,
    content: bytes | str = b"",
    headers: Headers | dict | Iterable[tuple[bytes,bytes]] = (),
) -> Response
```

---

## 11. Critical Gotchas for cred-proxy Implementation

1. **`flow.request.pretty_host` vs `flow.request.host`**: In forward proxy mode (HTTPS via CONNECT),
   use `pretty_host` — it reads the `Host` header which has the correct hostname. `host` may be an
   IP in transparent mode.

2. **Setting `flow.response` in `request` hook**: This is the correct way to serve `/__auth/*`
   responses. The upstream connection is never made.

3. **Async hooks for OAuth2**: Token acquisition with httpx should be `async def request(...)` to
   avoid blocking mitmproxy while waiting for the token endpoint.

4. **OAuth2 token acquisition bypasses its own interception**: Use `httpx.AsyncClient()` directly
   (not via proxy). Or add the token endpoint to `ignore_hosts`. Or check in the `request` hook
   if the request originates from the addon itself (not possible directly — use a flag or direct HTTP).
   Best approach: use `httpx.AsyncClient()` with `proxies={}` (no proxy) to bypass mitmproxy.

5. **`flow.live` attribute**: `True` when the flow belongs to an active connection. The built-in
   `asgiapp.ASGIApp` checks `flow.live` before serving — replayed flows are skipped.

6. **Uvicorn + mitmproxy event loops**: Run uvicorn in a daemon thread with its own `asyncio.run()`
   to keep event loops completely isolated.

7. **`Headers` is case-insensitive**: `flow.request.headers["authorization"]` and
   `flow.request.headers["Authorization"]` access the same header.

8. **`flow.response.stream`**: Must be set in `responseheaders` hook, not `response` hook. If set
   in `response`, the body is already fully buffered and the flag is ignored.

9. **`block_global=false`**: Must be set when running in Docker where mitmproxy may need to reach
   RFC-1918 addresses or the management API on loopback. Default is `true` which blocks these.
