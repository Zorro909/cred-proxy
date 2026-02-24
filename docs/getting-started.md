# Getting Started

Get cred-proxy running in 5 minutes with Docker Compose.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- A `credentials.yaml` file with your API credentials

## 1. Clone and Configure

```bash
git clone https://github.com/your-org/cred-proxy.git
cd cred-proxy
```

Copy the example config and add your credentials:

```bash
cp config.example.yaml credentials.yaml
```

Edit `credentials.yaml` with your API keys:

```yaml
proxy:
  listen_port: 8080
  mgmt_port: 8081

credentials:
  - id: "openai-prod"
    domain: "api.openai.com"
    path_prefix: "/v1/"
    enabled: true
    auth:
      type: bearer
      token: "sk-proj-your-actual-key-here"
```

See [Configuration](configuration.md) for all auth types and options.

## 2. Start the Proxy

```bash
docker compose up -d
```

This starts:

- **auth-proxy** on port `8080` (proxy) and `8081` (management API)
- Generates mitmproxy CA certificates in a shared volume

Check it's running:

```bash
curl http://localhost:8081/api/status
```

```json
{"status": "ok", "uptime_seconds": 5.2, "total_rules": 1, "enabled_rules": 1}
```

## 3. Point Your Agent at the Proxy

Configure your agent container to route traffic through the proxy. In `docker-compose.yml`, the agent service is pre-configured:

```yaml
agent:
  image: your-agent-image
  networks:
    - agent-net
  environment:
    - HTTP_PROXY=http://auth-proxy:8080
    - HTTPS_PROXY=http://auth-proxy:8080
    - REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/mitmproxy-ca.crt
  volumes:
    - proxy-certs:/usr/local/share/ca-certificates:ro
  depends_on:
    auth-proxy:
      condition: service_healthy
```

Replace `your-agent-image` with your actual agent Docker image.

## 4. Verify It Works

From inside the agent container (or any container on the `agent-net` network), make a request without credentials:

```bash
# This request has no Authorization header, but cred-proxy will inject one
curl -x http://auth-proxy:8080 https://api.openai.com/v1/models
```

The proxy matches the domain `api.openai.com` with path prefix `/v1/`, injects the bearer token, and forwards the authenticated request.

## Running Locally (Without Docker)

For development or testing without Docker:

```bash
# Install dependencies
uv sync --extra dev

# Run the proxy directly
uv run mitmdump \
  --listen-port 8080 \
  --set block_global=false \
  -s src/auth_injection_proxy/addon.py \
  --set config_path="credentials.yaml"
```

Or with the Justfile:

```bash
just run credentials.yaml
```

Then point your HTTP client at `http://localhost:8080`:

```bash
curl -x http://localhost:8080 https://api.openai.com/v1/models
```

!!! note "CA Certificate"
    When using HTTPS through the proxy, you need to trust mitmproxy's CA certificate.
    The certificate is generated at `~/.mitmproxy/mitmproxy-ca-cert.pem` on first run.
    Set `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE` to this path in your client.
