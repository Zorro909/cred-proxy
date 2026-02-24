# Deployment

cred-proxy is designed for Docker-based deployment with network isolation between the agent and the internet.

## Docker Compose

The provided `docker-compose.yml` sets up the full topology:

```yaml
networks:
  agent-net:
    internal: true        # No internet access
  proxy-external:
    driver: bridge        # Internet access for the proxy

services:
  auth-proxy:
    build: .
    networks:
      agent-net: {}       # Reachable by agents
      proxy-external: {}  # Can reach the internet
    ports:
      - "127.0.0.1:8081:8081"  # Management API (localhost only)
    volumes:
      - ./credentials.yaml:/data/config/credentials.yaml
      - proxy-certs:/data/certs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/api/status"]
      interval: 5s
      timeout: 3s
      retries: 3

  agent:
    image: your-agent-image
    networks:
      - agent-net          # Internal only — no direct internet
    environment:
      - HTTP_PROXY=http://auth-proxy:8080
      - HTTPS_PROXY=http://auth-proxy:8080
      - REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/mitmproxy-ca.crt
    volumes:
      - proxy-certs:/usr/local/share/ca-certificates:ro
    depends_on:
      auth-proxy:
        condition: service_healthy

volumes:
  proxy-certs:            # Shared CA certificates
```

### Key Points

- **`agent-net` is internal** — containers on this network cannot reach the internet directly
- **Only `auth-proxy` is on both networks** — it bridges agent traffic to the internet
- **Port `8081` is bound to `127.0.0.1`** — management API is only accessible from the host
- **Port `8080` is not exposed** — proxy traffic stays within Docker networks
- **Healthcheck** ensures the agent waits for the proxy to be ready

## CA Certificate Trust

mitmproxy generates a CA certificate on first run. For HTTPS interception to work, the agent must trust this CA:

1. The proxy stores its CA certificate in `/data/certs/` (Docker volume: `proxy-certs`)
2. The agent mounts this volume read-only at `/usr/local/share/ca-certificates/`
3. The `REQUESTS_CA_BUNDLE` environment variable tells Python's `requests`/`httpx` libraries to trust it

For other languages or HTTP clients, set the appropriate CA trust variable:

| Client / Language | Environment Variable |
|-------------------|---------------------|
| Python (requests, httpx) | `REQUESTS_CA_BUNDLE` |
| Python (ssl module) | `SSL_CERT_FILE` |
| Node.js | `NODE_EXTRA_CA_CERTS` |
| curl | `CURL_CA_BUNDLE` |
| Go | `SSL_CERT_FILE` |
| System-wide (Debian) | Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates` |

## Environment Variables

The proxy container accepts these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_PATH` | `/data/config/credentials.yaml` | Path to the credentials YAML file |
| `LISTEN_PORT` | `8080` | Proxy listen port |
| `CERTS_DIR` | `/data/certs` | Directory for mitmproxy CA certificates |

## Building the Docker Image

```bash
# Build locally
docker build -t auth-injection-proxy .

# Or with just
just docker-build

# With a custom tag
just docker-build my-registry/auth-proxy:v0.1.0
```

## Custom Agent Container

To add the proxy trust to your own agent Dockerfile:

```dockerfile
FROM python:3.12-slim

# Copy CA certificate from the shared volume at runtime
# (mounted via docker-compose volumes)
ENV REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/mitmproxy-ca.crt
ENV HTTP_PROXY=http://auth-proxy:8080
ENV HTTPS_PROXY=http://auth-proxy:8080

# Your agent setup
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

CMD ["python", "agent.py"]
```

Then in `docker-compose.yml`:

```yaml
agent:
  build: ./my-agent
  networks:
    - agent-net
  volumes:
    - proxy-certs:/usr/local/share/ca-certificates:ro
  depends_on:
    auth-proxy:
      condition: service_healthy
```

## Production Considerations

!!! warning "Not production-hardened"
    cred-proxy is designed for development and controlled environments. Review these considerations before running in production.

- **Management API access** — the management API has no authentication. Keep port 8081 bound to localhost or behind a reverse proxy with auth.
- **Credential storage** — credentials are stored in a plain YAML file. For production, consider implementing a vault-backed `CredentialStore`.
- **TLS termination** — the management API runs over plain HTTP. Use a reverse proxy (nginx, Caddy) for TLS if exposing beyond localhost.
- **Log sensitivity** — ensure log aggregation does not capture request bodies, which may contain credentials before injection.
- **Resource limits** — set Docker memory and CPU limits for the proxy container.
- **Monitoring** — poll `/api/status` for health checks. Integrate with your monitoring stack.
