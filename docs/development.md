# Development

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- [just](https://github.com/casey/just) command runner (optional but recommended)

## Setup

```bash
git clone https://github.com/your-org/cred-proxy.git
cd cred-proxy

# Install all dependencies (dev + docs)
uv sync --extra dev --extra docs
```

## Running Locally

```bash
# Copy example config
cp config.example.yaml credentials.yaml

# Start the proxy
just run credentials.yaml

# Or directly:
uv run mitmdump \
  --listen-port 8080 \
  --set block_global=false \
  -s src/auth_injection_proxy/addon.py \
  --set config_path="credentials.yaml"
```

## Project Structure

```
src/auth_injection_proxy/
├── addon.py                 # mitmproxy addon entry point
├── config.py                # YAML config loading
├── logging.py               # Logging with secret masking
├── matching/
│   ├── models.py            # Pydantic models (rules, auth types)
│   └── rules.py             # Domain/path matching
├── injection/
│   ├── injector.py          # Auth injection dispatcher
│   ├── bearer.py            # Bearer token injection
│   ├── basic.py             # Basic auth injection
│   ├── header.py            # Custom header injection
│   ├── query_param.py       # Query parameter injection
│   └── oauth2.py            # OAuth2 client credentials
├── stripping/
│   └── response_strip.py    # Secret stripping from responses
├── store/
│   ├── interface.py         # CredentialStore ABC
│   ├── yaml_store.py        # YAML-backed store (atomic write, hot-reload)
│   └── masking.py           # Secret masking utilities
├── agent_api/
│   └── handlers.py          # /__auth/* agent API handlers
├── requests/
│   └── pending.py           # Pending request store (TTL, rate limiting)
└── mgmt/
    ├── app.py               # FastAPI application factory
    ├── routes_credentials.py # CRUD /api/credentials
    ├── routes_setup.py      # /setup/{token} flow
    ├── routes_status.py     # /api/status
    └── templates/
        └── setup.html       # Jinja2 setup form template
```

## Testing

The test suite has 133 tests across unit and integration tests.

```bash
# Run all tests
just test

# Run unit tests only
just test-unit

# Run integration tests only
just test-integration

# Run with verbose output
just test -v

# Run a specific test file
uv run pytest tests/unit/test_matching.py -v

# Run with coverage
uv run pytest tests/ --cov=auth_injection_proxy --cov-report=term-missing
```

### Test Organization

| Directory | Tests | What's covered |
|-----------|-------|----------------|
| `tests/unit/` | 13 files | Models, matching, injection (all 5 types), response stripping, config loading, masking, pending requests, logging |
| `tests/integration/` | 5 files | Addon request/response flow, management API, agent API, setup flow, hot-reload |

### Key Fixtures

Fixtures are defined in `tests/conftest.py`:

- `sample_rules` — list of `CredentialRule` objects covering all 5 auth types
- `yaml_store` / `yaml_store_with_rules` — `YamlCredentialStore` instances backed by temp files
- `pending_store` — `PendingRequestStore` with short TTL for testing
- `mgmt_client` — FastAPI `TestClient` for management API tests
- `mock_flow` — factory for creating mitmproxy `HTTPFlow` objects

## Linting and Type Checking

```bash
# Run linter + format check
just lint

# Auto-fix lint and formatting
just fix

# Run type checker
just typecheck
```

Tools and configuration:

| Tool | Config | Purpose |
|------|--------|---------|
| [ruff](https://docs.astral.sh/ruff/) | `pyproject.toml [tool.ruff]` | Linting (E, F, I, N, W, UP rules) and formatting |
| [mypy](https://mypy.readthedocs.io/) | `pyproject.toml [tool.mypy]` | Static type checking (strict-ish) |

## CI Pipeline

The GitHub Actions CI workflow (`.github/workflows/ci.yml`) runs on every push and PR to `main`:

1. **Lint** — `ruff check` and `ruff format --check`
2. **Typecheck** — `mypy src/`
3. **Test** — unit tests, then integration tests

## Release Process

```bash
# Bump version, commit, and tag
just release 0.2.0

# Push the release
git push origin main --tags
```

The `release` target validates semver format, updates `pyproject.toml`, runs `uv lock`, commits, and creates an annotated git tag.

## Adding a New Auth Type

To add a new authentication type (e.g., `api_signature`):

1. **Define the model** in `src/auth_injection_proxy/matching/models.py`:

    ```python
    class ApiSignatureAuth(BaseModel):
        type: Literal["api_signature"]
        api_key: str
        api_secret: str
    ```

2. **Add it to the `AuthConfig` union** in the same file:

    ```python
    AuthConfig = Annotated[
        Union[
            BearerAuth,
            BasicAuth,
            HeaderAuth,
            QueryParamAuth,
            OAuth2ClientCredentialsAuth,
            ApiSignatureAuth,  # Add here
        ],
        Field(discriminator="type"),
    ]
    ```

3. **Create the injector** at `src/auth_injection_proxy/injection/api_signature.py`:

    ```python
    from mitmproxy import http
    from auth_injection_proxy.matching.models import ApiSignatureAuth

    def inject(flow: http.HTTPFlow, auth: ApiSignatureAuth) -> list[str]:
        # Compute signature, set headers, etc.
        signature = compute_signature(auth.api_key, auth.api_secret, flow)
        flow.request.headers["X-Api-Signature"] = signature
        return [auth.api_secret]  # Return secrets for response stripping
    ```

4. **Register it in the dispatcher** at `src/auth_injection_proxy/injection/injector.py`:

    ```python
    case ApiSignatureAuth():
        from auth_injection_proxy.injection.api_signature import inject
        return inject(flow, rule.auth)
    ```

5. **Add masking** in `src/auth_injection_proxy/store/masking.py`:

    ```python
    case ApiSignatureAuth():
        data["auth"]["api_secret"] = mask_secret(auth.api_secret)
    ```

6. **Add the type to validation** in `src/auth_injection_proxy/agent_api/handlers.py`:

    ```python
    VALID_AUTH_TYPES = {"bearer", "basic", "header", "query_param",
                        "oauth2_client_credentials", "api_signature"}
    ```

7. **Write tests** — unit test for injection, update integration tests.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run the full check suite: `just lint && just typecheck && just test`
5. Commit and open a pull request
