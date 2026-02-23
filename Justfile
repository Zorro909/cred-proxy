# Auth Injection Proxy — Task Runner

# Install all dependencies including dev extras
install:
    uv sync --extra dev

# Run linter and format checker
lint:
    uv run ruff check src/ tests/
    uv run ruff format --check src/ tests/

# Auto-fix lint and formatting issues
fix:
    uv run ruff check --fix src/ tests/
    uv run ruff format src/ tests/

# Run type checker
typecheck:
    uv run mypy src/

# Run all tests
test *ARGS:
    uv run pytest {{ARGS}}

# Run unit tests only
test-unit *ARGS:
    uv run pytest tests/unit/ -v {{ARGS}}

# Run integration tests only
test-integration *ARGS:
    uv run pytest tests/integration/ -v {{ARGS}}

# Run proxy with example config
run CONFIG="config.example.yaml":
    uv run mitmdump \
        --listen-port 8080 \
        --set block_global=false \
        -s src/auth_injection_proxy/addon.py \
        --set config_path="{{CONFIG}}"

# Build Docker image
docker-build TAG="auth-injection-proxy:latest":
    docker build -t {{TAG}} .
