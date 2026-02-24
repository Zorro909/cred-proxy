FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies only (cached layer)
RUN uv sync --frozen --no-dev --no-install-project

# Copy application and install project
COPY README.md ./
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable

# Make venv binaries available without activation
ENV PATH="/app/.venv/bin:$PATH"

COPY scripts/ scripts/

# Volumes
VOLUME /data/certs
VOLUME /data/config

# Ports
EXPOSE 8080 8081

# Entrypoint
ENTRYPOINT ["scripts/entrypoint.sh"]
