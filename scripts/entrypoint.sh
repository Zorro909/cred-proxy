#!/bin/bash
set -e

CONFIG_PATH="${CONFIG_PATH:-/data/config/credentials.yaml}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
CERTS_DIR="${CERTS_DIR:-/data/certs}"

# Start mitmdump with the addon
exec mitmdump \
  --listen-port "$LISTEN_PORT" \
  --set confdir="$CERTS_DIR" \
  --set block_global=false \
  -s src/auth_injection_proxy/addon.py \
  --set config_path="$CONFIG_PATH"
