#!/bin/bash
set -e
cp "${CERTS_DIR:-/data/certs}/mitmproxy-ca-cert.pem" "$1"
