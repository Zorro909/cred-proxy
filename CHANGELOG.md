# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-02-24

### Fixed

- `path_prefix: null` written to credentials.yaml when path_prefix is omitted (#2)

## [0.2.1] - 2026-02-24

### Fixed

- Docker image failing to start because `mitmdump` was not on PATH (#1)

## [0.1.0] - 2025-02-22

### Added

- mitmproxy addon with request interception and credential injection
- FastAPI management API for credential CRUD operations
- Five authentication strategies: Bearer token, Basic auth, custom Header, Query parameter, OAuth2 client credentials
- Domain wildcard and path prefix matching for credential rules
- YAML-based credential storage with atomic writes and hot-reload via watchfiles
- Response stripping to prevent credential leakage in responses
- Agent API (`/__auth/*`) for in-band credential requests from proxied clients
- Pending request store with TTL, rate limiting, and single-use approval tokens
- Browser-based setup flow for interactive credential configuration
- Secret masking in logs via custom logging filter
- Docker image with mitmproxy + management API on ports 8080/8081
- 133 tests (unit + integration)
