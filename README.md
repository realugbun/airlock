# Airlock

[![CI](https://github.com/realugbun/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/realugbun/airlock/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/realugbun/airlock)](https://goreportcard.com/report/github.com/realugbun/airlock)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A secure reverse proxy sidecar for AI agents. Airlock sits between your agent and external APIs, handling authentication, access control, and rate limiting so the agent never sees real credentials.

> **Pre-1.0 notice:** Airlock is under active development. Configuration, Helm chart values, and some behaviors may change between minor releases until 1.0.

## Why

AI agents need to call external APIs (OpenAI, GitHub, Slack, etc.) but giving them raw API keys is risky:

- **Credential exposure** — agent logs, prompt injections, or bugs can leak keys
- **Unrestricted access** — an agent with a GitHub token can delete repos, not just read them
- **No visibility** — hard to see what the agent is actually doing across multiple APIs
- **Blast radius** — one compromised key can affect everything

Airlock solves this by acting as a gateway. The agent talks to Airlock over a local network. Airlock injects credentials, enforces firewall-style access rules, rate limits requests, and forwards them upstream. The agent never has access to real secrets.

```
┌──────────────────────────────────────────────────────┐
│  Isolated Network                                    │
│                                                      │
│  ┌─────────┐         ┌─────────┐                     │
│  │  Agent   │──HTTP──▶│ Airlock │──┐                  │
│  └─────────┘         └─────────┘  │                  │
│   No credentials      Injects     │                  │
│   No internet          auth       │                  │
│                                   │                  │
└───────────────────────────────────┼──────────────────┘
                                    │
                          ┌─────────▼──────────┐
                          │   External APIs     │
                          │  (OpenAI, GitHub…)  │
                          └────────────────────┘
```

## Features

- **Firewall-style access rules** — method + path globs, first-match-wins, implicit deny
- **MCP tool filtering** — allowlist/denylist for JSON-RPC tool calls on MCP servers
- **Auth injection** — static tokens or OAuth2 refresh flow, agent never sees credentials
- **Secret providers** — env vars, files, HashiCorp Vault, AWS Secrets Manager
- **Automatic credential redaction** — headers + body, including SSE streams
- **Per-route rate limiting** — token bucket with configurable burst
- **Request + idle timeouts** — per-route, SSE-aware idle detection
- **OpenTelemetry** — traces + metrics to any OTEL-compatible backend
- **Hot reload** — `SIGHUP` swaps routes atomically, in-flight requests complete
- **~10MB scratch image** — no shell, no OS, minimal attack surface

## Quick Start

### 1. Create a config file

```yaml
listen: ":8080"
service: "my-agent"

providers:
  env: {}

routes:
  - path_prefix: "/openai"
    upstream: "https://api.openai.com"
    strip_prefix: "/openai"
    auth:
      type: static
      token:
        from: env
        key: "OPENAI_API_KEY"
      header: "Authorization"
      prefix: "Bearer "
    access_rules:
      - action: ALLOW
        method: POST
        path: /v1/chat/completions
      - action: ALLOW
        method: POST
        path: /v1/embeddings
```

Strict mode is on by default — every route must include `access_rules` or Airlock refuses to start.

### 2. Run it

```bash
# Docker
docker run -p 8080:8080 \
  -e OPENAI_API_KEY=sk-... \
  -v ./config.yaml:/config.yaml:ro \
  ghcr.io/realugbun/airlock:0.1.0

# Or build from source
make build
OPENAI_API_KEY=sk-... ./bin/airlock -config config.yaml
```

### 3. Point your agent at Airlock

```python
from openai import OpenAI

# Instead of talking directly to OpenAI, go through Airlock
client = OpenAI(
    base_url="http://localhost:8080/openai/v1",
    api_key="unused",  # Airlock injects the real key
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The agent doesn't know Airlock exists. It just talks to a URL. Airlock handles the rest.

## How Routing Works

Each route has a `path_prefix` that determines which upstream API a request goes to. The prefix is stripped before forwarding:

```yaml
routes:
  - path_prefix: "/openai"
    upstream: "https://api.openai.com"
    strip_prefix: "/openai"
    ...

  - path_prefix: "/github"
    upstream: "https://api.github.com"
    strip_prefix: "/github"
    ...
```

| Agent request | Matched route | Upstream request |
|---|---|---|
| `GET /openai/v1/models` | `/openai` | `GET https://api.openai.com/v1/models` |
| `GET /github/repos/org/repo` | `/github` | `GET https://api.github.com/repos/org/repo` |
| `GET /unknown/path` | none | `404 Not Found` |

Configure your agent by setting the base URL for each SDK:

```python
# OpenAI
client = OpenAI(base_url="http://airlock:8080/openai/v1")

# Anthropic
client = Anthropic(base_url="http://airlock:8080/anthropic")

# Any HTTP client
requests.get("http://airlock:8080/github/repos/myorg/myrepo")
```

Routes are matched in order — first match wins. Put more specific prefixes before broader ones.

## Access Rules

Airlock uses firewall-style rules to control what the agent can do. Rules are evaluated in order. First match wins. If rules are defined but nothing matches, the request is denied (implicit deny).

**Strict mode** (default) requires `access_rules` on every route — a route with auth but no rules is a startup error. Set `strict: false` to opt out. Three behaviors for `access_rules`:

- **Omitted** — allow all requests (only permitted with `strict: false`)
- **`access_rules: []`** — explicit empty list, deny all requests
- **`access_rules: [...]`** — evaluate rules, implicit deny at end

### Path Patterns

| Pattern | Matches | Doesn't match |
|---|---|---|
| `/v1/models` | `/v1/models` (exact) | `/v1/models/gpt-4` |
| `/users/*/detail` | `/users/123/detail`, `/users/abc/detail` | `/users/detail`, `/users/1/2/detail` |
| `/repos/**` | `/repos`, `/repos/foo`, `/repos/foo/bar/baz` | `/other` |
| `/api/*/files/**` | `/api/v1/files/readme.md`, `/api/v2/files/a/b/c` | `/api/files/x`, `/api/v1/v2/files/x` |

- `*` matches exactly one non-empty path segment
- `**` matches zero or more path segments
- Actions: `ALLOW` or `DENY` (returns 403)
- Methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, or `ALL`

**Example — allow-only (strict whitelist):**

```yaml
access_rules:
  - action: ALLOW
    method: POST
    path: /v1/chat/completions
  - action: ALLOW
    method: GET
    path: /v1/models
  # Everything else is denied (implicit deny)
```

See [docs/security.md](docs/security.md) for path normalization rules and security testing details.

## MCP Tool Filtering

When proxying [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) servers, path-based rules can't distinguish `get_events` (read) from `delete_event` (destructive). Add `mcp_rules` to inspect JSON-RPC request bodies:

**Allow all tools** (proxy with auth injection, no filtering):

```yaml
mcp_rules: {}
```

**Block specific tools:**

```yaml
mcp_rules:
  denied_tools:
    - delete_event
    - send_message
```

**Strict allowlist:**

```yaml
mcp_rules:
  allowed_tools:
    - get_events
    - list_calendars
    - search_emails
```

Tool names support glob patterns (`*`, `?`, `[chars]`) for matching groups of tools:

```yaml
mcp_rules:
  denied_tools:
    - "*_delete"
    - "*_remove"
    - "admin_*"
```

Non-tool MCP methods (`initialize`, `ping`, etc.) always pass through. When a tool is denied, Airlock returns a JSON-RPC 2.0 error with HTTP 403:

```json
{"jsonrpc":"2.0","id":3,"error":{"code":-32600,"message":"tool \"delete_event\" is not allowed"}}
```

Airlock also filters `tools/list` responses — agents only see tools they're permitted to use.

## Authentication

Airlock injects credentials into outbound requests. The agent never sees them.

**Static token** — API keys, bearer tokens:

```yaml
auth:
  type: static
  token:
    from: env
    key: "API_KEY"
  header: "Authorization"
  prefix: "Bearer "
```

**OAuth2** — automatic refresh token flow:

```yaml
auth:
  type: oauth2
  client_id:    { from: vault, path: "secret/app", key: "client-id" }
  client_secret: { from: vault, path: "secret/app", key: "client-secret" }
  refresh_token: { from: vault, path: "secret/app", key: "refresh-token" }
  token_url: "https://github.com/login/oauth/access_token"
  scopes: "repo read:org"
  header: "Authorization"
  prefix: "Bearer "
```

See [docs/configuration.md](docs/configuration.md) for secret providers (env, file, Vault, AWS SM) and full auth configuration.

## Non-Goals

Airlock is a credential gateway for AI agents. It is **not**:

- **A general-purpose API gateway** — no load balancing, caching, or request transformation
- **A WAF** — no SQL injection detection, payload scanning, or content filtering
- **A replacement for upstream RBAC** — Airlock controls which endpoints the agent can call, not what the API does with the request
- **An agent sandbox** — it doesn't restrict what the agent does locally, only what it can reach over HTTP
- **A DLP platform** — it redacts injected credentials, not arbitrary sensitive data in responses
- **Semantic intent verification** — MCP tool filtering matches tool names (with globs), not what the tool actually does

## Deployment

```bash
docker run -d --name airlock -p 8080:8080 \
  -e OPENAI_API_KEY=sk-... \
  -v ./config.yaml:/config.yaml:ro \
  ghcr.io/realugbun/airlock:0.1.0
```

For production, use Docker Compose network isolation (agent on `internal: true` network, Airlock bridging to external) or Kubernetes with NetworkPolicy. See [docs/deployment.md](docs/deployment.md) for full examples including Helm charts and DNS hardening.

## Building

```bash
make build           # Build binary to bin/airlock
make test            # Run tests with race detector
make lint            # Run golangci-lint
make docker          # Build Docker image
make push            # Build and push to registry
make test-coverage   # Generate HTML coverage report
```

Requires Go 1.25+.

## Documentation

- [Configuration Reference](docs/configuration.md) — secret providers, auth types, rate limiting, timeouts, observability, hot reload
- [Security](docs/security.md) — threat model, path normalization, fuzz testing, production checklist
- [Deployment](docs/deployment.md) — Docker Compose isolation, Helm/Kubernetes, DNS hardening, agent auth proxy
- [Claude Code Guide](docs/claude-code-guide.md) — running Claude Code through Airlock with fake credentials, git proxying, and network isolation
- [Examples](examples/) — ready-to-use config files for common setups

Before deploying to production, review the [production checklist](docs/security.md#production-checklist).

## License

[Apache 2.0](LICENSE)
