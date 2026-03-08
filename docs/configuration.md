# Configuration Reference

This document covers Airlock's full configuration including secret providers, authentication, rate limiting, timeouts, observability, and response security.

## Full Configuration

```yaml
# ─── Server ───
listen: ":8080"              # Listen address (default: ":8080")
service: "my-agent"          # Service name (required, used in logs)
agent_id: "agent-01"         # Optional agent identifier
strict: true                 # Require access_rules on all routes (default: true)

# ─── Telemetry ───
telemetry:
  endpoint: "otel:4317"      # OTLP gRPC endpoint (omit to disable)
  service_name: "airlock"    # OTEL service name
  insecure: true             # Use insecure gRPC connection

# ─── Secret Providers ───
providers:
  env: {}                          # Environment variables
  file: {}                         # Raw file content
  envfile:
    path: "/path/to/.env"          # KEY=VALUE file
  vault:
    address: "https://vault:8200"  # Vault address
    token_path: "/path/to/token"   # Vault token file
    skip_verify: false             # Skip TLS verification
    cache_ttl: "5m"                # Secret cache duration
  aws_sm:
    region: "us-east-1"            # AWS region

# ─── Routes ───
routes:
  - path_prefix: "/openai"           # Match requests starting with this
    upstream: "https://api.openai.com" # Forward to this URL
    strip_prefix: "/openai"           # Remove this prefix before forwarding
    timeout: "300s"                    # Total request timeout (default 300s, 0 to disable)
    idle_timeout: "60s"               # Idle stream timeout (default 60s, 0 to disable)
    strip_agent_auth: false            # Strip incoming auth headers before injecting
    extra_headers:                     # Additional headers to inject upstream
      X-Custom: "value"

    auth:
      type: static                    # "static" or "oauth2"
      token:                          # Secret reference
        from: env                     #   Provider name
        path: ""                      #   Secret path (provider-specific)
        key: "OPENAI_API_KEY"         #   Key within the secret
      header: "Authorization"         # Header to inject
      prefix: "Bearer "              # Value prefix

    rate_limit:                       # Optional
      rps: 10                         # Requests per second
      burst: 20                       # Max burst

    access_rules:                     # Required in strict mode (default)
      - action: ALLOW                 # ALLOW or DENY
        method: POST                  # GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, or ALL
        path: /v1/chat/completions    # Exact path or glob pattern (* / **)

    strip_response_headers:           # Optional — remove these upstream headers
      - Server
      - X-Powered-By

    mcp_rules:                        # Optional — MCP tool-level filtering
      allowed_tools:                  # Only these tools allowed (strict allowlist)
        - get_events
        - list_calendars
        - "calendar_*"               # Glob patterns supported (*, ?, [chars])
      # OR
      denied_tools:                   # These tools blocked, rest allowed
        - delete_event
        - send_message
        - "*_delete"                  # Glob: block all tools ending in _delete
```

## Secret Providers

Credentials are never stored in the config file. They're resolved at runtime from secret providers.

### Environment Variables

```yaml
providers:
  env: {}

# Usage
token:
  from: env
  key: "OPENAI_API_KEY"
```

### File

Reads the entire file content as the secret value:

```yaml
providers:
  file: {}

# Usage
token:
  from: file
  path: "/run/secrets/api-key"
```

### Env File

Reads a `KEY=VALUE` file (supports comments and quoted values):

```yaml
providers:
  envfile:
    path: "/run/secrets/credentials.env"

# Usage
token:
  from: envfile
  key: "API_SECRET"
```

### HashiCorp Vault

```yaml
providers:
  vault:
    address: "https://vault.example.com:8200"
    token_path: "/run/secrets/vault-token"
    skip_verify: false
    cache_ttl: "5m"     # default: 5m

# Usage
token:
  from: vault
  path: "secret/openai"
  key: "api-key"
```

### AWS Secrets Manager

```yaml
providers:
  aws_sm:
    region: "us-east-1"

# Usage
token:
  from: aws_sm
  path: "my-app/openai-key"
  key: "api-key"          # JSON field within the secret
```

## Authentication

Airlock injects credentials into outbound requests. The agent never sees them.

### Static Token

Injects a fixed token (API key, bearer token, etc.):

```yaml
auth:
  type: static
  token:
    from: env          # secret provider
    key: "API_KEY"     # key to look up
  header: "Authorization"
  prefix: "Bearer "
```

### OAuth2 (Refresh Token Flow)

Automatically manages access tokens using a refresh token:

```yaml
auth:
  type: oauth2
  client_id:
    from: vault
    path: "secret/github-oauth"
    key: "client-id"
  client_secret:
    from: vault
    path: "secret/github-oauth"
    key: "client-secret"
  refresh_token:
    from: vault
    path: "secret/github-oauth"
    key: "refresh-token"
  token_url: "https://github.com/login/oauth/access_token"
  scopes: "repo read:org"
  header: "Authorization"
  prefix: "Bearer "
```

Airlock refreshes the access token automatically before it expires.

## Response Security

### Automatic Credential Redaction

Airlock automatically redacts any injected credentials from upstream responses — both headers and body. No configuration needed.

If an upstream API echoes the injected `Authorization` header value in a response body or header, the agent sees `[REDACTED]` instead of the real credential. This works with streaming/SSE responses and handles tokens that span chunk boundaries.

### Response Header Stripping

You can optionally remove entire response headers per route. Useful for stripping upstream metadata the agent doesn't need:

```yaml
strip_response_headers:
  - Server
  - X-Powered-By
```

## Rate Limiting

Per-route token bucket rate limiting:

```yaml
rate_limit:
  rps: 10    # requests per second (sustained rate)
  burst: 20  # max burst above sustained rate
```

Requests exceeding the limit receive `429 Too Many Requests`.

## Request Timeouts

Per-route timeouts prevent stalled upstreams from blocking the agent indefinitely:

```yaml
timeout: "120s"       # Hard cap on total request duration (default: 300s)
idle_timeout: "30s"   # Kill if no bytes received for this long (default: 60s)
```

- **`timeout`** — total wall-clock time for the entire request/response cycle. When exceeded, the agent receives `504 Gateway Timeout`.
- **`idle_timeout`** — time without any bytes arriving from the upstream. Catches "connection alive but upstream stopped sending" without killing healthy long-running streams that are actively producing tokens. Works with SSE/streaming.

Both default to sane values (300s / 60s). Set to `"0"` to disable.

## Observability

### Structured Logging

Every request is logged as JSON with correlation tracking:

```json
{
  "timestamp": "2026-02-15T12:00:00.000Z",
  "level": "info",
  "message": "proxied request",
  "service": "my-agent",
  "agent_id": "research-agent-01",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "method": "POST",
  "route": "/openai",
  "target_path": "/v1/chat/completions",
  "upstream_status": 200,
  "duration_ms": 1234
}
```

### OpenTelemetry

Export traces and metrics to any OTEL-compatible backend (SigNoz, Jaeger, Datadog, etc.):

```yaml
telemetry:
  endpoint: "otel-collector:4317"
  service_name: "airlock"
  insecure: true   # set false for TLS
```

**Metrics exported:**

| Metric | Type | Description |
|---|---|---|
| `gateway.requests` | Counter | Total requests by route and status |
| `gateway.request.duration` | Histogram | Request latency in ms |
| `gateway.rate_limit.rejected` | Counter | Rate limit rejections by route |
| `gateway.auth.refreshes` | Counter | Auth token refresh events |
| `gateway.mcp.tool_denied` | Counter | MCP tool call denials by route and tool |

### Correlation IDs

Every request gets an `X-Correlation-Id` header (generated or adopted from the incoming request). This ID is:

- Logged with every request
- Forwarded to the upstream API
- Returned in the response

Use it to trace a request across your agent, Airlock, and the upstream API.

### Agent ID

If `agent_id` is set in the config, it's:

- Included in every log line
- Sent upstream as `X-Agent-Id`

Useful when running multiple agents through the same gateway or when upstream APIs need to identify which agent is making requests.

## Hot Reload

Send `SIGHUP` to reload the config without restarting:

```bash
kill -HUP $(pidof airlock)

# Or in Docker
docker kill --signal=HUP <container>
```

- Routes are swapped atomically — in-flight requests complete on the old config
- If the new config is invalid, the old config stays active and an error is logged
- Secret providers are **not** re-initialized on reload (only routes and access rules)
