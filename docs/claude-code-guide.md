# Running Claude Code Through Airlock

This guide covers running [Claude Code](https://docs.anthropic.com/en/docs/claude-code) through Airlock so the agent never has direct access to your Anthropic API key or GitHub PAT.

## Overview

Claude Code needs two things to work:

1. **Anthropic API access** (required) — for inference calls
2. **GitHub access** (optional) — for git clone, fetch, and push

Airlock handles both as separate routes. The agent container has zero real credentials.

## Airlock Configuration

### Anthropic Route (Required)

```yaml
listen: ":8080"
service: "claude-code"

providers:
  env: {}

routes:
  - path_prefix: "/anthropic"
    upstream: "https://api.anthropic.com"
    strip_prefix: "/anthropic"
    strip_agent_auth: true
    extra_headers:
      anthropic-beta: "oauth-2025-04-20"
      anthropic-version: "2023-06-01"
    auth:
      type: static
      token:
        from: env
        key: "ANTHROPIC_SETUP_TOKEN"
      header: "Authorization"
      prefix: "Bearer "
    timeout: "300s"
    idle_timeout: "120s"
    rate_limit:
      rps: 5
      burst: 10
    access_rules:
      - action: ALLOW
        method: POST
        path: /v1/messages
      - action: ALLOW
        method: POST
        path: /v1/messages/count_tokens
```

Key points:

- `strip_agent_auth: true` removes the fake token Claude Code sends before Airlock injects the real one.
- `extra_headers` are required — the setup token needs the `anthropic-beta: oauth-2025-04-20` header and an `anthropic-version` header.

### GitHub Route (Optional)

Add this route if you want Claude Code to clone, fetch, or push to GitHub repos:

```yaml
  - path_prefix: "/github-git"
    upstream: "https://github.com"
    strip_prefix: "/github-git"
    strip_agent_auth: true
    auth:
      type: static
      token:
        from: env
        key: "GITHUB_PAT"
      header: "Authorization"
      prefix: "Bearer "
    timeout: "120s"
    idle_timeout: "30s"
    rate_limit:
      rps: 10
      burst: 20
    access_rules:
      - action: ALLOW
        method: GET
        path: "/*/*/info/refs"
      - action: ALLOW
        method: POST
        path: "/*/*/git-upload-pack"
      - action: ALLOW
        method: POST
        path: "/*/*/git-receive-pack"
```

The access rules allow only the three Git smart HTTP endpoints. The `*/*` pattern matches `{owner}/{repo}`. The PAT should be scoped to `repo` for private repos or `public_repo` for public-only access.

## Agent Container Setup

### Environment Variables

```bash
ANTHROPIC_BASE_URL=http://<gateway-host>:8080/anthropic
CLAUDE_CONFIG_DIR=/workspace/.claude-home
DISABLE_AUTOUPDATER=1
```

- `ANTHROPIC_BASE_URL` points Claude Code at the Airlock gateway instead of the real API.
- `CLAUDE_CONFIG_DIR` sets where Claude Code looks for config and credentials.
- `DISABLE_AUTOUPDATER` prevents Claude Code from trying to update itself (which would fail in an isolated network).

### Fake Credential File (Required)

Claude Code refuses to make API calls without a credential file on disk. Your agent container entrypoint must create one before launching Claude Code:

```bash
mkdir -p "$CLAUDE_CONFIG_DIR"
cat > "$CLAUDE_CONFIG_DIR/.credentials.json" << 'EOF'
{
  "claudeAiOauth": {
    "accessToken": "sk-ant-fake-placeholder",
    "expiresAt": 1893456000000,
    "scopes": ["user:inference"],
    "subscriptionType": "max"
  }
}
EOF
```

This token is never used — `strip_agent_auth` removes it and Airlock injects the real one. But without this file, Claude Code won't start.

### Git URL Rewriting (Required If Using GitHub Route)

If you added the GitHub route, configure git to redirect GitHub HTTPS traffic through the gateway:

```bash
git config --global url."http://<gateway-host>:8080/github-git/".insteadOf "https://github.com/"
```

After this, `git clone https://github.com/org/repo.git` transparently routes through Airlock. The agent doesn't need to know about the proxy.

## Secrets

You need two secrets (environment variables, k8s Secrets, Vault, etc.):

| Secret | Injected into | Purpose |
|--------|---------------|---------|
| Anthropic setup token | Gateway pod | API authentication |
| GitHub PAT (optional) | Gateway pod | Git operations |

The agent container has **zero secrets** — it only knows the gateway URL and has a fake credential file.

## Network Isolation

For the security model to hold, the agent must not be able to bypass Airlock:

- **Docker Compose:** Use an `internal: true` network for the agent. See [examples/docker-compose.yaml](../examples/docker-compose.yaml).
- **Kubernetes:** Apply a NetworkPolicy so agent pods can only reach DNS and the gateway on port 8080. See [deployment docs](deployment.md#agent-networkpolicy) for a ready-to-use policy.
- **DNS hardening (optional):** Set `dnsPolicy: None` with an external nameserver (e.g., `1.0.0.1`) so the agent can't discover cluster services. Add a `hostAlias` mapping the gateway hostname to its ClusterIP.
