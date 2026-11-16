# Deployment

Airlock is designed as a **per-agent sidecar**. Run one instance per agent — this is the default security boundary. If multiple agents share one Airlock instance, they all get the same credentials and access rules.

"Sidecar" here means one gateway per agent, not necessarily one container per pod. On Kubernetes, prefer a separate gateway pod: a sidecar *container* in the agent's own pod shares the agent's network namespace, so a NetworkPolicy cannot isolate the agent's egress from the gateway's. See [Same-pod (sidecar container) deployment](#same-pod-sidecar-container-deployment).

## Docker

```bash
docker run -d \
  --name airlock \
  -p 8080:8080 \
  -e OPENAI_API_KEY=sk-... \
  -v ./config.yaml:/config.yaml:ro \
  ghcr.io/realugbun/airlock:0.1.0
```

The image is built from `scratch` — no shell, no OS, minimal attack surface (~10MB).

**Health check:** `-healthcheck` flag or `GET /healthz`

```yaml
healthcheck:
  test: ["CMD", "/airlock", "-healthcheck"]
  interval: 5s
  timeout: 2s
  retries: 3
```

## Docker Compose (Network Isolation)

The recommended deployment uses two Docker networks to fully isolate the agent:

```yaml
services:
  agent:
    image: your-agent-image
    networks:
      - isolated           # no internet
    environment:
      - API_BASE_URL=http://gateway:8080
    depends_on:
      gateway:
        condition: service_healthy

  gateway:
    image: ghcr.io/realugbun/airlock:0.1.0
    networks:
      - isolated           # agent can reach it
      - external           # it can reach the internet
    volumes:
      - ./config.yaml:/config.yaml:ro
    healthcheck:
      test: ["CMD", "/airlock", "-healthcheck"]
      interval: 5s
      timeout: 2s
      retries: 3

networks:
  isolated:
    internal: true         # no outbound internet
  external:
    driver: bridge
```

The agent sits on the `isolated` network with no internet access. Airlock bridges both networks — the agent can reach Airlock, and Airlock can reach external APIs. The agent has no path to the internet except through Airlock.

## Kubernetes (Helm)

The Helm chart deploys the Airlock gateway only — you manage your agent deployment separately.

```bash
helm install airlock deploy/helm/airlock \
  --set gateway.config.service="my-agent"
```

The chart includes:

- Gateway Deployment with health probes on `/healthz`
- ClusterIP Service on port 8080
- ConfigMap for gateway config (auto-restarts pods on change)
- NetworkPolicy restricting gateway egress to DNS + external HTTPS
- Optional Vault Agent sidecar for token injection

See `deploy/helm/airlock/values.yaml` for all options.

### Agent NetworkPolicy

Apply a NetworkPolicy to your agent pods so they can only reach the Airlock gateway.
This requires the agent and the gateway to be in **separate pods** — see
[Same-pod (sidecar container) deployment](#same-pod-sidecar-container-deployment)
below for why a NetworkPolicy cannot isolate them otherwise:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-isolation
spec:
  podSelector:
    matchLabels:
      app: my-agent           # match your agent pods
  policyTypes:
    - Egress
    - Ingress
  ingress: []
  egress:
    - to: []
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    - to:
        - podSelector:
            matchLabels:
              app: airlock-gateway
      ports:
        - port: 8080
          protocol: TCP
```

### Same-pod (sidecar container) deployment

Airlock can run as a second container inside the agent's own pod, bound to
`127.0.0.1:8080` so only that agent can reach it. **A NetworkPolicy cannot
isolate the agent's egress in this arrangement.** Containers in a pod share one
network namespace — the same IP, loopback interface and routing table — and a
NetworkPolicy selects pods, not containers. Its `egress` rules therefore apply
to the whole pod: every upstream the policy must allow for Airlock to reach is
equally reachable from the agent container, directly, bypassing access rules,
MCP filtering and rate limits. Binding the gateway to loopback does not change
this; it restricts who can reach Airlock, not where the agent can go.

For egress isolation, use one of:

- **Separate pods** — the agent in its own pod with the
  [Agent NetworkPolicy](#agent-networkpolicy) above, and the gateway in the
  Deployment the Helm chart creates. Different pods have different IPs, so the
  policy can distinguish them. This is the documented pattern.
- **An egress control that works below pod granularity** — an authenticating
  egress proxy whose credential the agent does not have, a service mesh with
  per-workload identity, or host/cloud firewall rules keyed on something other
  than the pod IP.

Same-pod mode is a reasonable choice when Airlock is there for credential
injection, auditing and rate limiting and the agent container is trusted not to
make its own outbound calls. It is not a containment boundary. See
[Security](security.md#same-pod-deployment-and-egress-isolation).

### DNS Hardening

By default, agent pods can resolve cluster DNS names. The NetworkPolicy blocks TCP connections so this isn't directly exploitable, but it leaks service topology. To eliminate DNS-based discovery entirely, set `dnsPolicy: None` on the agent pod and use `hostAliases` to map the gateway hostname to its ClusterIP:

```yaml
spec:
  dnsPolicy: None
  dnsConfig:
    nameservers:
      - "1.0.0.1"
  hostAliases:
    - ip: "10.43.200.50"    # kubectl get svc airlock-gateway -o jsonpath='{.spec.clusterIP}'
      hostnames:
        - airlock-gateway
```

The agent resolves only the gateway via `/etc/hosts` — no cluster DNS access at all.

## Agent Auth Proxy

When proxying for AI agents (like Claude Code), the agent typically needs *some* credential to initialize its SDK, even though Airlock will inject the real one. Two features close this gap:

**`strip_agent_auth`** strips the agent's incoming auth headers (`Authorization`, `x-api-key`) before Airlock injects the real credentials:

```yaml
strip_agent_auth: true
```

**`extra_headers`** injects additional static headers the upstream API requires (so the agent doesn't need to know about them). Config always wins — if the agent sends a header that's also in `extra_headers`, Airlock overwrites it with the configured value:

```yaml
extra_headers:
  anthropic-beta: "oauth-2025-04-20"
  anthropic-version: "2023-06-01"
```

**Full example** — proxying Claude Code through Airlock with a setup token:

```yaml
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
        key: ANTHROPIC_SETUP_TOKEN
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

The agent gets a dummy token and `ANTHROPIC_BASE_URL=http://airlock:8080/anthropic`. Airlock strips the dummy, injects the real credential and required headers, and forwards to the API. Even if the agent is compromised, it only has a worthless token and the NetworkPolicy prevents direct API access.
