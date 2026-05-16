# Security

This document covers Airlock's security model, threat model, path normalization, fuzz testing, and production hardening.

## Security Model and Threat Model

### What Airlock protects against

- **Direct credential exposure to the agent.** In the documented deployment model, the agent is not given real upstream API credentials directly. Airlock injects credentials at the network boundary.
- **Unauthorized API operations.** Firewall-style access rules restrict which HTTP methods and paths the agent can call. MCP tool filtering restricts which JSON-RPC tools the agent can invoke.
- **Credential leakage in responses.** Airlock redacts injected credentials from proxied response headers and bodies, including SSE streams.
- **Uncontrolled blast radius.** Per-route rate limiting and timeouts prevent a single agent from exhausting upstream API quotas or hanging indefinitely.

### Assumptions

- **Network isolation is enforced.** Airlock assumes the agent cannot bypass it to reach external APIs directly. This requires Docker `internal: true` networks, Kubernetes NetworkPolicy, or equivalent network controls. Without isolation, the agent can simply call APIs directly.
- **Upstream credentials are appropriately scoped.** Airlock controls which endpoints the agent can reach, but it cannot limit what the upstream API does with a valid request. Use the narrowest API scopes and permissions possible.
- **One Airlock per agent.** The sidecar model is the default security boundary. If multiple agents share one Airlock instance, Airlock cannot distinguish between them for authorization purposes unless they are separated at deployment time.
- **The host and container runtime are trusted.** Airlock does not defend against a compromised container runtime, kernel exploits, or host-level access.
- **Configuration correctness matters.** Overly broad `access_rules`, permissive `mcp_rules`, disabled strict mode, or weak upstream credential scopes can undermine the protection Airlock provides.

### Out of scope

- **Agent sandboxing.** Airlock does not restrict what the agent does locally (file access, process execution, etc.) — only what it can reach over HTTP.
- **Semantic intent verification.** MCP tool filtering matches tool names, not what the tool actually does. `get_events` with a malicious parameter is still allowed if the tool name is on the allowlist.
- **Content inspection / DLP.** Airlock redacts injected credentials in responses but does not scan for arbitrary sensitive data.
- **Upstream API vulnerabilities.** Airlock forwards allowed requests as-is. It does not validate request payloads, detect prompt injection, or act as a WAF.
- **Malicious or compromised upstream services.** If an allowed upstream returns harmful, misleading, or adversarial content, Airlock forwards it unless blocked by other controls.
- **Replacing upstream RBAC.** Airlock is an additional layer, not a replacement for the upstream API's own authorization.

## Production Checklist

- [ ] Every route has `access_rules` — strict mode (default) enforces this at startup
- [ ] Bind to loopback in same-pod mode: `listen: "127.0.0.1:8080"`
- [ ] Network isolation: Docker `internal: true` network or K8s NetworkPolicy
- [ ] Enable telemetry: set `telemetry.endpoint` for OTel traces and metrics
- [ ] Set timeouts: `timeout` and `idle_timeout` on every route
- [ ] Set rate limits: `rate_limit` on routes exposed to agents
- [ ] Strip agent auth: `strip_agent_auth: true` if agents send dummy auth headers
- [ ] Review MCP rules: use `allowed_tools` for strict control, check logs for `MCP tools discovered`
- [ ] One Airlock per agent — the sidecar model is the default security boundary

## Path Normalization

Airlock matches against `r.URL.Path` (the percent-decoded request path) after `strip_prefix` is applied. Matching is **segment-based** — paths are split on `/` and compared segment by segment.

**Normalization rules:**

- **Double slashes** (`//`) are normalized — interior empty segments are filtered, so `/v1//chat/completions` matches the same as `/v1/chat/completions`
- **Encoded path separators** — requests whose escaped path contains `%2f` or `%5c` are rejected with `400 Bad Request`, preventing "policy sees path A, upstream sees path B" mismatches (checked via `RawPath` with `EscapedPath()` fallback)
- **Path traversal** — Airlock does not interpret `.`/`..` specially; segments are compared literally. Some upstream proxies or Go's `net/http` may normalize traversal before it reaches Airlock; Airlock's policy does not rely on that
- **Null bytes** (`%00`) are decoded but treated as literal characters — no truncation
- **Case-sensitive** — `/V1/CHAT/COMPLETIONS` does not match `/v1/chat/completions`
- **`*` matches exactly one non-empty segment** — it never matches empty strings
- **Safety caps** — patterns exceeding 64 segments or paths exceeding 256 segments are denied automatically. These limits are not configurable

**Pattern matching** uses an iterative dynamic programming algorithm with O(P×S) worst-case time complexity, where P is the number of pattern segments and S is the number of path segments. There is no recursive backtracking — pathological patterns like `**/*/**/*/**/end` complete in bounded time.

The fuzz seed corpus includes all of the above attack vectors plus extreme-length paths (1000+ segments).

## Regex Path Matching (`path_regex`)

Each access rule must specify exactly one of `path` (glob) or `path_regex` (RE2 regex). Both cannot be set on the same rule — startup fails with a clear validation error if they are.

**When to use which:**

- **Default to `path`.** Glob is segment-based, easier to read, and protected by the bounded DP matcher described above. Use it for the common case (whole-segment matches, prefixes, simple wildcards).
- **Use `path_regex` only when you need within-segment constraints** that glob cannot express — for example, restricting writes to issue keys matching `AI-\d+` while leaving reads unrestricted.

**Example — restrict Jira writes to AI-prefixed tickets:**

```yaml
access_rules:
  - { action: ALLOW, method: GET,  path: /rest/api/3/search/jql }
  - { action: ALLOW, method: PUT,  path_regex: '/rest/api/3/issue/AI-\d+' }
  - { action: ALLOW, method: GET,  path_regex: '/rest/api/3/issue/AI-\d+' }
  - { action: ALLOW, method: POST, path_regex: '/rest/api/3/issue/AI-\d+/comment' }
  - { action: DENY,  method: ALL,  path: /** }
```

### Semantics

- **Implicit full-match anchoring.** Every `path_regex` is wrapped as `\A(?:<your_pattern>)\z` before compilation. Your pattern must match the entire path, not a prefix or substring. Adding your own `^` or `$` is harmless but redundant. The wrapping is non-capturing, which means alternations like `path_regex: 'foo|bar'` behave as `(?:foo|bar)` against the full path — neither branch matches `/prefix/foo` or `/foo/extra`.
- **Same normalized path as glob.** The regex runs against the same normalized path glob sees: leading `/`, no trailing `/` (root stays `/`), interior `//` collapsed. A request to `/rest/api/3//issue/AI-1` matches `path_regex: '/rest/api/3/issue/AI-\d+'` for the same reason it would match the equivalent glob.
- **First-match ordering is preserved.** Regex and glob rules can be mixed freely in the same `access_rules` list. Rules are still evaluated top-to-bottom, first match wins, with implicit deny at the end if rules are defined.
- **Method semantics are unchanged.** `method: ALL` matches any verb; specific methods only match that verb. Regex applies to the path only — there is no method regex.

### RE2 dialect (no lookahead, no backreferences)

`path_regex` uses Go's standard library `regexp` package, which implements [RE2 syntax](https://pkg.go.dev/regexp/syntax). RE2 guarantees linear-time matching — there is no catastrophic backtracking, regardless of how the pattern is constructed. This is by design: features that require backtracking are not supported.

Notably **not supported**:

- Lookahead / lookbehind (`(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`)
- Backreferences (`\1`, `\2`, etc.)
- Atomic groups, possessive quantifiers

If your matching need requires any of these, restructure as multiple rules or do the check upstream of Airlock.

### Compiled once at config load

Every `path_regex` is compiled when the gateway boots (or when config is reloaded). Invalid patterns fail loudly with the route prefix and rule index. Compilation is not done per request — there is no per-request regex compilation cost.

### Length cap

`path_regex` is capped at **512 characters** at config load. RE2 already prevents runtime DoS, but a multi-kilobyte regex in a YAML file is almost certainly a config mistake or an abuse of the loader. The cap is not configurable.

### Performance

RE2 matching is linear in the path length. A typical short URL path matches in under a microsecond — well within the noise floor of any real proxy hop. For the vast majority of deployments, regex matching cost is not measurable. The reason to prefer glob is readability and the segment-based safety guarantees, not throughput.

### Capture groups and rewrites

Regex is for **matching only**. Capture groups are ignored — they do not feed into URL rewriting, header injection, or any other downstream behavior. Path rewriting belongs in `strip_prefix` and `upstream` joining, not in `path_regex`.

## Fuzz Testing

The access rule engine is covered by Go fuzz tests that throw millions of random inputs at the path matcher and access policy evaluator, looking for bypasses, panics, or unexpected matches:

| Fuzz Target | What it tests |
|---|---|
| `FuzzMatchPattern` | Exact path match — path traversal, URL encoding, null bytes, case tricks |
| `FuzzMatchPatternWildcard` | Single-segment wildcard (`*`) bypass attempts |
| `FuzzMatchPatternDoublestar` | Multi-segment wildcard (`**`) bypass attempts |
| `FuzzAccessPolicyBypass` | Full ALLOW-only policy — only POST `/v1/chat/completions` should pass |
| `FuzzAccessPolicyDenyBypass` | DENY rule bypass — DELETE must always be denied |
| `FuzzMatchPatternNoPanic` | Arbitrary pattern + path combinations for panics |

Run them yourself:

```bash
# Quick smoke test (10s per target)
go test -fuzz=FuzzAccessPolicyBypass -fuzztime=10s ./internal/proxy/

# Longer run for higher confidence
go test -fuzz=FuzzAccessPolicyBypass -fuzztime=5m ./internal/proxy/
```

All six targets have been run for millions of executions each with zero bypasses or panics found.

## HTTP Status Codes

| Code | Meaning |
|---|---|
| `400` | Encoded path separator (`%2f`/`%5c`) in request |
| `403` | Access rule or MCP tool policy denied the request |
| `404` | No route matched the request path |
| `429` | Rate limit exceeded |
| `502` | Upstream returned an error or is unreachable |
| `504` | Request or idle timeout exceeded |
