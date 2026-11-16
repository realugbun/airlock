# Security

This document covers Airlock's security model, threat model, path normalization, fuzz testing, and production hardening.

## Security Model and Threat Model

### What Airlock protects against

- **Direct credential exposure to the agent.** In the documented deployment model, the agent is not given real upstream API credentials directly. Airlock injects credentials at the network boundary.
- **Unauthorized API operations.** Firewall-style access rules restrict which HTTP methods and paths the agent can call. MCP tool filtering restricts which JSON-RPC tools the agent can invoke.
- **Credential leakage in responses.** Airlock redacts injected credentials from proxied response headers, trailers and bodies, including SSE streams, independently of how the upstream chunks the response. On routes that inject a credential, upstream 1xx informational responses (such as `103 Early Hints`) are not forwarded. A credential that cannot be redacted safely is refused rather than forwarded — see [Credential Characters and Redaction](#credential-characters-and-redaction).
- **Uncontrolled blast radius.** Per-route rate limiting and timeouts prevent a single agent from exhausting upstream API quotas or hanging indefinitely.

### Assumptions

- **Network isolation is enforced.** Airlock assumes the agent cannot bypass it to reach external APIs directly. This requires Docker `internal: true` networks, Kubernetes NetworkPolicy, or equivalent network controls. Without isolation, the agent can simply call APIs directly. **A NetworkPolicy cannot provide this isolation when the agent and Airlock are containers in the same pod** — see [Same-Pod Deployment and Egress Isolation](#same-pod-deployment-and-egress-isolation).
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
- [ ] Bind to loopback in same-pod mode: `listen: "127.0.0.1:8080"` — and note that a NetworkPolicy cannot isolate the agent's egress in that mode, see [Same-Pod Deployment and Egress Isolation](#same-pod-deployment-and-egress-isolation)
- [ ] Network isolation: Docker `internal: true` network, or a K8s NetworkPolicy on a **separate** agent pod
- [ ] Enable telemetry: set `telemetry.endpoint` for OTel traces and metrics
- [ ] Set timeouts: `timeout` and `idle_timeout` on every route
- [ ] Set rate limits: `rate_limit` on routes exposed to agents
- [ ] Strip agent auth: `strip_agent_auth: true` if agents send dummy auth headers
- [ ] Review MCP rules: use `allowed_tools` for strict control, check logs for `MCP tools discovered`
- [ ] One Airlock per agent — the sidecar model is the default security boundary

## Injected Headers

Before injecting credentials and `extra_headers`, Airlock removes the agent's `Connection` header, every header it names, and the standard hop-by-hop headers. Otherwise `Connection: Authorization` would make the proxy drop the injected credential. `auth.header` and `extra_headers` may not be hop-by-hop names.

## Same-Pod Deployment and Egress Isolation

Running Airlock as a second container in the agent's pod and binding it to
`127.0.0.1:8080` is a convenient way to make the gateway reachable only by that
agent. It controls *ingress* to Airlock. **It does not control the agent's
egress, and a Kubernetes NetworkPolicy cannot make it do so.**

Every container in a pod shares one network namespace. They share the pod's IP,
its loopback interface and its routing table, and a NetworkPolicy selects
*pods*, not containers. So a NetworkPolicy's `egress` rules apply to the pod as
a whole: whatever the policy must permit for Airlock to reach its upstreams, the
agent container can use directly. The two containers are indistinguishable to
the policy engine, and to anything else that makes decisions from the source IP.

Concretely, in same-pod mode:

- An egress rule allowing `443/TCP` to the internet so Airlock can call the
  upstream API lets the agent call that API itself, with its own credential if
  it has one, bypassing access rules, MCP filtering and rate limits.
- Binding Airlock to loopback does not help. It stops *other* pods reaching the
  gateway; the agent was never going through the network to reach it.
- Dropping the agent's `NET_RAW`, running it as non-root, or setting
  `dnsPolicy: None` do not change this. They raise the cost of discovering a
  destination, not the ability to reach a permitted one.

Use one of these instead:

- **A separate gateway pod with a NetworkPolicy on the agent pod.** This is the
  arrangement [deploy/helm](deployment.md#kubernetes-helm) ships and the
  [Agent NetworkPolicy](deployment.md#agent-networkpolicy) example configures:
  the agent pod's only permitted egress is DNS plus the gateway Service, and the
  gateway pod is the only thing with egress to the internet. Because they are
  different pods they have different IPs, so the policy can tell them apart.
- **An egress control that distinguishes containers rather than pods** — an
  authenticating egress proxy the agent has no credential for, a service mesh
  sidecar with per-workload identity, or host or cloud firewall rules keyed on
  something finer-grained than the pod IP.

Same-pod mode is still reasonable when the agent container is trusted not to
make its own outbound calls and Airlock is there for credential injection,
auditing and rate limiting rather than as a containment boundary. It is not a
substitute for network isolation.

## Credential Characters and Redaction

Airlock redacts an injected credential from response headers, trailers and
bodies by replacing it with the literal `[REDACTED]`. Because the placeholder
opens with `[` and closes with `]`, a credential that itself contains `[` or
`]` can be re-formed by a replacement sitting next to the bytes around it. Take
a credential of `]Z!`: an upstream body of `]Z!Z!` redacts to `[REDACTED]Z!`,
and the `]` that closes the placeholder plus the `Z!` left behind spell the
credential again. Redaction removed the credential and then wrote it back.

**Airlock therefore refuses a request on a route whose resolved credential (or
the injected header value built from `auth.prefix` plus the credential)
contains `[` or `]`.** The request is answered `500` and the upstream is never
contacted, so no response exists to leak. The log names the route and the
reason; it never contains the credential value. Rotate the credential to a
value without brackets, or drop the brackets from `auth.prefix`.

A credential free of `[` and `]` cannot be re-formed this way: every span of a
redacted response that overlaps a replacement without being contained in it
includes the placeholder's `[` or `]`, so such a credential can only "appear"
inside the constant placeholder text.

That leaves one edge case, which is refused on the same path: **a credential
that is itself a substring of the literal text `[REDACTED]`** — `RED`,
`ACTED`, `DAC`, the whole placeholder, or the empty string. Such a credential
appears verbatim in any redacted response that contains a replacement at all.
The appearance carries no information about the credential, because the bytes
come from a constant rather than from the upstream, but the guarantee "no
injected credential appears in the response" would be false as stated. Airlock
refuses the request instead of shipping the guarantee with a caveat: the
request is answered `500`, the upstream is never contacted, and the log names
the route and the reason but never the value. Bracket-free credentials of four
characters or more are unaffected unless they are a run of `REDACTED`.

Together the two conditions are exactly the precondition of the redaction
proofs, and that they are is itself proved — see
[Machine-Checked Proofs](#machine-checked-proofs).

Redaction is also independent of how the upstream chunks its response. Both the
plain and the SSE redactor hold back only the tail of the stream that could
still begin a credential, and replace longest match first, so the bytes the
agent receives are the same whatever the chunk boundaries are. An agent cannot
reveal a fragment of a credential by influencing the response framing.

Both of these properties — that no credential Airlock accepts survives
redaction, and that the output does not depend on the chunk boundaries — are
proved mechanically, as is the fact that `redactionSafe` enforces the whole
credential constraint the first proof needs. See
[Machine-Checked Proofs](#machine-checked-proofs).

## MCP Request Inspection

On a route whose `mcp_rules` lists `allowed_tools` or `denied_tools`, a POST body that Airlock cannot inspect exactly as the upstream will read it is rejected, never forwarded:

- `413` if the body exceeds 10 MiB (by `Content-Length` or after reading a chunked body)
- `415` for a `Content-Encoding` other than `identity`, or a `Content-Type` that is not `application/json` or `text/json` (compared case-insensitively; a `charset` must be UTF-8). A missing `Content-Type` is inspected as JSON
- `400` for malformed JSON, invalid UTF-8, a `tools/call` without a non-empty string `params.name`, a batch with any invalid element, or a duplicate or case-variant `method`, `params` or `name` key (`"Name"`, `"METHOD"`). JSON parsers disagree on which duplicate wins and whether keys are case-sensitive, so these are ambiguous

`mcp_rules: {}` enforces nothing and keeps forwarding such requests unchanged.

## Time and Size Limits

- A route's `timeout` starts when the request is routed and covers reading and inspecting the body and resolving secrets. A body not received in time gets `408 Request Timeout`
- The listener allows 10s to read request headers, 1 MiB of headers, and closes idle keep-alive connections after 120s. There is no server-wide read or write timeout, so SSE streams are bounded only by the route's `timeout` and `idle_timeout`
- A non-streaming `tools/list` response is buffered to filter it and capped at 10 MiB; a larger response gets `502 Bad Gateway`

## Route Matching

A route's `path_prefix` matches **whole path segments**: a path matches when it equals the prefix or continues it after a `/`. A `/git` route serves `/git` and `/git/org/repo` and does not serve `/github/repos`, so a request cannot be pulled onto a route whose credential and access rules were written for a different API. A trailing slash on the prefix is normalized; a `/` prefix matches every path.

`strip_prefix` is removed on the same boundary, so the path checked against the access rules is the path the upstream receives.

Routes are matched in config order, first match wins. A config in which an earlier route's prefix equals or covers a later route's is rejected at load — at startup and on `SIGHUP` reload — with an error naming both routes, because the later route's rules, credential and upstream could never apply. A `/` catch-all is valid only as the last route. A rejected reload leaves the previously loaded routes active, and every request is served entirely by one config snapshot: the upstream it reaches and the credential it carries always come from the same config.

## Request Method

Access rules authorize a method together with a path, so Airlock forwards the request method it routed on and refuses the standard ways of asking an upstream to use a different one. A request with `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` (any header-name case) is rejected with `400 Bad Request` before routing; a framework or upstream that honours one of those headers would otherwise run a method the rules never authorized. As with an ambiguous path, the request is refused rather than cleaned up, and the header's value is never logged, only its name.

This covers the three override headers, not every convention an upstream might invent. A framework that reads a method out of the request body or the query string (`?_method=DELETE`) sees whatever the agent sent: the query string and the body are forwarded unchanged, so the access rules cannot constrain them. Do not place a route in front of an upstream that honours such a parameter unless the rules allow that method anyway.

## Query Strings

The query string is forwarded to the upstream unchanged, including its percent-encoding. It takes no part in route matching and no part in access rules: rules match on the path only, so `path: /v1/users` matches `/v1/users?role=admin` as well. Access rules cannot constrain query parameters.

## Path Normalization

Airlock matches against `r.URL.Path` (the percent-decoded request path) after `strip_prefix` is applied. Matching is **segment-based** — paths are split on `/` and compared segment by segment.

**Normalization rules:**

- **Double slashes** (`//`) are normalized — interior empty segments are filtered, so `/v1//chat/completions` matches the same as `/v1/chat/completions`
- **Encoded path separators** — requests whose escaped path contains `%2f` or `%5c` are rejected with `400 Bad Request`, preventing "policy sees path A, upstream sees path B" mismatches (checked via `RawPath` with `EscapedPath()` fallback)
- **Path traversal** — requests whose decoded path contains a `.` or `..` segment (including `%2e` forms), or a literal backslash, are rejected with `400 Bad Request`. Airlock never cleans the path, since many upstreams would resolve `/allowed/../admin` to `/admin`. The check runs before routing, and again after `strip_prefix` as a backstop; a path that only looks like it is under a route's prefix, such as `/api../admin` for an `/api` route, matches no route at all and gets `404 Not Found`
- **Null bytes** (`%00`) are decoded but treated as literal characters — no truncation
- **Case-sensitive** — `/V1/CHAT/COMPLETIONS` does not match `/v1/chat/completions`
- **`*` matches exactly one non-empty segment** — it never matches empty strings
- **Safety caps** — patterns exceeding 64 segments or paths exceeding 256 segments are denied automatically. These limits are not configurable. The 256-segment path cap is enforced once for the whole request, before any rule is consulted: the glob matcher denies an over-cap path but a `path_regex` rule has no such cap, so without a central check a path long enough to fail a trailing `DENY /**` could be picked up by a later `ALLOW path_regex` and fail open. That the cap is consulted before any rule is [proved](#machine-checked-proofs)

**Pattern matching** uses an iterative dynamic programming algorithm with O(P×S) worst-case time complexity, where P is the number of pattern segments and S is the number of path segments. There is no recursive backtracking — pathological patterns like `**/*/**/*/**/end` complete in bounded time.

The fuzz seed corpus includes all of the above attack vectors plus extreme-length paths (1000+ segments).

## Regex Path Matching (`path_regex`)

Each access rule must specify exactly one of `path` (glob) or `path_regex` (RE2 regex). Both cannot be set on the same rule — startup fails with a clear validation error if they are.

**When to use which:**

- **Default to `path`.** Glob is segment-based, easier to read, and protected by the bounded DP matcher described above. Use it for the common case (whole-segment matches, prefixes, simple wildcards).
- **Use `path_regex` only when you need within-segment constraints** that glob cannot express — for example, restricting writes to issue keys matching `REC-\d+` while leaving reads unrestricted.

**Example: restrict writes to a single record prefix**

```yaml
access_rules:
  - { action: ALLOW, method: GET,  path: /v1/search/jql }
  - { action: ALLOW, method: PUT,  path_regex: '/v1/records/REC-\d+' }
  - { action: ALLOW, method: GET,  path_regex: '/v1/records/REC-\d+' }
  - { action: ALLOW, method: POST, path_regex: '/v1/records/REC-\d+/comment' }
  - { action: DENY,  method: ALL,  path: /** }
```

### Semantics

- **Implicit full-match anchoring.** Every `path_regex` is wrapped as `\A(?:<your_pattern>)\z` before compilation. Your pattern must match the entire path, not a prefix or substring. Adding your own `^` or `$` is harmless but redundant. The wrapping is non-capturing, which means alternations like `path_regex: 'foo|bar'` behave as `(?:foo|bar)` against the full path — neither branch matches `/prefix/foo` or `/foo/extra`.
- **Same normalized path as glob.** The regex runs against the same normalized path glob sees: leading `/`, no trailing `/` (root stays `/`), interior `//` collapsed. A request to `/v1//records/REC-1` matches `path_regex: '/v1/records/REC-\d+'` for the same reason it would match the equivalent glob.
- **First-match ordering is preserved.** Regex and glob rules can be mixed freely in the same `access_rules` list. Rules are still evaluated top-to-bottom, first match wins, with implicit deny at the end if rules are defined. First-match-wins and implicit deny are [proved for an arbitrary per-rule matcher](#machine-checked-proofs), so they cover regex and glob rules equally; RE2's own matching behaviour is not modelled.
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

The access rule engine and the response redactors are covered by Go fuzz tests that throw millions of random inputs at the path matcher, the access policy evaluator and the redaction readers, looking for bypasses, panics, or unexpected matches:

| Fuzz Target | What it tests |
|---|---|
| `FuzzMatchPattern` | Exact path match — path traversal, URL encoding, null bytes, case tricks |
| `FuzzMatchPatternWildcard` | Single-segment wildcard (`*`) bypass attempts |
| `FuzzMatchPatternDoublestar` | Multi-segment wildcard (`**`) bypass attempts |
| `FuzzAccessPolicyBypass` | Full ALLOW-only policy — only POST `/v1/chat/completions` should pass |
| `FuzzAccessPolicyDenyBypass` | DENY rule bypass — DELETE must always be denied |
| `FuzzMatchPatternNoPanic` | Arbitrary pattern + path combinations for panics |
| `FuzzRedactStreaming` | Response body redaction — a secret must never survive, and streamed output must equal one-shot output for every chunking |
| `FuzzRedactHeaderValues` | Response header redaction — same replacement result as bodies, no surviving secret |

Run them yourself:

```bash
# Quick smoke test (10s per target)
go test -fuzz=FuzzAccessPolicyBypass -fuzztime=10s ./internal/proxy/

# Longer run for higher confidence
go test -fuzz=FuzzAccessPolicyBypass -fuzztime=5m ./internal/proxy/
```

The six access rule targets have been run for millions of executions each with zero bypasses or panics found. Run the redaction targets the same way (`go test -fuzz=FuzzRedactStreaming -fuzztime=60s ./internal/proxy/`) when changing the redactors; CI runs the seed corpus of every target as part of `go test`, not a fuzzing campaign.

## Machine-Checked Proofs

The access-rule matcher and the response redactors are modelled in
[Dafny](https://dafny.org) under [`formal/`](../formal) and the models are
verified in CI by [`.github/workflows/formal.yml`](../.github/workflows/formal.yml),
which installs a pinned, SHA-256-checked Dafny 4.11.0 and runs
`dafny verify --verification-time-limit 60` over every file. Warnings are
errors, so a file that verifies with a warning still fails the job. The whole
suite is 259 proof obligations and takes about 20 seconds.

Nothing in `formal/` is axiomatised and nothing is assumed away inside a proof:
CI rejects the build if `{:axiom}` or an `assume` statement appears anywhere
under `formal/`. Everything listed under "What is assumed" below is a statement
about the gap between the models and the shipped Go, not a hole inside a proof.

| File | Models |
|---|---|
| `formal/path.dfy` | `splitPath`, `matchSegment`, the segment caps |
| `formal/glob.dfy` | `matchPattern`, `collapseDoublestar`, `matchSegments` |
| `formal/policy.dfy` | `(*AccessPolicy).Allowed` |
| `formal/redact.dfy` | `bytes.ReplaceAll`, `redactAll`, `redactionSafe` |
| `formal/stream.dfy` | `tokenReplacer`, `streamRedactor` |

### What is proved

Access rules, for an **arbitrary** per-rule matcher — the model leaves `hit`
uninterpreted, so these hold for glob and `path_regex` rules alike:

- **First match wins.** If rule *k* is the first applicable rule, the decision is exactly `rules[k].action == ALLOW`.
- **Implicit deny.** If rules are defined and none applies, the request is denied.
- **Explicit deny-all.** `access_rules: []` denies every request.
- **The 256-segment cap denies before any rule is consulted.** Proved over `len(splitPath(path))` computed by the modelled splitter, not over a free parameter, and proved to hold even against a rule list that would otherwise allow everything. This is intended behaviour, not a limitation — see [Path Normalization](#path-normalization).
- **No rules means no restrictions.** Faithful to the shipped code; see the note below.

The glob matcher:

- **`*` never matches an empty segment.** Both halves: `matchSegment("*", "")` is false, and `splitPath` never produces an empty segment, so the matcher is never offered one.
- **The shipped bottom-up DP equals a declarative glob semantics** (`**` matches zero or more segments, `*` exactly one non-empty segment) whenever the 64/256 caps allow, and denies above them.
- **Collapsing consecutive `**` does not change what matches.** `collapseDoublestar` is an optimisation against exponential branching; it is proved to accept exactly the same language.
- **The whole `matchPattern` composition** — `splitPath`, then `collapseDoublestar`, then the DP — equals the declarative semantics of the *uncollapsed* pattern under the caps.

Redaction, for every credential `redactionSafe` accepts:

- **A bracket-free secret cannot overlap the placeholder.** It contains no `[REDACTED]`, has no suffix that is a placeholder prefix, and no prefix that is a placeholder suffix — so a replacement cannot splice the secret back together across its own boundary.
- **One pass removes every occurrence of its secret and creates none.**
- **Replacing one secret cannot resurrect another.** Later passes only insert placeholders and delete their own token, neither of which can spell a bracket-free secret that was not already there.
- **No secret appears in the output of `redactAll`,** for any number of secrets in any order.
- **Streamed redaction equals one-shot redaction, for every chunking.** The chunk list is universally quantified, so this covers every way the upstream could split the body, including splitting a secret byte by byte across reads. Two different chunkings of the same body give byte-identical output.
- **No secret appears in the streamed output, for every chunking** — the previous two results composed.
- **The credential constraint those results need is enforced by `redactionSafe`, not assumed.** The theorems above have one hypothesis, `RedactableTok`: the secret is nonempty, contains no `[` or `]`, and is not a substring of `[REDACTED]`. The model of the shipped `redactionSafe` is proved to imply it for every secret it accepts (`RedactionSafeImpliesRedactable` in `formal/redact.dfy`), so the whole-buffer and streaming guarantees hold with `redactionSafe` as their only hypothesis (`NoSecretSurvivesTheShippedCheck`, `NoStreamedSecretSurvivesTheShippedCheck`). The converse is proved too, so the check refuses no credential the theorems could have covered.

### No rules means no restrictions

`Allowed` returns true when a route has no `access_rules`, and the model states
that explicitly rather than hiding it. It is not a fail-open path: **strict mode
is the default and rejects a route with no `access_rules` at config load**, so
an unconfigured route fails to start rather than serving traffic unrestricted.
Reaching this branch requires an operator to have set `strict: false` *and*
omitted `access_rules`.

### What is assumed

The proofs are about the models. These are the gaps between the models and the
running binary:

- **The models are hand-written transliterations of the Go, not generated from it.** No `dafny translate` output ships. The link is `internal/proxy/formal_diff_test.go`, which compares the shipped `splitPath`, `collapseDoublestar`, `matchSegment`, `matchPattern`, `AccessPolicy.Allowed`, `redactAll`, `tokenPrefixSuffixLen` and `streamRedactor` against hand-written Go reference implementations that mirror each Dafny definition line for line, over edge cases plus seeded pseudo-random input. It runs under `go test -race ./...`. A change to either side that breaks the correspondence fails that test, but the correspondence is checked by testing, not proved.
- **`splitPath`'s use of the standard library is discharged by test, not proof.** The model splits on every `/` and drops empty pieces; the shipped code calls `strings.Trim` then `strings.Split` then filters. These are equal because `Trim` only removes leading and trailing `/`, each of which contributes an empty piece that the filter drops — an argument about the standard library, checked by `TestSplitPathMatchesDafnySplitPath`.
- **`redactionSafe`'s use of the standard library is discharged by test, not proof.** The model of the check is `!ContainsAnyMeta(s) && !Occurs(PH, s)`; the shipped code calls `strings.ContainsAny(s, "[]")` then `strings.Contains("[REDACTED]", s)`. That these agree — including that `strings.Contains(x, "")` is true, which is what rejects the empty credential — is an argument about the standard library, checked by `TestRedactionSafeMatchesDafnyRedactionSafe` and `TestRedactionSafeDischargesRedactableTok`. The credential constraint itself is no longer assumed: see the last bullet under [What is proved](#what-is-proved).
- **`path_regex` semantics are not modelled.** The per-rule matcher is uninterpreted, which is why first-match-wins, implicit deny and the segment cap cover regex rules too. But RE2's own behaviour, the `\A(?:...)\z` anchoring wrapper, and `normalizePath` are outside the models. The anchoring argument is in [Regex Path Matching](#regex-path-matching-path_regex) and is covered by tests and fuzzing, not proofs.
- **The reader plumbing is not modelled.** The proofs cover the redaction algebra: the cascade receives some partition of its input followed by exactly one flush. That both shipped readers do deliver such a partition — `redactingReader` pushing `buf[:n]` per `Read` and flushing once when the upstream ends, `sseEventReader` calling the transform per event batch and the final hook once in `drain()` — is read off the code, not proved. Buffering, error ordering and `Close` behaviour are covered by tests only.
- **SSE line-ending normalization happens before redaction.** `\r\n` and lone `\r` become `\n` on the way into the cascade, so the streaming guarantee is about the normalized byte stream, which is what the agent receives.
- **`prepareRedactTokens`' ordering and deduplication are not modelled.** Neither theorem needs them: both hold for any token order, and the streaming and one-shot sides are always handed the same list. Longest-first ordering is a quality-of-redaction choice, not a safety property here.
- **Alphabet.** Dafny `string` is a sequence of characters; the redactors operate on `[]byte`. The redaction proofs never inspect an element except to compare it with `[`, with `]`, or with a character of the constant `[REDACTED]`, so they hold over sequences of any element type with those values distinguished, and every one of them is single-byte ASCII. That is also why the byte-level `strings.ContainsAny(s, "[]")` and `strings.Contains("[REDACTED]", s)` agree with the character-level model: the haystacks are pure ASCII, which is self-synchronizing in UTF-8, so no multi-byte character can match across a boundary. The reference implementations in `formal_diff_test.go` are byte-based, which is the side that ties the model to the shipped code. The same applies to `/` in the path model.
- **Performance is not proved.** The DP is proved correct and terminating, not O(P×S).
- **The toolchain is trusted.** Dafny 4.11.0 and its bundled Z3 are assumed sound; the release archive is pinned by SHA-256 but the proof checker itself is trusted.

## HTTP Status Codes

| Code | Meaning |
|---|---|
| `400` | Encoded path separator (`%2f`/`%5c`), `.`/`..` segment or backslash in the path, or a method override header in the request |
| `403` | Access rule or MCP tool policy denied the request |
| `404` | No route matched the request path |
| `429` | Rate limit exceeded |
| `500` | A credential could not be injected (including a failed OAuth2 refresh), or cannot be redacted because it contains `[`/`]` or is a substring of `[REDACTED]` |
| `502` | Upstream returned an error or is unreachable |
| `504` | Request or idle timeout exceeded |
