# Security

This document covers Airlock's security model, threat model, path normalization, fuzz testing, and production hardening.

## Security Model and Threat Model

### What Airlock protects against

- **Direct credential exposure to the agent.** In the documented deployment model, the agent is not given real upstream API credentials directly. Airlock injects credentials at the network boundary.
- **Unauthorized API operations.** Firewall-style access rules restrict which HTTP methods and paths the agent can call. MCP tool filtering restricts which JSON-RPC tools the agent can invoke.
- **Credential leakage in responses.** Airlock redacts injected credentials from proxied response headers, trailers and bodies, including SSE streams, independently of how the upstream chunks the response. On routes that inject a credential, upstream 1xx informational responses (such as `103 Early Hints`) are not forwarded. A credential that cannot be redacted safely is refused rather than forwarded — see [Credential Characters and Redaction](#credential-characters-and-redaction).
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

## Injected Headers

Before injecting credentials and `extra_headers`, Airlock removes the agent's `Connection` header, every header it names, and the standard hop-by-hop headers. Otherwise `Connection: Authorization` would make the proxy drop the injected credential. `auth.header` and `extra_headers` may not be hop-by-hop names.

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
inside the constant placeholder text (a credential of `RED` is a substring of
`[REDACTED]`, which reveals nothing about it). Bracket-free credentials are
unaffected by this check.

Redaction is also independent of how the upstream chunks its response. Both the
plain and the SSE redactor hold back only the tail of the stream that could
still begin a credential, and replace longest match first, so the bytes the
agent receives are the same whatever the chunk boundaries are. An agent cannot
reveal a fragment of a credential by influencing the response framing.

Both of these properties — that no bracket-free credential survives redaction,
and that the output does not depend on the chunk boundaries — are proved
mechanically. See [Machine-Checked Proofs](#machine-checked-proofs), which also
states the one part of the credential constraint that `redactionSafe` does not
enforce.

## MCP Request Inspection

On a route whose `mcp_rules` lists `allowed_tools` or `denied_tools`, a POST body that Airlock cannot inspect exactly as the upstream will read it is rejected, never forwarded:

- `413` if the body exceeds 10 MiB (by `Content-Length` or after reading a chunked body)
- `415` for a `Content-Encoding` other than `identity`, or a `Content-Type` that is not `application/json` or `text/json` (compared case-insensitively; a `charset` must be UTF-8). A missing `Content-Type` is inspected as JSON
- `400` for malformed JSON, invalid UTF-8, a `tools/call` without a non-empty string `params.name`, a batch with any invalid element, or a duplicate or case-variant `method`, `params` or `name` key (`"Name"`, `"METHOD"`). JSON parsers disagree on which duplicate wins and whether keys are case-sensitive, so these are ambiguous

`mcp_rules: {}` enforces nothing and keeps forwarding such requests unchanged.

That an uninspectable body is never forwarded, that a batch is all-or-nothing, and that the tools an agent can see are exactly the tools it can call are [proved](#mcp).

## Time and Size Limits

- A route's `timeout` starts when the request is routed and covers reading and inspecting the body and resolving secrets. A body not received in time gets `408 Request Timeout`
- The listener allows 10s to read request headers, 1 MiB of headers, and closes idle keep-alive connections after 120s. There is no server-wide read or write timeout, so SSE streams are bounded only by the route's `timeout` and `idle_timeout`
- A non-streaming `tools/list` response is buffered to filter it and capped at 10 MiB; a larger response gets `502 Bad Gateway`

## Path Normalization

Airlock matches against `r.URL.Path` (the percent-decoded request path) after `strip_prefix` is applied. Matching is **segment-based** — paths are split on `/` and compared segment by segment.

**Normalization rules:**

- **Double slashes** (`//`) are normalized — interior empty segments are filtered, so `/v1//chat/completions` matches the same as `/v1/chat/completions`
- **Encoded path separators** — requests whose escaped path contains `%2f` or `%5c` are rejected with `400 Bad Request`, preventing "policy sees path A, upstream sees path B" mismatches (checked via `RawPath` with `EscapedPath()` fallback)
- **Path traversal** — requests whose decoded path contains a `.` or `..` segment (including `%2e` forms), or a literal backslash, are rejected with `400 Bad Request`, both before and after `strip_prefix` is applied. Airlock never cleans the path, since many upstreams would resolve `/allowed/../admin` to `/admin`
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

The access-rule matcher, the response redactors and MCP tool
authorization are modelled in
[Dafny](https://dafny.org) under [`formal/`](../formal) and the models are
verified in CI by [`.github/workflows/formal.yml`](../.github/workflows/formal.yml),
which installs a pinned, SHA-256-checked Dafny 4.11.0 and runs
`dafny verify --verification-time-limit 60` over every file. Warnings are
errors, so a file that verifies with a warning still fails the job. The whole
suite is 304 proof obligations and takes about 25 seconds.

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
| `formal/mcp.dfy` | `isToolDenied`, `checkSingle`, `checkBatch`, `enforceRequest`, the `tools/list` name filter |

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

Redaction, under the credential constraint stated below:

- **A bracket-free secret cannot overlap the placeholder.** It contains no `[REDACTED]`, has no suffix that is a placeholder prefix, and no prefix that is a placeholder suffix — so a replacement cannot splice the secret back together across its own boundary.
- **One pass removes every occurrence of its secret and creates none.**
- **Replacing one secret cannot resurrect another.** Later passes only insert placeholders and delete their own token, neither of which can spell a bracket-free secret that was not already there.
- **No secret appears in the output of `redactAll`,** for any number of secrets in any order.
- **Streamed redaction equals one-shot redaction, for every chunking.** The chunk list is universally quantified, so this covers every way the upstream could split the body, including splitting a secret byte by byte across reads. Two different chunkings of the same body give byte-identical output.
- **No secret appears in the streamed output, for every chunking** — the previous two results composed.

### MCP

MCP tool authorization is modelled in [`formal/mcp.dfy`](../formal/mcp.dfy)
over an **abstract parsed message** — a method, a tool name and an id, or a
`Malformed` constructor for a body that is not well-formed or whose
policy-relevant keys are ambiguous. `path.Match` is left uninterpreted, and the
**same** uninterpreted matcher is used by the `tools/call` check and by the
`tools/list` filter, so every property below holds for any glob behaviour
whatsoever.

The two tool lists are mutually exclusive, which is checked both at config load
and in the policy constructor. The model states that as a precondition and
proves the constructor is what enforces it:

- **A config that sets both `allowed_tools` and `denied_tools` is refused,** so no policy value the other theorems range over can carry both lists.
- **A non-empty list always selects its own mode.** Every entry lands in either the exact set or the pattern list, so a non-empty `allowed_tools` always produces allowlist mode and never silently degrades to pass-through. `checkEmptyAllowlists` separately rejects a present-but-empty `allowed_tools`, which is the one way an operator could reach pass-through while believing they had written an allowlist.
- **Allowlist mode allows only listed tools**, and **denylist mode denies exactly the listed tools**, in both cases exact names plus pattern matches and nothing else.
- **No lists means pass-through** — nothing is denied. Stated explicitly rather than hidden, as with access rules.

The request path:

- **A forwarded `tools/call` names a tool the policy allows.** Stated for a single message and for every element of a batch, via the names a body would have the upstream execute.
- **A batch is all-or-nothing.** It is forwarded **if and only if** every element is well-formed and no element is a denied `tools/call`. Every element is parsed before any element is authorized, so one malformed element in any position rejects the whole batch instead of travelling alongside the others.
- **With tool rules set, a body that cannot be inspected is never forwarded.** Proved in both directions: uninspectable implies rejected, and forwarded implies inspectable. A compressed body, a non-JSON or duplicated `Content-Type`, an oversized body, a body that is not valid UTF-8, and a body that is not a JSON array when it opens with `[` are all uninspectable, because Airlock cannot read them the way the upstream will. (An array whose *elements* are not JSON-RPC objects, such as `[1,2]`, is stopped one step later, by the all-or-nothing batch property above: each element parses as malformed.)
- **A forwarded POST carries no `tools/call` the policy does not allow**, in every mode. In pass-through mode this holds because the policy allows everything, which is the configured behaviour.

The response path:

- **`tools/list` filtering keeps exactly the allowed tools, in order.** Proved as a strictly ascending index map into the upstream list that selects precisely the allowed positions: every allowed tool is kept, no denied tool survives, no tool is invented, and the upstream's order is preserved.
- **Listing and calling agree.** A tool survives the `tools/list` filter **if and only if** a `tools/call` naming it is forwarded, and a tool hidden from the listing is refused by name when called. Both sides are the same predicate over the same uninterpreted matcher, so they cannot drift apart.
- **The `tools/list` request itself is always forwarded.** It is not a `tools/call`; it is the response that is filtered.

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
- **The credential constraint includes one condition `redactionSafe` does not enforce.** The redaction theorems assume a secret is nonempty, free of `[` and `]`, **and not itself a substring of the literal text `[REDACTED]`**. `redactionSafe` enforces the brackets; it does not reject a credential like `RED` or `ACTED`. Such a credential does "appear" in redacted output, but only as part of the constant placeholder text, which carries no information about it. This is the same argument made in [Credential Characters and Redaction](#credential-characters-and-redaction), and it is an argument, not a theorem.
- **`path_regex` semantics are not modelled.** The per-rule matcher is uninterpreted, which is why first-match-wins, implicit deny and the segment cap cover regex rules too. But RE2's own behaviour, the `\A(?:...)\z` anchoring wrapper, and `normalizePath` are outside the models. The anchoring argument is in [Regex Path Matching](#regex-path-matching-path_regex) and is covered by tests and fuzzing, not proofs.
- **The reader plumbing is not modelled.** The proofs cover the redaction algebra: the cascade receives some partition of its input followed by exactly one flush. That both shipped readers do deliver such a partition — `redactingReader` pushing `buf[:n]` per `Read` and flushing once when the upstream ends, `sseEventReader` calling the transform per event batch and the final hook once in `drain()` — is read off the code, not proved. Buffering, error ordering and `Close` behaviour are covered by tests only.
- **SSE line-ending normalization happens before redaction.** `\r\n` and lone `\r` become `\n` on the way into the cascade, so the streaming guarantee is about the normalized byte stream, which is what the agent receives.
- **`prepareRedactTokens`' ordering and deduplication are not modelled.** Neither theorem needs them: both hold for any token order, and the streaming and one-shot sides are always handed the same list. Longest-first ordering is a quality-of-redaction choice, not a safety property here.
- **Alphabet.** Dafny `string` is a sequence of characters; the redactors operate on `[]byte`. The redaction proofs never inspect an element except to compare it with `[` or `]`, so they hold over sequences of any element type with those two values distinguished, and both brackets are single-byte ASCII. The same applies to `/` in the path model.
- **Performance is not proved.** The DP is proved correct and terminating, not O(P×S).
- **JSON decoding is not modelled.** The MCP model starts from an already-parsed message, so no proof covers `parseRPCMessage` or `decodeStrictObject`. They are covered instead by the adversarial differential tests in `internal/proxy/formal_mcp_diff_test.go`, which re-derive the policy-relevant fields with an independent JSON scanner — its own tokenizer, its own escape decoding including `\uXXXX` and surrogate pairs, its own Unicode case folding, no `encoding/json` and no `strings.EqualFold` — and check that duplicate keys, case-variant keys, non-object `params`, batches mixing valid and invalid elements, trailing data, BOMs and truncations are **rejected** rather than decided one way. That is testing, not proof.
- **An escape-spelled key is read, not refused.** `{"params":{"\u006eame":"x"}}` is accepted and the tool name is read as `x`, because every JSON parser decodes `\u006eame` to `name` — there is only one reading, so there is nothing to be ambiguous about. What is refused is an escape spelling that **collides** with another spelling of the same key (`{"name":"a","\u006eame":"b"}`) or that decodes to a case variant (`{"\u004Eame":"a"}`, `{"param\u017f":{…}}`, where U+017F folds to `s`). `TestEscapeSpelledKeysAreReadNotRejected` pins the accepting half, and the ambiguous corpus pins the refusing half.
- **`{"method":null}` is read as a message with no method.** `encoding/json` treats JSON `null` as a silent no-op for a string target, so a null `method` is forwarded as a non-tool message rather than refused. No reading of it executes a tool — an empty method is not `tools/call` and no upstream can dispatch it — so it is not a policy-relevant ambiguity, but it is leniency rather than strictness, and it is pinned by `TestNullMethodIsReadAsNoMethod`. A null `params.name` is refused, because the parser requires a non-empty name.
- **The `tools/list` filter reads tool names leniently; the request check does not.** The response filter decodes each entry with `encoding/json`, which is case-insensitive and keeps the last duplicate, so a hostile upstream advertising `{"name":"admin_delete","Name":"calendar_read"}` can make a **listing** misleading. It cannot make a **call** succeed: the request path reads the name strictly and independently, so the ambiguous call is refused outright and the unambiguous hostile name is denied. `TestListingNameAmbiguityCannotAuthorizeACall` pins that. An entry that does not decode into `{name string}` at all is passed through untouched and contributes no name; the model carries that branch explicitly.
- **A non-POST request is forwarded uninspected.** The request theorems are stated for POST. MCP carries JSON-RPC payloads over POST; `GET` opens the server-sent-event channel and `DELETE` ends a session, neither of which can invoke a tool. That is a statement about the MCP transport, not a theorem.
- **Response framing is not modelled.** The `tools/list` proofs are about the name filter. SSE envelope handling (`filterSSEToolsList`, `newMCPToolFilterReader`, `filterMCPEventData`) and the re-serialization of the JSON envelope are covered by tests only.
- **`isGlobPattern`'s split between the exact map and the pattern list is left uninterpreted,** like `path.Match` itself. No property depends on which bucket an entry lands in, only that it lands in exactly one.
- **The toolchain is trusted.** Dafny 4.11.0 and its bundled Z3 are assumed sound; the release archive is pinned by SHA-256 but the proof checker itself is trusted.

## HTTP Status Codes

| Code | Meaning |
|---|---|
| `400` | Encoded path separator (`%2f`/`%5c`) in request |
| `403` | Access rule or MCP tool policy denied the request |
| `404` | No route matched the request path |
| `429` | Rate limit exceeded |
| `500` | A credential could not be injected, or contains `[`/`]` and cannot be redacted |
| `502` | Upstream returned an error or is unreachable |
| `504` | Request or idle timeout exceeded |
