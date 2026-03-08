# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Airlock, **please do not open a public GitHub issue.**

Instead, report it privately via [GitHub Security Advisories](https://github.com/realugbun/airlock/security/advisories/new).

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential impact or exploit scenario

## Response

- We will acknowledge your report within 3 business days.
- We will provide an initial assessment within 7 business days.
- We will work with you to understand and resolve the issue before any public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Scope

The following are in scope for security reports:

- Access rule bypasses (path traversal, encoding tricks, wildcard logic errors)
- MCP tool filtering bypasses
- Credential leakage (redaction failures, logging secrets, response body exposure)
- Authentication injection failures
- Denial of service via crafted input (pathological patterns, unbounded allocations)

The following are **out of scope**:

- Vulnerabilities in upstream APIs that Airlock proxies to
- Misconfiguration (e.g., running without `strict: true`, no network isolation)
- Issues that require host-level or container runtime compromise
- Social engineering
