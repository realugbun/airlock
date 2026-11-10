# Contributing to Airlock

## Prerequisites

- Go 1.25+
- golangci-lint v2+ (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`)

## Build and Test

```bash
make build           # Build binary to bin/airlock
make test            # Run tests with race detector and coverage
make lint            # Run golangci-lint
make test-coverage   # Generate HTML coverage report
```

## Fuzz Testing

The access rule engine has fuzz tests that test for bypasses, panics, and unexpected behavior:

```bash
# Quick smoke test (10s per target)
go test -fuzz=FuzzAccessPolicyBypass -fuzztime=10s ./internal/proxy/

# Longer run
go test -fuzz=FuzzMatchPatternNoPanic -fuzztime=5m ./internal/proxy/
```

See [docs/security.md](docs/security.md) for all six fuzz targets.

## Formal Proofs

The access-rule matcher and the response redactors are modelled in Dafny under
`formal/`. CI verifies them on every pull request with a pinned, checksummed
Dafny 4.11.0. To run them locally, install [Dafny 4.11.0](https://github.com/dafny-lang/dafny/releases/tag/v4.11.0)
and run the same command CI runs:

```bash
for f in formal/*.dfy; do dafny verify --verification-time-limit 60 "$f"; done
```

Every file must verify with 0 errors and no warnings. Nothing in `formal/` may
be axiomatised — CI fails the build if `{:axiom}` or an `assume` statement
appears there.

If you change `splitPath`, `collapseDoublestar`, `matchSegment`, `matchPattern`,
`AccessPolicy.Allowed`, `redactAll`, `redactionSafe`, `tokenPrefixSuffixLen` or
the streaming redactors, update the corresponding model and the reference
implementations in
`internal/proxy/formal_diff_test.go`, which are what tie the models to the
shipped code. See [docs/security.md](docs/security.md#machine-checked-proofs)
for what is proved and what is assumed.

## Pull Requests

1. Fork the repo and create a branch from `main`.
2. Add tests for any new functionality.
3. Run `make test` and `make lint` before submitting — CI will reject PRs that fail either.
4. Update documentation if your change affects configuration, behavior, or deployment:
   - `README.md` for user-facing features
   - `docs/configuration.md` for config options
   - `docs/security.md` for security-relevant changes
   - `docs/deployment.md` for deployment changes
   - `examples/` for new configuration patterns
5. Keep PRs focused — one feature or fix per PR.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Handle errors explicitly — don't ignore return values in production code.
- Add comments only where the logic isn't self-evident.

## Reporting Issues

- **Bugs and feature requests** — [GitHub Issues](https://github.com/realugbun/airlock/issues)
- **Security vulnerabilities** — see [SECURITY.md](SECURITY.md)
