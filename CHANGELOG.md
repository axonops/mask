# Changelog

All notable changes to `github.com/axonops/mask` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes.

## Upgrading

While the project is pre-1.0 (`v0.x`) every minor version MAY include
breaking changes. Pin a specific tag in `go.mod` and treat every minor
bump as a manual review step: read the release notes for the target
version, update your `Register` / `DeterministicHashFunc` call sites
where the public API has changed, run your test suite with
`-race`, and confirm the new version against the `make check` gate
before rolling to production. From `v1.0.0` onwards the library
commits to the standard Go semver compatibility promise — breaking
changes only in a new major version.

## [0.9.0] — 2026-04-18

Initial public release.

### Added

- **Core API.** `mask.Apply(name, value)` for rule lookup and invocation, `mask.Register(name, fn)` for custom rules on the package-level registry, `mask.New(opts...)` for per-instance isolated registries, and `mask.Rules()` / `mask.Describe(name)` for runtime catalogue discovery.
- **Configurable mask character.** `mask.SetMaskChar(c)` for the package-level default and `mask.WithMaskChar(c)` for per-instance override.
- **Utility primitives** — direct-call helpers (`FullRedact`, `Nullify`, `SameLengthMask`, `KeepFirstN`, `KeepLastN`, `KeepFirstLast`, `PreserveDelimiters`, `ReducePrecision`, `DeterministicHash`) and factory wrappers (`KeepFirstNFunc`, `KeepLastNFunc`, `KeepFirstLastFunc`, `PreserveDelimitersFunc`, `ReplaceRegexFunc`, `ReducePrecisionFunc`, `FixedReplacementFunc`, `DeterministicHashFunc`). Regex masking is factory-only: a compiled `RuleFunc` is the supported form; a one-shot `ReplaceRegex(v, pattern, replacement)` helper that re-compiled on every call is intentionally not part of the public API.
- **Deterministic hashing** with configurable algorithm (`SHA256`, `SHA512`, `SHA3_256`, `SHA3_512`) and atomic keyed-salt configuration via `WithKeyedSalt(salt, version)` — the salt and version are validated together so keyed hashing can never be half-configured. Output format `<algo>:<hex16>` unsalted, `<algo>:<version>:<hex16>` when keyed. An empty salt or invalid version fails closed to `[REDACTED]` rather than silently downgrading.
- **68 built-in masking rules**: 4 utility primitives (`full_redact`, `same_length_mask`, `nullify`, `deterministic_hash`) plus 64 domain rules across identity (11 global + 14 country-specific), financial (11), healthcare (5), technology (14), and telecom + location (9). Every rule is fail-closed, honours the configured mask character, and is registered with a populated `RuleInfo` including category, jurisdiction, and an `input → output` example.
- **Runnable godoc examples** covering the simplest `Apply` case, fail-closed behaviour, custom rule registration, per-instance mask-character override, global mask-character override, direct primitive calls, factory-based registration, runtime discovery via `Describe`, and a realistic structured-log redaction sample.
- **Package documentation** (`doc.go`) covering the quick start, design principles, thread-safety contract, mask-character configuration, and explicit non-goals.
- **BDD coverage** under godog strict mode (`Strict: true`) with feature files per category (`identity.feature`, `financial.feature`, `health.feature`, `technology.feature`, `telecom.feature`, `country.feature`, plus `core_api.feature` and `primitives.feature`).
- **Benchmarks** for every rule, with allocation reporting and fail-closed-path variants where meaningful.
- **Drift guards.** CI-enforced checks that: every registered rule appears in exactly one README rule-table row; every rule carries an `Example:` line in its description; the BDD suite runs in strict mode; all Makefile targets are documented; no local paths or replace directives leak into `go.mod`; no AI-tooling attribution appears in commits, PRs, or code.
- **CI/CD.** Format check, vet, lint, unit and BDD tests, coverage, module tidy, security scan, cross-platform builds (`linux/amd64`, `darwin/arm64`, `windows/amd64`), and a CI-only release workflow — no local tagging permitted.
- `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` (Apache 2.0).

[Unreleased]: https://github.com/axonops/mask/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/axonops/mask/releases/tag/v0.9.0
