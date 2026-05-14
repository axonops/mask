# Changelog

All notable changes to `github.com/axonops/mask` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OpenSSF Scorecard weekly workflow (`.github/workflows/scorecard.yml`) that publishes a supply-chain posture score to `scorecard.dev` and uploads SARIF results to the GitHub Code scanning Security tab. Triggers on push to `main`, every PR against `main`, a weekly cron (Saturday 01:30 UTC), and `workflow_dispatch` for manual verification. Governance test `TestGovernance_ScorecardWorkflowExists` asserts the workflow's permission scopes, SHA-pinned action ref, `publish_results: true`, and `paths-ignore` policy. ([#52](https://github.com/axonops/mask/issues/52))
- OpenSSF Scorecard badge in the README badge row (linking to the live viewer), and an Elsewhere link to the Scorecard report in `docs/README.md`. ([#52](https://github.com/axonops/mask/issues/52))
- Bulk fixture corpus under `tests/corpus/` with ~12,000 generated fixtures across all 68 registered rules. The harness sits behind the `corpus` build tag and runs as part of `make check` and the new `Corpus fixture tests` CI job. A deterministic per-rule generator framework (`tests/corpus/gen/`, build tag `corpusgen`) preserves a hand-written canonical section in each fixture file and rewrites a much larger generated section. A `.corpus.lock` SHA-256 manifest is verified at `TestMain`, and the `Corpus lock is fresh` CI job re-runs `make corpus-regen` and fails on diff so generator output stays byte-stable. Two author helpers (`tests/corpus/_tools/bootstrap` and `tests/corpus/_tools/expect`, build tag `corpushelper`) streamline canonical-section curation. ([#54](https://github.com/axonops/mask/issues/54))

### Fixed

- `phone_number` and `mobile_phone_number` now recognise the ITU-T `00<CC>` international access prefix in addition to `+<CC>`. Inputs like `0044 7911 123456` mask to `0044 **** **3456` (country code preserved, subscriber masked) instead of failing closed. The `00` prefix is kept verbatim — it is not rewritten to `+`. Inputs with a single domestic leading `0` (e.g. `07911 123456`) are unaffected. ([#55](https://github.com/axonops/mask/issues/55))
- Compact form (`00CC<digits>` with no separator between country code and subscriber) is accepted on the `00` path to match the dial-string convention. The `+` parser continues to require a separator after the country code; this asymmetry is deliberate and documented in the rule godoc. ([#55](https://github.com/axonops/mask/issues/55))
- `mask.Apply` now calls `ensureInit` on every invocation rather than only when the rules pointer is nil. `ensureInit` uses two `sync.Once` calls (`initOnce` stores an empty rule map; `builtinsOnce` registers the built-ins) and the previous fast-path skipped both whenever the rules pointer had already been published — so a parallel first-Apply caller that observed the pointer between the two `Once` calls saw an empty registry and fell through to `FullRedactMarker` for every rule. `sync.Once`'s post-init fast path is one atomic load + branch, so the cost of removing the gap is negligible. Surfaced by the new corpus harness, whose parallel subtests are the first thing in the suite to exercise zero-value `Masker` init under concurrency. Regression test: `TestZeroValueMasker_ParallelFirstApply`. ([#54](https://github.com/axonops/mask/issues/54))

### Security

- Tightened workflow token permissions to a `contents: read` workflow-level baseline across `cla.yml`, `contributors.yml`, `dependabot-automerge.yml`, and `release.yml`. Jobs that need elevated scopes (`contents: write`, `pull-requests: write`, `statuses: write`) now declare them per-job rather than workflow-wide, so a future job added to one of these workflows inherits read-only by default. Dropped the redundant `actions: write` scope from the CLA Assistant flow. Governance test `TestGovernance_WorkflowsLeastPrivilegeBaseline` pins the baseline (single `contents: read` key) across all six workflow files. ([#66](https://github.com/axonops/mask/issues/66))
- Pinned every GitHub Actions reference in `.github/workflows/` by 40-hex commit SHA with a trailing `# vX.Y.Z` tag comment. Covers 39 `uses:` lines across `ci.yml`, `release.yml`, `cla.yml`, `contributors.yml`, `dependabot-automerge.yml`, and `scorecard.yml`. Closes a tag-retag supply-chain hole — most critically on `cla.yml`'s `contributor-assistant/github-action` ref, which runs in `pull_request_target` context with the `CLA_ASSISTANT_PAT` admin token in env. `.github/dependabot.yml` now declares a `github-actions-all` group so all action bumps land in a single weekly PR with SHA and trailing comment updated together. Governance test `TestGovernance_AllActionsSHAPinned` walks every `.github/workflows/*.yml` file and rejects any unpinned `uses:` line or missing version comment. ([#65](https://github.com/axonops/mask/issues/65))

## Upgrading

From `v1.0.0` onwards `mask` follows the standard Go semantic-versioning
compatibility promise: breaking changes to the public API only in a new
major version. Minor and patch releases are always backwards-compatible
for the API surface documented on [pkg.go.dev](https://pkg.go.dev/github.com/axonops/mask).
Pin a specific tag in your `go.mod`, review the release notes for the
target version, and run your test suite with `-race` against the new
version before rolling to production.

## [1.0.0] — 2026-04-19

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

[Unreleased]: https://github.com/axonops/mask/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/axonops/mask/releases/tag/v1.0.0
