# Contributing to mask

Thank you for your interest in contributing to `github.com/axonops/mask`. This document covers the expectations for code, tests, documentation, and release discipline.

## Ground rules

- **Zero runtime dependencies.** The library MUST remain stdlib-only. PRs that add a runtime dependency will not be merged.
- **Correctness first.** Every masking rule, every primitive, and every edge case is covered by both unit and BDD tests. If a change cannot be tested, it cannot land.
- **Fail closed.** Masking rules never return the original unmasked value on parse failure.

## Branching

- `main` is always green and always buildable.
- Feature work: `feature/<short-name>` branched from `main`.
- Bug fixes: `fix/<short-name>` branched from `main`.
- Never commit directly to `main`.

## Commits

Conventional Commits are mandatory:

```
<type>(<scope>): <subject> (#<issue>)

<body>
```

**Types:** `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `perf`.

**Rules:**

1. Subject line: imperative mood, lowercase, no period, ≤ 72 chars.
2. Every commit MUST reference the GitHub issue it addresses: `feat: add iban masking rule (#12)`.
3. Body is optional but MUST explain *why*, not *what*.
4. Never mention AI tooling (Claude, Copilot, GPT, LLM, Anthropic) anywhere in a commit message.
5. One logical change per commit. Use rebase, not merge commits.

## Pull requests

Every PR MUST:

1. Reference the issue it closes (`Closes #N`).
2. Include unit tests AND BDD scenarios for every new or changed masking rule.
3. Include a benchmark for any rule on the hot path.
4. Pass `make check` locally before pushing.
5. Keep `go.mod` and `go.sum` tidy (`go mod tidy` clean).
6. Maintain coverage at 90% or higher.

CI runs the same gates as `make check`. If CI fails on your PR, fix the root cause — do not add suppressions or `//nolint` directives without an issue reference.

## Testing

- Unit tests live beside the code in external (`package mask_test`) black-box style.
- BDD tests live under `tests/bdd/`. Feature files in `tests/bdd/features/`, step definitions in `tests/bdd/steps/`.
- Every masking rule and every primitive has at least one `Scenario Outline` with `Examples` covering canonical, formatted, malformed, empty, and (where applicable) unicode inputs.
- Benchmarks live in `*_bench_test.go` files and call `b.ReportAllocs()`.

See [`CLAUDE.md`][claude-md] (not in this repo — developer-local) and the `docs/v0.9.0-requirements.md` spec for the authoritative testing requirements.

## Code standards

- Google Go Style Guide baseline.
- Functions over ~40 lines: split them.
- Cyclomatic complexity > 10: refactor before merge.
- Errors wrapped with `%w` and context.
- No `Get` prefix on accessors. Acronyms preserve case (`URL`, `PAN`, `IBAN`).
- Apache 2.0 licence header on every `.go` file.

## Releases are CI-only

**Never tag locally. Never run `goreleaser release` locally.**

The release process is:

1. Update `CHANGELOG.md` and any version references in a PR to `main`.
2. After merge, trigger the `Release` workflow via `workflow_dispatch` with the target tag, OR publish a GitHub Release.
3. CI validates the quality gate, creates the tag, and runs GoReleaser.

Any local tagging attempt is a policy violation. The `devops` review agent treats local tagging in workflows or docs as a BLOCKING issue.

### Branch protection

The `main` branch is protected. The protection rules require:

- Pull request review before merge.
- Status checks: `CI` must pass.
- Linear history (no merge commits).
- No force pushes.
- Only administrators may override, and overrides are logged.

## Security

See [`SECURITY.md`](./SECURITY.md) for vulnerability disclosure.

## Licence

By contributing, you agree that your contributions will be licensed under the [Apache Licence 2.0](./LICENSE).

[claude-md]: CLAUDE.md
