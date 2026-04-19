# Contributing to mask

Thank you for your interest in contributing to `github.com/axonops/mask`. This document covers the expectations for code, tests, documentation, and release discipline.

## Contributor License Agreement

Every contributor must sign our [Contributor License Agreement](./CLA.md) before a pull request can be merged. This is a one-time step per GitHub account and covers every future contribution you make to any AxonOps open-source project.

The CLA Assistant bot will comment on your first pull request with the signing instructions — you reply with one sentence and you are done. The process takes under a minute. Your signature is recorded in `signatures/version1/cla.json` (the audit trail) and you appear in the auto-generated [`CONTRIBUTORS.md`](./CONTRIBUTORS.md) (the public thank-you list).

**Why we require it.** The CLA makes it explicit that (a) you have the right to contribute the code, (b) AxonOps has the licence to distribute your contributions under the project's Apache Licence 2.0, and (c) the project is legally protected if a dispute arises about contributed code. Signing the CLA does NOT change your rights to use your own contributions for any other purpose.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards. Report unacceptable behaviour privately to `oss@axonops.com`.

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

```text
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

### Signing your commits

`main` is protected with `required_signatures: true` — GitHub rejects unsigned commits when a PR is merged. Set up signing once and all your future commits are covered. **SSH signing is recommended** (simpler, reuses the key you already push with, no separate keyring to manage); GPG is documented below as a fallback for contributors who already use it.

**SSH signing (recommended — one key does push + sign):**

```sh
# 1. If you do not already have an SSH key, generate one. Ed25519 is the
#    modern default; 3072-bit RSA is also fine if your org mandates it.
ssh-keygen -t ed25519 -C "you@example.com"

# 2. Tell git to use SSH for commit signing and point at your public key.
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# 3. Add the SAME public key to GitHub as a Signing Key so commits show
#    as "Verified" in the web UI. This is a separate entry from the
#    Authentication Key — even if the underlying file is identical.
#
#    Copy the public key to your clipboard:
pbcopy < ~/.ssh/id_ed25519.pub           # macOS
# xclip -selection clipboard < ~/.ssh/id_ed25519.pub   # Linux (with xclip)
#
#    Then go to https://github.com/settings/ssh/new and pick
#    "Key type: Signing Key", paste, save.
```

**GPG signing (classic, also supported):**

```sh
# 1. Generate a key if you do not already have one.
gpg --full-generate-key                  # RSA 4096, 2-year expiry is sensible

# 2. Find the key ID and tell git to use it. Replace KEYID.
gpg --list-secret-keys --keyid-format long
git config --global user.signingkey KEYID
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# 3. Upload the public key to GitHub at
#    https://github.com/settings/gpg/new:
gpg --armor --export KEYID | pbcopy      # macOS
# gpg --armor --export KEYID | xclip -selection clipboard  # Linux
```

**Verify it worked (either path):**

```sh
git commit --allow-empty -m "chore: test signing"
git log --show-signature -1
```

You should see `Good "git" signature for ...` (SSH) or `gpg: Good signature from ...` (GPG). Push the commit and GitHub will show a green **Verified** badge next to it.

Full GitHub docs: <https://docs.github.com/en/authentication/managing-commit-signature-verification>.

## Pull requests

Every PR MUST:

1. Reference the issue it closes (`Closes #N`).
2. Include unit tests AND BDD scenarios for every new or changed masking rule.
3. Include a benchmark for any rule on the hot path.
4. Pass `make check` locally before pushing.
5. Keep `go.mod` and `go.sum` tidy (`go mod tidy` clean).
6. Maintain coverage at 90% or higher.

CI runs the same gates as `make check`. If CI fails on your PR, fix the root cause — do not add suppressions or `//nolint` directives without an issue reference.

Documentation changes that touch `README.md`, `doc.go`, `CONTRIBUTING.md`, `SECURITY.md`, `llms.txt`, `docs/rules.md`, or `docs/extending.md` MUST also regenerate `llms-full.txt` by running `make llms-full` and including the updated `llms-full.txt` in the **same commit** as the documentation change. CI enforces this via the `llms-full.txt is up to date` job.

### Review workflow

Before opening a PR, run the full quality gate (`make check`). Internally this project uses several review passes — code review, security review, documentation review, performance review, and a test-analyst pass — before every merge. Contributors are expected to address findings from those passes the same way they address CI failures: fix the root cause in the same PR rather than deferring to a follow-up.

## Testing

- Unit tests live beside the code in external (`package mask_test`) black-box style.
- BDD tests live under `tests/bdd/`. Feature files in `tests/bdd/features/`, step definitions in `tests/bdd/steps/`.
- Every masking rule and every primitive has at least one `Scenario Outline` with `Examples` covering canonical, formatted, malformed, empty, and (where applicable) unicode inputs.
- Benchmarks live in `*_bench_test.go` files and call `b.ReportAllocs()`.

See `CLAUDE.md` (developer-local, not checked into the repo) for the authoritative project-specific testing requirements.

### Performance baseline

`bench.txt` at the repo root is the committed benchmark baseline. CI runs the `benchstat-regression-guard` job on every PR, which compares a fresh benchmark run against `bench.txt` and fails the build if any measurement regresses beyond the threshold.

**Thresholds (enforced by `scripts/check-bench-regression.sh`):**

- `time/op`: any regression of 10% or more at p ≤ 0.05 fails the build.
- `allocs/op`: any increase at all fails the build.
- `alloc/op` (bytes): same threshold as `time/op`.

**Checking locally before pushing:**

```sh
go install golang.org/x/perf/cmd/benchstat@latest
make bench-regression
```

The target runs `go test -bench=. -benchmem -run=^$ -count=5 .`, pipes through `benchstat`, and exits non-zero if any regression crosses the threshold. The full report is written to `bench-regression.txt`.

**Regenerating the baseline after a legitimate optimisation:**

```sh
make bench > bench.txt
# Manually trim the trailing 'PASS' / 'ok' lines so the file ends with
# the final Benchmark* line. Commit the updated bench.txt in the same
# PR as the optimisation.
```

**Reading a regression report:** benchstat prints three tables — `time/op`, `alloc/op`, `allocs/op` — each with `old`, `new`, and `delta` columns. A row with `+5.00%` and `(p=0.000 n=5+5)` means 5% slower with high statistical significance. A `~` in the delta column means no measurable change. The guard fires on positive deltas above threshold; negative deltas (improvements) are always accepted.

> **Known caveat — shared-runner noise.** The guard currently runs on `ubuntu-latest`, a shared GitHub-hosted runner. Those runners share CPU with neighbouring workloads and exhibit ±5-15% variance between runs for nanosecond-scale benchmarks, which can fire this guard on pure jitter. We are watching it in practice; if it flakes repeatedly we will either (a) move the job to a dedicated runner, (b) raise the time/op threshold (keeping `allocs/op` strict since allocation counts are deterministic), or (c) make the job advisory-only rather than build-blocking. If you see a regression report on a PR that does not touch the hot path and re-running CI clears it, that is likely what happened — flag it on the PR and we will tune the threshold.

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
