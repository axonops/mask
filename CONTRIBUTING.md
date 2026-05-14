# Contributing to mask

Thank you for your interest in contributing to `github.com/axonops/mask`. This document covers the expectations for code, tests, documentation, and release discipline.

## Contributor License Agreement

Every contributor must sign our [Contributor License Agreement](./CLA.md) before a pull request can be merged. This is a one-time step per GitHub account and covers every future contribution you make to any AxonOps open-source project.

The CLA Assistant bot will comment on your first pull request with the signing instructions — you reply with one sentence and you are done. The process takes under a minute. Your signature is recorded in `signatures/version1/cla.json` (the audit trail) and you appear in the auto-generated [`CONTRIBUTORS.md`](./CONTRIBUTORS.md) (the public thank-you list).

**Why we require it.** The CLA makes it explicit that (a) you have the right to contribute the code, (b) AxonOps has the licence to distribute your contributions under the project's Apache Licence 2.0, and (c) the project is legally protected if a dispute arises about contributed code. Signing the CLA does NOT change your rights to use your own contributions for any other purpose.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards. Report unacceptable behaviour privately to `oss@axonops.com`.

## Your first pull request — step by step

If you have never contributed to an open-source project on GitHub before, this is the full walkthrough. Everyone goes through the same flow; there is no separate process for AxonOps employees.

### 1. Fork and clone

1. Click **Fork** at the top-right of [`github.com/axonops/mask`](https://github.com/axonops/mask). This creates a copy of the repository under your own GitHub account — e.g. `github.com/your-handle/mask`. You have full write access to your fork; you do NOT have write access to the `axonops/mask` repository, and that is by design.
2. Clone **your fork** (not the upstream) to your laptop:

   ```sh
   git clone git@github.com:your-handle/mask.git
   cd mask
   ```

3. Add a remote pointing at the upstream repository so you can pull in the latest changes when you need to:

   ```sh
   git remote add upstream git@github.com:axonops/mask.git
   git fetch upstream
   ```

### 2. Find or open an issue

Every pull request must reference a GitHub issue. For anything beyond a typo fix, open an issue first so the maintainers can agree on the approach before you write code. The [issue templates](https://github.com/axonops/mask/issues/new/choose) route you to the right form — bug report, feature request, or new built-in rule request.

Small trivial fixes (typos, broken links, obvious one-line bugs) are fine without a prior issue.

### 3. Create a branch

Branch from an up-to-date `main`:

```sh
git checkout main
git pull upstream main
git checkout -b feature/short-descriptive-name        # or fix/<name>, docs/<name>, etc.
```

Branch-name prefixes used in this project: `feature/`, `fix/`, `docs/`, `chore/`, `refactor/`, `test/`, `perf/`.

### 4. Make your change

- Follow the [Ground rules](#ground-rules), [Commits](#commits), [Pull requests](#pull-requests), [Testing](#testing), and [Code standards](#code-standards) sections below.
- Add unit tests AND BDD scenarios for any new or changed masking rule.
- Run `make check` until it is clean before pushing.
- If your change edits any of the files bundled into `llms-full.txt` (documentation, examples, `README.md`, `CONTRIBUTING.md`, etc.), also regenerate it with `make llms-full` and commit the refreshed `llms-full.txt` in the same commit — CI enforces this via `make llms-full-check`.

### 5. Commit (signed, conventional-commit message)

Commits must follow the [Commits](#commits) format and must be cryptographically signed — see [§ Signing your commits](#signing-your-commits). If you have not set up signing yet, do that once and all future commits are covered.

```sh
git add <files>
git commit -m "feat(rules): add de_steuer_id masking rule (#NNN)"
```

### 6. Push to your fork

```sh
git push -u origin feature/short-descriptive-name
```

Because you are pushing to YOUR fork, branch protection on the upstream repository does not apply at this stage.

### 7. Open a pull request

On GitHub, navigate to your fork; a banner will prompt you to open a PR against `axonops/mask:main`. Fill in the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) — describe the change, link the issue, tick the checklist items you have satisfied.

### 8. Sign the CLA (first time only)

On your first PR, the CLA Assistant bot comments asking you to sign. Post this exact phrase as a new PR comment — case-sensitive, verbatim, no leading/trailing punctuation:

> I have read the CLA Document and I hereby sign the CLA

Your signature is recorded in `signatures/version1/cla.json` and you appear in [`CONTRIBUTORS.md`](./CONTRIBUTORS.md) automatically. Every future PR you open passes the CLA check without any extra step.

### 9. Iterate on review feedback

CI runs on every push to your PR branch. If anything fails, fix the root cause and push again — no need to close and re-open. Reviewers may ask for changes; address them with additional commits on the same branch. Keep the branch up to date with upstream main with `git fetch upstream && git rebase upstream/main` when needed.

You do not need to squash your own commits — the maintainer squash-merges on your behalf at the end, so extra iteration commits on the PR branch are expected and fine.

### 10. Merge

A maintainer with write access squash-merges the PR once CI is green, the CLA is signed, and any review feedback is resolved. External contributors cannot self-merge (GitHub disables the button). You do not need to do anything at this stage — after the merge, GitHub closes the PR and your commit lands on `main` with a clean squashed history.

Your branch can be deleted once the merge lands. GitHub usually offers a button for this on the PR page.

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
- A bulk fixture corpus lives under `tests/corpus/` — see [Corpus harness](#corpus-harness) below.

### Corpus harness

`tests/corpus/` holds a fixture-per-line test corpus that exercises every registered rule with hundreds of inputs at once. The harness sits behind the `corpus` build tag so it does not affect `go test ./...`. Run it explicitly via:

```sh
make test-corpus    # one-off
make check          # part of the full local quality gate
```

Each rule has a single fixture file at `tests/corpus/<rule>.txt`, split into two sections by comment banners:

```text
# === canonical (hand-written; preserved by generator) ===
... inputs hand-picked for spec coverage ...

# === generated (do not edit; regenerated by make corpus-regen) ===
... inputs produced deterministically by tests/corpus/gen/<rule>.go ...
```

The generator under `tests/corpus/gen/` (build tag `corpusgen`) writes the generated section and a `.corpus.lock` manifest that `TestMain` verifies before subtests run. Run it via:

```sh
make corpus-regen   # rewrites every <rule>.txt's generated section + .corpus.lock
```

Every fixture line is `input<TAB>expected`. The harness reads the line, calls `mask.Apply(rule, input)`, and asserts the result equals `expected`. Expected outputs come from `mask.Apply` at generation time — the corpus locks current behaviour. A rule change that affects a fixture line surfaces as a CI failure on `corpus-lock-fresh`; rerun `make corpus-regen` and commit the diff.

**Adding fixtures.** Add inputs to the canonical section of an existing file (use `tests/corpus/_tools/expect` to have `mask.Apply` fill in the expected column). To grow the generated section, add or extend the per-rule generator at `tests/corpus/gen/<rule>.go` with build tag `corpusgen`.

**Surfacing latent rule bugs.** If a fixture forces the generator to emit output that looks wrong, mark the affected fixture line with a `# BUG?` comment in the canonical section and open a follow-up issue. Do not edit the generated section by hand — the `corpus-lock-fresh` CI job will fail.

**File-format rules** (enforced by `TestCorpusFormatStrict`):

- UTF-8, LF line endings, no BOM.
- Each fixture line contains exactly one TAB separator.
- Comments start with `#`. Blank lines are ignored.
- Optional pragma `# corpus: escaped` near the top enables `\\ \t \n \r \xNN \uXXXX` decoding for the rest of the file. Use it sparingly — the byte-literal common case is unambiguous.

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
