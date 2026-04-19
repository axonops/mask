<!-- markdownlint-disable MD041 -->
## Description

<!-- 1-3 bullets. What changed and why. Link the issue this closes. -->

Closes #

## Type of change

- [ ] Bug fix (non-breaking fix to an existing masking rule or primitive)
- [ ] New built-in masking rule
- [ ] Enhancement to an existing masking rule
- [ ] Documentation update (README, docs/, godoc, examples, CONTRIBUTING, etc.)
- [ ] CI / build / release configuration
- [ ] Other (describe):

## Test plan

<!-- Tick the relevant boxes; leave N/A for items that do not apply. -->

- [ ] `make check` — unit + BDD tests, lint, formatter, tidy, coverage ≥ 90 %, vuln scan
- [ ] Added / updated unit tests for new behaviour
- [ ] Added / updated BDD scenarios for new or changed masking rules
- [ ] Added / updated `docs/rules.md` row for new or changed rules
- [ ] Regenerated `llms-full.txt` (`make llms-full`) if docs/ or llms.txt changed
- [ ] Regenerated `bench.txt` if a hot path changed
- [ ] `docs-writer`, `user-guide-reviewer`, `security-reviewer`, or `api-ergonomics-reviewer`
      agent consulted where the change warrants it; findings resolved in this PR

## Contributor compliance

- [ ] I have read [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- [ ] I have signed the [Contributor License Agreement](../CLA.md). The CLA Assistant bot will comment on this PR with signing instructions on first contribution — please sign there.
- [ ] I have read the [Code of Conduct](../CODE_OF_CONDUCT.md).
- [ ] My commits are signed (GPG or SSH) — see [CONTRIBUTING.md § Signing your commits](../CONTRIBUTING.md#signing-your-commits). Unsigned commits will fail the `main`-branch protection gate on merge.

## Notes for reviewers

<!-- Anything a reviewer should focus on or validate manually. -->
