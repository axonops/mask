<!-- markdownlint-disable MD041 -->
## Summary

<!-- 1-3 bullet points. What changed and why. Link the issue this closes. -->

Closes #

## Test plan

<!-- Tick the relevant boxes; leave N/A for items that do not apply. -->

- [ ] `make check` — unit + BDD tests, lint, formatter, tidy, coverage ≥ 90 %, vuln scan
- [ ] Added / updated unit tests for new behaviour
- [ ] Added / updated BDD scenarios for new masking rules
- [ ] Added / updated `docs/rules.md` row for new or changed rules
- [ ] Regenerated `llms-full.txt` (`make llms-full`) if docs/ or llms.txt changed
- [ ] Regenerated `bench.txt` if a hot path changed
- [ ] `docs-writer`, `user-guide-reviewer`, `security-reviewer`, or `api-ergonomics-reviewer`
      agent consulted where the change warrants it; findings resolved in this PR

## Notes for reviewers

<!-- Anything a reviewer should focus on or validate manually. -->
