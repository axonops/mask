# Changelog

All notable changes to `github.com/axonops/mask` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial public release in progress. No versioned releases yet.

### Added

- Project scaffolding: Go module, Makefile, `.golangci.yml`, GoReleaser configuration.
- Continuous integration workflow covering format check, vet, lint, unit and BDD tests, coverage, module tidy, security scan, and cross-platform builds (`linux/amd64`, `darwin/arm64`, `windows/amd64`).
- CI-only release workflow with dry-run support — no local tagging permitted.
- Dependabot configuration for weekly Go module and GitHub Actions updates.
- `CONTRIBUTING.md` and `SECURITY.md`.

[Unreleased]: https://github.com/axonops/mask/compare/HEAD
