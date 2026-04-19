# mask documentation

<sub>← [Back to project README](../README.md)</sub>

Deep-dive documentation for `github.com/axonops/mask`. The project [README](../README.md) gives the shop-front tour, the Quick Start, and the short behavioural contracts (thread safety, fail-closed, configuration). The files here hold the long tables and extension patterns that would overwhelm a landing page.

## Contents

| File | What you'll find |
|---|---|
| [`rules.md`](./rules.md) | The full rule catalogue — every built-in rule, across seven categories, with descriptions and `input → output` examples. |
| [`extending.md`](./extending.md) | Utility primitives (direct-call signatures, factory signatures, registered names) and five custom-rule patterns from one-liner factories to fully custom `RuleFunc` implementations. |
| [`hashing.md`](./hashing.md) | Dedicated guide for `deterministic_hash`: pseudonymisation vs anonymisation, the atomic salt-and-version contract, wire format, fail-closed behaviour, rotation procedure, supported algorithms, and the 64-bit truncation collision bound. |

## Elsewhere

- [pkg.go.dev/github.com/axonops/mask](https://pkg.go.dev/github.com/axonops/mask) — generated Go API reference.
- [`../llms.txt`](../llms.txt) and [`../llms-full.txt`](../llms-full.txt) — AI-assistant-oriented documentation bundle.
- [`../SECURITY.md`](../SECURITY.md) — threat model and coordinated disclosure.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — how to contribute.
