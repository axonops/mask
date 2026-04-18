# Security Policy

## Supported versions

The `mask` library is currently in pre-release (`v0.x`). Only the most recent `v0.x` minor release receives security fixes until `v1.0.0` stabilises the API.

| Version | Supported |
|---------|-----------|
| `v0.9.x` | Yes |
| Older | No |

## Threat model

`github.com/axonops/mask` is a pure-function string-masking library. Consumers embed it to redact personally identifying information, payment card data, and protected health information before logging, displaying, or persisting values.

**In scope:**

- Correctness of masking rules against the spec in `docs/v0.9.0-requirements.md`.
- Fail-closed behaviour: the library MUST NEVER return the original unmasked value when a rule cannot parse its input.
- No leakage of the unmasked input through error messages, panics, or logs.
- Unicode correctness: no byte-level splitting that could produce partially masked output.
- Thread safety under the documented contract (`Register` at init, `Apply` concurrent thereafter).
- Use of `crypto/sha256` for `deterministic_hash` — never MD5 or SHA-1.

**Out of scope:**

- Guaranteeing anonymisation. `deterministic_hash` is **pseudonymisation**, not anonymisation — same input always produces the same output, so the hash remains a linkable identifier.
- Validating that callers use the correct rule for their data. The library masks; it does not detect.
- Protecting against memory disclosure through unrelated channels (process dumps, swap, etc.).
- Side-channel timing analysis. Masking is not a cryptographic primitive.

## Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub Security Advisories:

https://github.com/axonops/mask/security/advisories/new

Include:

- A description of the issue and its impact.
- Steps to reproduce (input, expected output, actual output).
- The library version and Go version you observed it with.
- Any suggested mitigation.

We aim to acknowledge reports within three working days and to issue a fix or mitigation guidance within 30 days for confirmed high-severity issues.

Please do **not** file a public GitHub issue for vulnerabilities.

## Disclosure policy

Once a fix is released, the advisory is published on GitHub and the fix is referenced in the `CHANGELOG.md` entry under the relevant release.
