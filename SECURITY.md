# Security Policy

## Supported versions

The `mask` library follows a `v0.x` versioning scheme. Only the most recent `v0.x` minor release receives security fixes until `v1.0.0` stabilises the API.

| Version | Supported |
|---------|-----------|
| `v0.9.x` | Yes |
| Older | No |

## Threat model

`github.com/axonops/mask` is a pure-function string-masking library. Consumers embed it to redact personally identifying information, payment card data, and protected health information before logging, displaying, or persisting values.

**In scope:**

- Correctness of masking rules against their documented behaviour in [`docs/rules.md`](./docs/rules.md).
- Fail-closed behaviour: the library MUST NEVER return the original unmasked value when a rule cannot parse its input.
- No leakage of the unmasked input through error messages, panics, or logs.
- Unicode correctness: no byte-level splitting that could produce partially masked output.
- Thread safety under the documented contract (`Register` at init, `Apply` concurrent thereafter).
- Use of `crypto/sha256` for `deterministic_hash` — never MD5 or SHA-1.

**Salt rotation and versioning.** The `deterministic_hash` primitive takes its salt and version as a single atomic option — `WithKeyedSalt(salt, version)` — so keyed hashing cannot be half-configured. The version is emitted on the wire (`<algo>:<version>:<hex16>`) so downstream consumers can identify which salt generation a hash was computed with. Rotating the salt MUST coincide with changing the version — hashes computed with different versions are not comparable. An empty salt, a version that violates `^[A-Za-z0-9._-]{1,32}$`, or any other invalid argument is a fail-closed misconfiguration: every subsequent `Apply` returns `[REDACTED]` rather than producing a hash indistinguishable from the unsalted path. The salt itself is never logged, echoed in output, or exposed via `Describe`; the version, by design, is.

**Unsalted default.** The built-in `deterministic_hash` rule is registered out of the box with no salt, so that `mask.Apply("deterministic_hash", v)` works in smoke tests without configuration. The unsalted path is NOT pseudonymisation for GDPR Art. 4(5) or HIPAA purposes and MUST NOT be used in production. Re-register the rule with `DeterministicHashFunc(WithKeyedSalt(salt, version))`, or register `full_redact` under the same name if hashing is not required. The default exists for ergonomics; production use requires an explicit configuration step.

**Out of scope:**

- Guaranteeing anonymisation. `deterministic_hash` is **pseudonymisation**, not anonymisation — same input always produces the same output, so the hash remains a linkable identifier.
- Validating that callers use the correct rule for their data. The library masks; it does not detect.
- Protecting against memory disclosure through unrelated channels (process dumps, swap, etc.). Salt and version both live in process memory and may appear in core dumps or goroutine stacks.
- Side-channel timing analysis. Masking is not a cryptographic primitive.
- Managing salt-version registries, rotation policies, or re-hashing historical corpora on version change. The library emits the version; the operator decides when and how to rotate.

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
