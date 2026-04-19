# Deterministic hashing, salt, and version

<sub>← [Back to docs index](./README.md) · [Project README](../README.md)</sub>

`mask` ships a `deterministic_hash` rule and a matching factory, `DeterministicHashFunc`, for the cases where you need a **stable but opaque** identifier rather than a redacted one. This document explains what the primitive does, why it takes a salt and a version together, and how to operate it in production.

Start with the [`deterministic_hash` entry in the rule catalogue](./rules.md#utility-primitives-rules) for the one-line summary and an `input → output` example. This guide covers everything the catalogue does not.

## Contents

- [What deterministic hashing is (and is not)](#what-deterministic-hashing-is-and-is-not)
- [Unsalted vs keyed hashing](#unsalted-vs-keyed-hashing)
- [Why the salt and the version are a single atomic option](#why-the-salt-and-the-version-are-a-single-atomic-option)
- [Wire format](#wire-format)
- [Fail-closed contract](#fail-closed-contract)
- [Salt rotation](#salt-rotation)
- [Supported algorithms](#supported-algorithms)
- [Truncation and collision bound](#truncation-and-collision-bound)
- [Operational notes](#operational-notes)
- [When NOT to use this primitive](#when-not-to-use-this-primitive)
- [Further reading](#further-reading)

## What deterministic hashing is (and is not)

Deterministic hashing replaces a value with a short, fixed-length digest derived from the input. Given the same configuration and the same input, the output is always the same string. That property is the point: downstream consumers can **correlate records** (count unique users, join two log streams, detect duplicates) without seeing the original value.

This is **pseudonymisation**, not anonymisation. The distinction matters under GDPR Article 4(5) and similar regimes:

- The digest alone does not identify a natural person.
- Anyone holding both the input value and the current salt can recompute the digest and recover the link.
- Regulators therefore treat pseudonymised data as still personal data — with lighter handling requirements than raw PII, but handling requirements nonetheless.

If you need a value that **cannot** be reversed even by the owner of the salt, use [`FullRedact`](./rules.md#utility-primitives) or one of the domain rules that discards the original bytes entirely.

## Unsalted vs keyed hashing

There are two modes.

**Unsalted** — the default. Call `DeterministicHash` directly or register `DeterministicHashFunc()` with no options:

```go
mask.DeterministicHash("alice@example.com")
// → "sha256:ff8d9819fc0e12bf"
```

Unsalted output is portable across any process that knows the algorithm. Use it for low-stakes pseudonymisation where the set of possible inputs is large enough that an attacker cannot feasibly precompute the digests of every candidate.

**Keyed (HMAC)** — configured with `WithKeyedSalt(salt, version)`:

```go
import "os"

mask.DeterministicHashFunc(
    mask.WithKeyedSalt(os.Getenv("MASK_SALT"), "v1"),
)("alice@example.com")
// → "sha256:v1:<hex16>"
```

Keyed hashing drives an **HMAC** construction over the configured algorithm. HMAC uses the salt as a secret key so the digest depends on a value the attacker does not hold — an attacker who does not know the salt cannot precompute candidate digests, so even a small input space (e.g. an enum of 200 statuses, a five-digit account number) remains pseudonymised in practice. Use keyed mode whenever the input space is enumerable.

## Why the salt and the version are a single atomic option

`WithKeyedSalt(salt, version)` takes both arguments on the same call by design. A half-configured keyed hasher — salt present but version missing, or version set but salt empty — is a silent data incident waiting to happen, because the output would be byte-identical to the unsalted path and downstream consumers would treat two different populations of hashes as comparable.

The atomic option gives four load-bearing guarantees:

1. **You cannot accidentally ship an unkeyed hasher that looks keyed.** An empty salt is rejected.
2. **You cannot ship a keyed hasher without labelling its epoch.** An empty or malformed version is rejected.
3. **You cannot rotate one without the other.** There is no `SetSalt` / `SetVersion` pair to get out of step.
4. **Misconfiguration fails closed.** An invalid argument flips the rule into the `[REDACTED]` path — see [Fail-closed contract](#fail-closed-contract) — rather than producing a hash that looks like the previous epoch.

The version grammar is `^[A-Za-z0-9._-]{1,32}$`. Colons, whitespace, non-ASCII characters, shell metacharacters, and strings longer than 32 bytes are rejected: a colon would confuse the `<algo>:<version>:<hex>` wire format, and the length bound caps the on-the-wire prefix so a malformed config cannot blow up output size.

## Wire format

The output always starts with the algorithm prefix followed by a colon. Salted output inserts the version between the prefix and the digest:

| Mode | Format | Example |
|---|---|---|
| Unsalted | `<algo>:<hex16>` | `sha256:ff8d9819fc0e12bf` |
| Salted | `<algo>:<version>:<hex16>` | `sha256:v1:a1b2c3d4e5f6a7b8` |

`<hex16>` is the first 16 hexadecimal characters — 64 bits — of the digest. `<algo>` is one of `sha256`, `sha512`, `sha3-256`, `sha3-512`.

Downstream consumers comparing digests should always split on `:` and compare the **(algo, version, hex)** tuple. Two digests from different versions are not comparable even if the underlying value is the same — that is the point of the version label.

## Fail-closed contract

Every `mask` rule fails closed: on a malformed configuration or a malformed input, the library returns a safe placeholder rather than the original value. For deterministic hashing the rules are:

| Situation | Output |
|---|---|
| Valid unsalted call, any input | `<algo>:<hex16>` |
| Valid salted call, any input | `<algo>:<version>:<hex16>` |
| `WithKeyedSalt` with empty salt | `[REDACTED]` — every subsequent call |
| `WithKeyedSalt` with version not matching the grammar | `[REDACTED]` — every subsequent call |

The `[REDACTED]` marker is the same string the `full_redact` primitive emits. If you see it appearing in production logs where you expected hashes, the rule was misconfigured at registration time. There is no recovery path other than re-registering the rule with valid arguments; the misconfigured config is captured at factory time and frozen.

## Salt rotation

Rotate the salt when any of the following happens:

- **Time-based policy.** E.g. quarterly or annually, to limit the correlation window available to a compromised salt.
- **Compromise.** The salt has leaked or is suspected of leaking.
- **Scope change.** You are onboarding a new downstream consumer that must not be able to join against the old population.

**The rotation procedure is always the same: change the salt AND the version in the same deploy.** Two populations of hashes will now coexist — the old ones with `version=v1`, the new ones with `version=v2` — and downstream consumers can decide whether to migrate, dual-read, or drop the old population.

```go
// Before rotation
mask.WithKeyedSalt(os.Getenv("MASK_SALT_V1"), "v1")

// After rotation — new salt, new version, same deploy
mask.WithKeyedSalt(os.Getenv("MASK_SALT_V2"), "v2")
```

Never reuse a version label with a different salt. The version is the audit trail that proves a given digest was produced under a given keying epoch; reusing labels destroys that property.

## Supported algorithms

Select the algorithm with `WithAlgorithm`:

| Constant | On-wire prefix | Full digest width |
|---|---|---|
| `mask.SHA256` (default) | `sha256` | 256 bits |
| `mask.SHA512` | `sha512` | 512 bits |
| `mask.SHA3_256` | `sha3-256` | 256 bits |
| `mask.SHA3_512` | `sha3-512` | 512 bits |

Regardless of algorithm, the output is always truncated to the first 64 bits on the wire — see [Truncation and collision bound](#truncation-and-collision-bound). The algorithm choice changes the cryptographic construction and the on-wire prefix, not the output length.

```go
mask.DeterministicHashFunc(
    mask.WithAlgorithm(mask.SHA3_256),
    mask.WithKeyedSalt(os.Getenv("MASK_SALT"), "v1"),
)("alice@example.com")
// → "sha3-256:v1:<hex16>"
```

MD5 and SHA-1 are **not** supported and will not be added — both are broken for collision resistance and have no place in a masking library. Values outside the supported enum passed to `WithAlgorithm` silently clamp to `SHA256` so the rule can never panic on a bad input; `HashAlgorithm.String()` deliberately does *not* clamp — it returns `HashAlgorithm(N)` for the raw integer so a programmer error is visible rather than papered over.

For salt rotation, the **(algo, version)** tuple together identifies a keying epoch. Changing either means the digests are no longer comparable across populations.

## Truncation and collision bound

The output always truncates the digest to the first 16 hex characters (8 bytes, 64 bits). That makes the output compact enough for logs and index keys while remaining long enough to be a useful identifier.

The price is the birthday bound: over roughly 2<sup>32</sup> (~4.3 billion) **distinct** inputs you expect to see a collision — two different inputs producing the same digest. That is usually not a problem:

- For most log streams, the distinct-input population is far below 2<sup>32</sup>.
- For uniqueness counting, a one-in-four-billion collision rarely moves a dashboard.
- For correlation across systems, the (algo, version, hex16) tuple plus some other field (timestamp, tenant id) makes the joined key unique in practice.

If your use case cannot tolerate that bound — e.g. a primary-key-like join across a population above ~10<sup>9</sup> distinct values — do not use `deterministic_hash` as the join key. Use a real identifier with reference-integrity guarantees instead.

## Operational notes

- **Inputs are hashed as their raw UTF-8 byte sequence.** No Unicode normalisation happens inside the library. If your input space mixes NFC and NFD (e.g. accented characters from different sources), normalise before hashing or the same visible string will produce two different digests.
- **The salt is never logged, returned in errors, or exposed via `mask.Describe`.** The version is, by design — it is part of the wire format and part of the audit trail. `mask.Describe("deterministic_hash")` returns the rule's category and description; it never returns the salt, and it never returns the version of a caller's custom-registered hashing rule either — inspect your own registration call site if you need to confirm which epoch is in force.
- **Salt storage is the caller's responsibility.** The library accepts an in-memory `string`. Inject it from a secrets manager, environment variable, or the platform's managed-identity construct — not from a checked-in config file. Protect the process (core-dump policy, memory-read permissions); the library cannot protect a secret that the kernel hands to any debugger.
- **Rule registration is not concurrent-safe with `Apply`.** Register deterministic-hash rules during program initialisation; after that, `Apply` is safe for concurrent use. See the README's [Thread Safety](../README.md#-thread-safety) section.
- **Config is captured at factory time.** `DeterministicHashFunc(opts...)` returns a `RuleFunc` with a frozen config snapshot. Mutating the options slice afterwards has no effect on the returned function.

## When NOT to use this primitive

- **Authentication / password storage.** Use a password-specific KDF: `argon2id` or `scrypt` (memory-hard) or `bcrypt` (work-factor-hard). `deterministic_hash` is designed for pseudonymisation, not verification — it is a single-pass HMAC, which is trivially brute-forced for password-sized secrets, and the 64-bit truncation on the wire compounds the problem.
- **Cryptographic commitment or MAC for message integrity.** Use the full `crypto/hmac` output directly, not the truncated form — a 64-bit tag provides only ~32 bits of security against forgery by the birthday bound.
- **Regulated data where reversibility under salt compromise is unacceptable.** GDPR/PCI/HIPAA may classify pseudonymised data differently from anonymised data, but the underlying reality is that anyone who gets the salt can reverse the mapping. If the regulator asks for unlinkability, full redaction is the only answer — use `full_redact` or one of the domain rules that discards the original bytes.
- **Input spaces you cannot risk an attacker enumerating.** Even with keyed hashing, if the salt leaks, a small input space is fully recoverable. Plan rotation (above) accordingly.

## Further reading

- [Rule catalogue — `deterministic_hash`](./rules.md#utility-primitives-rules) — one-line summary and `input → output` example.
- [Extending mask — pattern 4, deterministic hashing with salt and version](./extending.md#4-deterministic-hashing-with-salt-and-version) — the canonical registration snippet.
- [`../SECURITY.md`](../SECURITY.md) — threat model, salt-rotation policy, and coordinated disclosure process.
- [pkg.go.dev — `DeterministicHashFunc`](https://pkg.go.dev/github.com/axonops/mask#DeterministicHashFunc) — API reference for the factory.
- [pkg.go.dev — `WithKeyedSalt`](https://pkg.go.dev/github.com/axonops/mask#WithKeyedSalt) — option grammar and validation rules.
