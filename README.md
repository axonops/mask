<div align="center">
  <img src=".github/images/logo-readme.png" alt="mask" width="128">

  # mask

  **String Masking for Go Services — PII, PCI, PHI, zero dependencies**

  [![CI](https://github.com/axonops/mask/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/axonops/mask/actions/workflows/ci.yml)
  [![Go Reference](https://pkg.go.dev/badge/github.com/axonops/mask.svg)](https://pkg.go.dev/github.com/axonops/mask)
  [![Go Report Card](https://goreportcard.com/badge/github.com/axonops/mask)](https://goreportcard.com/report/github.com/axonops/mask)
  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
  ![Status](https://img.shields.io/badge/status-pre--release-orange)

  [🚀 Quick Start](#-quick-start) | [✨ Features](#-key-features) | [📚 Built-in Rules](#-built-in-rules) | [🛠 Primitives](#-utility-primitives) | [📖 Docs](./docs/) | [📡 API Reference](https://pkg.go.dev/github.com/axonops/mask)
</div>

---

**Table of contents**

- [⚠️ Status](#-status)
- [🔍 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [❓ Why mask?](#-why-mask)
- [🚀 Quick Start](#-quick-start)
- [📚 Built-in Rules](#-built-in-rules) — full catalogue in [`docs/rules.md`](./docs/rules.md)
- [🛠 Utility Primitives](#-utility-primitives) — full reference in [`docs/extending.md`](./docs/extending.md)
- [🧵 Thread Safety](#-thread-safety)
- [🛡 Fail Closed](#-fail-closed)
- [🔧 Configuration](#-configuration)
- [🎯 Custom Rules](#-custom-rules) — five patterns in [`docs/extending.md`](./docs/extending.md)
- [🌍 Regulatory Context](#-regulatory-context)
- [📖 API Reference](#-api-reference)
- [🤖 For AI Assistants](#-for-ai-assistants)
- [🤝 Contributing](#-contributing)
- [🔐 Security](#-security)
- [📄 Licence](#-licence)

---

## ⚠ Status

`mask` is pre-release software (`v0.x`). The public API may change between minor versions until `v1.0.0`. Pin the exact version in your `go.mod` and review the [CHANGELOG](./CHANGELOG.md) before upgrading.

## 🔍 Overview

> **Stop leaking PII through half-baked regexes.** `mask` is the drop-in redaction library every Go service on the hot path of a log, trace, or audit stream was missing. One import. One call. The original value **never** reaches the outside world.

Hand-rolled regexes work on the inputs you tested. They leak on the ones you didn't — the email with a `+` alias, the PAN with an extra space, the phone number from a country you forgot existed, the unicode address your byte-indexed slice chopped mid-character. `mask` is built so reality can disagree with the pattern and the library **still fails safe**.

### What you get, out of the box

- 🎯 **Format-aware by design** — preserves PAN separators, email domains, IBAN check digits, phone country codes, and geographic precision so masked fields stay useful for debugging, diffing, and support tickets.
- 🛡 **Fail-closed, always** — unknown rule? `[REDACTED]`. Malformed input? Same-length mask. The original value is **never** echoed back. Not even once.
- 🌍 **Unicode-safe from day one** — rune-aware so multi-byte UTF-8 is never split mid-character. International names, CJK addresses, emoji in free-text — all handled.
- ⚡ **Zero runtime dependencies** — stdlib only. No goroutines. No config files. No transitive-dependency CVEs.
- 🧵 **Thread-safe like the stdlib** — register at init, apply concurrently forever after. Same contract as `database/sql.Register`.

### See it in action

```go
mask.Apply("payment_card_pan", "4111-1111-1111-1111") // "4111-11**-****-1111"
mask.Apply("email_address",    "alice@example.com")   // "a****@example.com"
mask.Apply("us_ssn",           "123-45-6789")         // "***-**-6789"
mask.Apply("iban",             "GB82WEST12345698765432") // "GB82**************5432"
mask.Apply("no_such_rule",     "anything")            // "[REDACTED]"   ← fail closed
```

> **60+ built-in rules across seven categories, covering identifiers in more than a dozen jurisdictions.** PCI DSS display modes for PANs. HIPAA pseudonymisation caveats for clinical identifiers. GDPR Art. 4(5) salted hashing for user IDs. Every regulation-aware rule is documented next to the code that delivers it — no spelunking required.

---

## ✨ Key Features

<div align="center">

| Feature | Description | Docs |
|---|---|---|
| 📋 Rich built-in rule catalogue | 60+ rules across identity, financial, health, technology, telecom, and country-specific categories | [Built-in Rules](#-built-in-rules) |
| 🧩 Composable primitives | `KeepFirstN`, `KeepLastN`, `KeepFirstLast`, `DeterministicHash`, `ReplaceRegex`, `ReducePrecision`, and more — every primitive is exposed both as a direct-call helper and as a factory `RuleFunc` | [Primitives](#-utility-primitives) |
| 🌍 Unicode correct | Rune-aware masking for international names, addresses, and free-text content | [Unicode correctness](#unicode-correctness) |
| 🛡 Fail closed | Unknown rule returns `[REDACTED]`; malformed input returns a same-length mask; the original value is never echoed | [Fail Closed](#-fail-closed) |
| 🔐 PCI / HIPAA / GDPR aware | Jurisdiction-qualified names and regulation references in the catalogue | [Regulatory Context](#-regulatory-context) |
| ⚡ Zero dependencies | stdlib only at runtime | — |
| 🧵 Thread-safe after init | Register at startup; apply concurrently from any number of goroutines afterwards | [Thread Safety](#-thread-safety) |
| 🔧 Configurable mask character | Global override via `SetMaskChar`; per-instance via `WithMaskChar` | [Configuration](#-configuration) |
| 🧪 BDD-first testing | Every rule has a Gherkin feature file; consumer-language scenarios pin the contract | [Testing](./CONTRIBUTING.md#testing) |
| 🎯 Custom rules in three lines | `mask.Register("my_rule", func(v string) string { ... })` — then use it like any built-in | [Custom Rules](#-custom-rules) |

</div>

## ❓ Why mask?

> **Because `strings.Replace` fails silently, and your production logs are the wrong place to find out.**

Every Go project starts with a one-line regex and a TODO. Three outages and an audit later, it becomes a 400-line helper package nobody understands. `mask` is what that package wants to be when it grows up — fewer bugs, broader coverage, unicode-correct by default, and a fail-closed contract you can actually rely on.

<div align="center">

| Approach | Format-aware | Unicode-correct | Built-in catalogue | Fails closed |
|---|---|---|---|---|
| Ad-hoc `strings.Replace` | No | N/A | No | No — original leaks through |
| Hand-rolled regex | Partial — author-dependent | Partial | No | No — non-match returns original |
| **`github.com/axonops/mask`** | **Yes** — 60+ format-specific rules | **Yes** — rune-aware by default | **Yes** — identity, financial, health, tech, telecom, country-specific | **Yes** — unknown rule ⇒ `[REDACTED]`, malformed input ⇒ same-length mask |

</div>

## 🚀 Quick Start

### Install

```sh
go get github.com/axonops/mask
```

Requires Go 1.26 or later.

### Hello world

```go
package main

import (
	"fmt"

	"github.com/axonops/mask"
)

func main() {
	fmt.Println(mask.Apply("email_address", "alice@example.com"))
	// Output: a****@example.com
}
```

### Per-instance masker with a custom mask character

```go
m := mask.New(mask.WithMaskChar('#'))
fmt.Println(m.Apply("email_address", "alice@example.com"))
// Output: a####@example.com
```

### Registering a custom rule

```go
func init() {
	_ = mask.Register("employee_id", mask.KeepFirstNFunc(9))
}

// mask.Apply("employee_id", "EMP-ACME-12345") → "EMP-ACME-*****"
```

### Composing primitives directly

```go
// Keep the first and last 4 runes, mask the middle — one-off, no registration.
out := mask.KeepFirstLast("SensitiveData", 4, 4, '*')
// out == "Sens*****Data"
```

### Discovering rules at runtime

```go
for _, name := range mask.Rules() {
	info, _ := mask.Describe(name)
	fmt.Printf("%-25s %-10s %s\n", name, info.Category, info.Description)
}
```

### Common tasks

If you are looking for the right rule for a common field, start here.

| I want to mask... | Use rule | Example |
|---|---|---|
| An email address | [`email_address`](./docs/rules.md#identity) | `alice@example.com` → `a****@example.com` |
| A credit card number | [`payment_card_pan`](./docs/rules.md#financial) | `4111-1111-1111-1111` → `4111-11**-****-1111` |
| A US Social Security Number | [`us_ssn`](./docs/rules.md#country-specific-identity) | `123-45-6789` → `***-**-6789` |
| A phone number | [`phone_number`](./docs/rules.md#telecom-and-location) | `+44 7911 123456` → `+44 **** **3456` |
| An IPv4 address | [`ipv4_address`](./docs/rules.md#technology) | `192.168.1.42` → `192.168.*.*` |
| A UUID | [`uuid`](./docs/rules.md#technology) | `550e8400-e29b-41d4-a716-446655440000` → `550e8400-****-****-****-********0000` |
| An IBAN | [`iban`](./docs/rules.md#financial) | `GB82WEST12345698765432` → `GB82**************5432` |
| A medical record number | [`medical_record_number`](./docs/rules.md#health) | `MRN-123456789` → `MRN-*****6789` |
| A JWT | [`jwt_token`](./docs/rules.md#technology) | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc` → `eyJh****.****.****.` |
| A UK postcode | [`postal_code`](./docs/rules.md#telecom-and-location) | `SW1A 2AA` → `SW1A ***` |
| A UK National Insurance Number | [`uk_nino`](./docs/rules.md#country-specific-identity) | `AB123456C` → `AB******C` |
| Any free-text secret | [`full_redact`](./docs/rules.md#utility-primitives-rules) | anything → `[REDACTED]` |
| A password field | [`password`](./docs/rules.md#technology) | any non-empty value → `********` |
| An internal / bespoke ID | see [Custom rules](#-custom-rules) | compose with `KeepFirstN`, `KeepLastN`, `KeepFirstLast` |

For the full catalogue, see [Built-in Rules](#-built-in-rules) or call `mask.Rules()` at runtime.

## 📚 Built-in Rules

**60+ rules registered out of the box** across seven categories. Every rule is fail-closed, honours the configured mask character, and has a concrete `input → output` example in its godoc.

| Category | Examples |
|---|---|
| Utility primitives | `full_redact`, `same_length_mask`, `nullify`, `deterministic_hash` |
| Identity — global | `email_address`, `person_name`, `date_of_birth`, `passport_number` |
| Identity — country-specific | `us_ssn`, `uk_nino`, `in_aadhaar`, `br_cpf`, `mx_curp` |
| Financial | `payment_card_pan`, `iban`, `swift_bic`, `uk_sort_code` |
| Health | `medical_record_number`, `diagnosis_code`, `prescription_text` |
| Technology | `ipv4_address`, `url`, `jwt_token`, `uuid`, `password` |
| Telecom + location | `phone_number`, `imei`, `msisdn`, `postal_code`, `geo_coordinates` |

👉 **Full catalogue with `input → output` examples for every rule: [`docs/rules.md`](./docs/rules.md)**

Or discover them at runtime:

```go
for _, name := range mask.Rules() {
    info, _ := mask.Describe(name)
    fmt.Printf("%-25s %-10s %s\n", name, info.Category, info.Description)
}
```

> **💡 Missing a rule?** If your organisation masks a data type that isn't in this catalogue — a national identifier, a financial code, a telecom format, a sector-specific identifier — **[open an issue](https://github.com/axonops/mask/issues/new?title=New%20built-in%20rule%3A%20%3Cname%3E&labels=rule-request)** and tell us what it looks like. The catalogue grew from real services; we'd rather add a rule once than have every consumer hand-roll it.

## 🛠 Utility Primitives

Every primitive is exposed twice — as a Go helper (call it directly inside a custom `RuleFunc`) and as a factory (pass it to `Register`). Three the quick ones:

```go
mask.KeepFirstN("Sensitive", 4, '*')          // "Sens*****"
mask.KeepFirstLast("SensitiveData", 4, 4, '*') // "Sens*****Data"

_ = mask.Register("employee_id", mask.KeepFirstNFunc(9)) // factory
```

👉 **Full primitive table (direct-call signatures, factory signatures, registered rule names) and custom-rule patterns: [`docs/extending.md`](./docs/extending.md)**

## 🧵 Thread Safety

`Register` (both the package-level function and `Masker.Register`) MUST NOT be called concurrently with `Apply`. The contract matches `database/sql.Register`:

- Call `Register` during program initialisation, before any goroutine starts calling `Apply`.
- Once every Register call has returned, the registry is read-only and `Apply` is safe for concurrent use by any number of goroutines.
- Built-in rules are stateless pure functions. Custom `RuleFunc` implementations MUST satisfy the same contract.

Violating this contract is a data race and will be reported by the Go race detector (`go test -race`). The library does NOT `defer recover()` around custom `RuleFunc` calls — a panic in a custom rule propagates out of `Apply`, by design. Custom rules MUST NOT panic; treat a panic as a programmer error and fix it at source.

```go
// Correct — register once at init time.
func init() {
	_ = mask.Register("my_rule", myMaskingFunc)
}

// Correct — isolated per-instance registry, no concurrency concerns.
m := mask.New()
_ = m.Register("tenant_rule", tenantMaskingFunc)
```

## 🛡 Fail Closed

`mask.Apply` always returns a string and never an error.

- Unknown rule name → `[REDACTED]` (the value of `mask.FullRedactMarker`).
- Known rule, malformed input → a same-length mask of the configured mask character.
- Empty input → empty output (except for full-redact rules, which always return `[REDACTED]`).

This contract is uniform across every rule in the catalogue. Consumers can rely on it without per-rule knowledge.

### Unicode correctness

Every built-in rule walks the input as runes, not bytes. Multi-byte UTF-8 sequences (CJK street addresses, emoji in free-text fields, accented Latin letters stored as precomposed code points) are never split mid-character, and output is guaranteed to be valid UTF-8. This matters for dashboards, log viewers, and downstream tooling that may itself panic on invalid UTF-8. Decomposed forms (for example `e` followed by `U+0301` combining acute) are masked rune-by-rune — the library does not run full grapheme-cluster segmentation; if your data stores decomposed diacritics and you need the base letter masked together with its combining mark, normalise to NFC before masking.

## 🔧 Configuration

### Mask character

The default mask character is `*`. Override it globally (for the package-level registry) or per instance.

```go
// Global — mutates the package-level registry.
mask.SetMaskChar('#')

// Per instance — isolated to this Masker only.
m := mask.New(mask.WithMaskChar('#'))
```

Built-in rules read the configured character at apply time, so changes are picked up on the next call. The `password` rule honours the configured character for the 8-rune mask output.

> **Factory vs. closure for custom rules.** Factories such as `KeepFirstNFunc`, `KeepLastNFunc`, and `KeepFirstLastFunc` capture `DefaultMaskChar` at construction time and ignore later `SetMaskChar` / `WithMaskChar` overrides. If your custom rule must react to the configured character, register a closure that reads `m.MaskChar()` (or the package-level `mask.MaskChar()`) at apply time. See [`docs/extending.md`](./docs/extending.md#3-honour-per-instance-mask-character-config) for the pattern.

### Deterministic hashing (salt and version)

`deterministic_hash` is registered by default with no salt. For production pseudonymisation you MUST configure keyed hashing via `WithKeyedSalt(salt, version)` — the salt and version are validated atomically, so you cannot accidentally ship with one half configured:

```go
m := mask.New()
_ = m.Register(
	"user_id",
	mask.DeterministicHashFunc(
		mask.WithKeyedSalt(os.Getenv("MASK_SALT"), "v1"),
	),
)
```

Do not hard-code the salt — load it from a secret store or environment variable. Rotate the salt and bump the version together; downstream consumers can tell hashes from different generations apart by the `<algo>:<version>:<hex16>` output shape. The unsalted path (`DeterministicHashFunc()` with no options) emits `<algo>:<hex16>` and is only suitable for development and smoke tests. See [SECURITY.md](./SECURITY.md) for the full salt-rotation and versioning policy.

## 🎯 Custom Rules

A custom rule is a `func(string) string` registered under a name. The most common shapes are already one-liners:

```go
func init() {
    // Keep the first N runes, mask the rest.
    _ = mask.Register("employee_id", mask.KeepFirstNFunc(9))

    // Keep the first and last N runes — typical account-number shape.
    _ = mask.Register("account_id", mask.KeepFirstLastFunc(3, 4))

    // Keep the last N runes.
    _ = mask.Register("internal_ref", mask.KeepLastNFunc(4))
}
// mask.Apply("employee_id", "EMP-ACME-12345") → "EMP-ACME-*****"
// mask.Apply("account_id",  "ACME-1234-5678") → "ACM********5678"
// mask.Apply("internal_ref","REF-2025-001234") → "***********1234"
```

For the other four patterns — closures, per-instance mask-char config, deterministic hashing with salt + version, fully custom `RuleFunc` — see [`docs/extending.md`](./docs/extending.md).

## 🌍 Regulatory Context

Masking is one control in a broader compliance strategy — it is not a substitute for access control, encryption, or retention policy. The table below summarises where the library fits against common regulatory regimes. See [SECURITY.md](./SECURITY.md) for the full threat model.

| Use case | Fit | Notes |
|---|---|---|
| PCI DSS display modes for PAN | Yes | `payment_card_pan`, `payment_card_pan_first6`, `payment_card_pan_last4` match the three common display modes. `payment_card_cvv` is same-length — CVV is Sensitive Authentication Data that MUST NOT be retained post-authorisation. |
| HIPAA Safe Harbor de-identification | No | Identifier rules (including `medical_record_number`, `health_plan_beneficiary_id`) are pseudonymisation, not de-identification. Retained trailing digits combined with a date or ZIP remain re-identifiable. Register `full_redact` under the same rule name if you need Safe Harbor. |
| GDPR pseudonymisation (Art. 4(5)) | Yes, with configured salt | `deterministic_hash` with `WithKeyedSalt(salt, version)` meets the GDPR definition. Salt management, rotation, and additional access controls are the operator's responsibility. |
| GDPR anonymisation | No | No rule in this library is anonymisation — all preserved-window rules leak structure, and `deterministic_hash` is reversible given the input space. |

## 📖 API Reference

Full API documentation: [pkg.go.dev/github.com/axonops/mask](https://pkg.go.dev/github.com/axonops/mask).

A compact summary:

| Function | Purpose |
|---|---|
| `mask.Apply(name, value)` | Apply a registered rule to a value. |
| `mask.Register(name, fn)` | Register a custom rule on the package-level registry. |
| `mask.Rules()` | Return the names of every registered rule. |
| `mask.Describe(name)` | Return the `RuleInfo` for a rule (name, category, jurisdiction, description). |
| `mask.SetMaskChar(c)` | Change the default mask character on the package-level registry. |
| `mask.New(opts...)` | Construct an isolated `Masker`. Options: `mask.WithMaskChar`. |
| `mask.HasRule(name)` | Check whether a rule is registered. |
| `mask.DescribeAll()` | Return the `RuleInfo` metadata for every registered rule. |
| `mask.MaskChar()` | Return the mask rune currently configured on the package-level registry. |

## 🤖 For AI Assistants

Two files at the repository root are published specifically for AI coding assistants and automated documentation crawlers:

- [`llms.txt`](./llms.txt) — a concise index (~1000 words) following the [llmstxt.org](https://llmstxt.org/) specification, with the core concepts, API surface, integration flow, and common mistakes.
- [`llms-full.txt`](./llms-full.txt) — the complete documentation corpus (`llms.txt` + README + godoc + contributing + security + requirements + generated godoc reference) concatenated in a stable order. Regenerated via `make llms-full`; CI fails if it drifts.

## 🤝 Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for branching, commit, PR, and release guidance. Every masking rule requires a unit test AND a BDD scenario; coverage is held at 90% or higher.

## 🔐 Security

See [SECURITY.md](./SECURITY.md) for the threat model, salt-rotation policy, and coordinated disclosure procedure. Security-sensitive issues should be reported privately per that document.

## 📄 Licence

[Apache Licence 2.0](./LICENSE) — Copyright © 2026 AxonOps Limited.

---

<div align="center">
  <sub>Made with ❤️ by <a href="https://axonops.com">AxonOps</a></sub>
</div>
