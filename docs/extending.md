# Extending mask

<sub>← [Back to README](../README.md) · [Rule Catalogue](./rules.md) · **Extending**</sub>

Two concerns, one page:

- **[Utility Primitives](#utility-primitives)** — the composable building blocks exposed both as Go helper functions and as factory `RuleFunc`s.
- **[Custom Rules](#custom-rules)** — five patterns for registering your own rule on top of those primitives, from one-liner factories to fully custom `RuleFunc` implementations.

## Table of contents

- [Utility Primitives](#utility-primitives)
  - [Direct-call examples](#direct-call-examples)
  - [Factory examples](#factory-examples)
- [Custom Rules](#custom-rules)
  - [1. Use a factory directly](#1-use-a-factory-directly)
  - [2. Compose a primitive via a closure](#2-compose-a-primitive-via-a-closure)
  - [3. Honour per-instance mask-character config](#3-honour-per-instance-mask-character-config)
  - [4. Deterministic hashing with salt and version](#4-deterministic-hashing-with-salt-and-version)
  - [5. A fully custom `RuleFunc`](#5-a-fully-custom-rulefunc)
  - [Scoping: package-level vs per-instance](#scoping-package-level-vs-per-instance)
  - [Compile-time safety](#compile-time-safety)

## Utility Primitives

Every primitive is exposed both as a Go helper function (call it directly inside a custom `RuleFunc`) and as a factory returning a `RuleFunc` ready for `Register`. Four of them are also registered as named rules out of the box. Direct-call helpers accept the mask rune as a parameter; factories capture `DefaultMaskChar` at construction time.

| Primitive | Direct-call signature | Factory | Registered rule |
|---|---|---|---|
| `FullRedact` | `FullRedact(v string) string` | — | `full_redact` |
| `Nullify` | `Nullify(v string) string` | — | `nullify` |
| `SameLengthMask` | `SameLengthMask(v string, c rune) string` | — | `same_length_mask` |
| `KeepFirstN` | `KeepFirstN(v string, n int, c rune) string` | `KeepFirstNFunc(n int) RuleFunc` | — |
| `KeepLastN` | `KeepLastN(v string, n int, c rune) string` | `KeepLastNFunc(n int) RuleFunc` | — |
| `KeepFirstLast` | `KeepFirstLast(v string, first, last int, c rune) string` | `KeepFirstLastFunc(first, last int) RuleFunc` | — |
| `TruncateVisible` | `TruncateVisible(v string, n int) string` | `TruncateVisibleFunc(n int) RuleFunc` | — |
| `PreserveDelimiters` | `PreserveDelimiters(v, delim string, c rune) string` | `PreserveDelimitersFunc(delim string) RuleFunc` | — |
| `ReplaceRegex` | `ReplaceRegex(v, pattern, replacement string) (string, error)` | `ReplaceRegexFunc(pattern, replacement string) (RuleFunc, error)` | — |
| `ReducePrecision` | `ReducePrecision(v string, decimals int, c rune) string` | `ReducePrecisionFunc(decimals int) RuleFunc` | — |
| `DeterministicHash` | `DeterministicHash(v string) string` | `DeterministicHashFunc(opts ...HashOption) RuleFunc` | `deterministic_hash` |
| `FixedReplacementFunc` | — | `FixedReplacementFunc(s string) RuleFunc` | — |

> Factories (`KeepFirstNFunc`, `ReplaceRegexFunc`, etc.) capture `DefaultMaskChar` at construction and ignore per-instance overrides. Callers who need per-instance mask-character customisation should register a closure that captures the desired mask rune at construction time rather than using a factory.

### Direct-call examples

```go
mask.FullRedact("anything")                               // → "[REDACTED]"
mask.SameLengthMask("Hello", '*')                         // → "*****"
mask.KeepFirstN("Sensitive", 4, '*')                      // → "Sens*****"
mask.KeepLastN("Sensitive", 4, '*')                       // → "*****tive"
mask.KeepFirstLast("SensitiveData", 4, 4, '*')            // → "Sens*****Data"
mask.TruncateVisible("Sensitive", 4)                      // → "Sens"    (not fail-closed — composition only)
mask.PreserveDelimiters("ab-cd", "-", '*')                // → "**-**"
mask.ReducePrecision("37.7749", 2, '*')                   // → "37.77**"
mask.DeterministicHash("alice@example.com")               // → "sha256:ff8d9819fc0e12bf"
```

### Factory examples

```go
_ = mask.Register("employee_id",        mask.KeepFirstNFunc(9))
_ = mask.Register("internal_ref",       mask.KeepLastNFunc(4))
_ = mask.Register("warehouse_id",       mask.KeepFirstLastFunc(3, 3))
_ = mask.Register("latitude_low_res",   mask.ReducePrecisionFunc(2))
_ = mask.Register("internal_token",     mask.FixedReplacementFunc("[HIDDEN]"))

regex, _ := mask.ReplaceRegexFunc(`\d{6,}`, "[REDACTED]")
_ = mask.Register("free_text_digits",   regex)
```

See [pkg.go.dev](https://pkg.go.dev/github.com/axonops/mask) for the full API reference.

## Custom Rules

Registering your own rule is the extension point when the built-in catalogue does not cover a format. A rule is just a `RuleFunc` — `func(string) string` — registered under a name and then called via `Apply`. Most real rules compose one of the utility primitives; rarely do you need to write a masking algorithm from scratch.

The five patterns below cover the situations you're likely to hit, in rough order of simplicity.

### 1. Use a factory directly

The `…Func` factories turn a primitive into a ready-to-register `RuleFunc` with no closure required. Best when the masking shape is exactly one primitive.

**Keep the first N runes** — masks everything after a fixed prefix.

```go
_ = mask.Register("employee_id", mask.KeepFirstNFunc(9))
// mask.Apply("employee_id", "EMP-ACME-12345") → "EMP-ACME-*****"
```

**Keep the last N runes** — masks everything before a fixed suffix.

```go
_ = mask.Register("internal_ref", mask.KeepLastNFunc(4))
// mask.Apply("internal_ref", "REF-2025-001234") → "***********1234"
```

**Keep first and last N runes** — masks the middle, typical for account numbers or long identifiers.

```go
_ = mask.Register("warehouse_id", mask.KeepFirstLastFunc(3, 3))
// mask.Apply("warehouse_id", "WH-NORTH-DOCK-9876") → "WH-************876"
```

**Regex-based masking** — replace every match of a pattern with a fixed string. Useful when the secret has a predictable shape surrounded by context bytes you want to keep, or when you want a one-off rule without walking the string yourself.

```go
// Redact any 6-or-more-digit run embedded in free text.
r, err := mask.ReplaceRegexFunc(`\d{6,}`, "[REDACTED]")
if err != nil {
	log.Fatalf("compile regex: %v", err)
}
_ = mask.Register("free_text_digits", r)

// mask.Apply("free_text_digits", "Order #1234567 shipped")
//   → "Order #[REDACTED] shipped"
```

`ReplaceRegexFunc` returns `(nil, err)` on an invalid pattern — compile it once at init and panic fatally if it's wrong.

Other factories in the same shape: `TruncateVisibleFunc(n)`, `PreserveDelimitersFunc(delim)`, `ReducePrecisionFunc(decimals)`, `FixedReplacementFunc(s)`, `DeterministicHashFunc(opts...)`.

### 2. Compose a primitive via a closure

Reach for a closure when you want to pre-process the input (trim whitespace, normalise case, split on a delimiter, etc.) before delegating to a primitive. Direct-call helpers (`KeepFirstN`, `KeepLastN`, `KeepFirstLast`, `SameLengthMask`, `PreserveDelimiters`, …) take an explicit mask rune, so a closure is the place to read your chosen character.

```go
func init() {
	// internal_ticket: "ACME-TICKET-000123" → "ACME-TICKET-****23"
	_ = mask.Register("internal_ticket", func(v string) string {
		// Hyphens structure the ID; preserve them and keep the last 2
		// non-separator runes.
		return mask.PreserveDelimiters(mask.KeepLastN(v, 2, '*'), "-", '*')
	})
}
```

### 3. Honour per-instance mask-character config

Factories capture `DefaultMaskChar` at construction. If you want your custom rule to react to a later `SetMaskChar` call or a `WithMaskChar` on a specific `Masker`, register a closure that reads `m.MaskChar()` at apply time:

```go
m := mask.New(mask.WithMaskChar('#'))
_ = m.Register("employee_id", func(v string) string {
	return mask.KeepFirstN(v, 9, m.MaskChar())
})

// m.Apply("employee_id", "EMP-ACME-12345") → "EMP-ACME-#####"
```

The package-level `mask.MaskChar()` gives the same access for rules registered on the global registry.

### 4. Deterministic hashing with salt and version

For pseudonymisation — stable but opaque identifiers — register `DeterministicHashFunc` with a salt and a version. Both are required; see the [Configuration](../README.md#-configuration) section in the README for the full policy.

```go
func init() {
	_ = mask.Register("user_id", mask.DeterministicHashFunc(
		mask.WithSalt(os.Getenv("MASK_SALT")),
		mask.WithSaltVersion("v1"),
	))
}

// mask.Apply("user_id", "alice@example.com") → "sha256:v1:<hex16>"
```

### 5. A fully custom `RuleFunc`

When the primitives don't compose cleanly — for example, a format with a rotating checksum, a bank-specific account-number grammar, or a content-aware rule — implement the masking from scratch. The function MUST be deterministic, MUST NOT panic, and MUST NOT return the original value on malformed input:

```go
// internal_token: keeps the last 4 hex characters, masks the rest,
// and fails closed to a same-length mask on anything that is not a
// pure hex string.
func maskInternalToken(v string) string {
	for _, r := range v {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return mask.SameLengthMask(v, '*') // fail closed on non-hex
		}
	}
	return mask.KeepLastN(v, 4, '*')
}

func init() {
	_ = mask.Register("internal_token", maskInternalToken)
}

// mask.Apply("internal_token", "deadbeefcafe1234")  → "************1234"
// mask.Apply("internal_token", "nothex!!")          → "********"   (fail closed)
// mask.Apply("internal_token", "")                  → ""
```

### Scoping: package-level vs per-instance

`mask.Register` mutates the process-wide registry. That's the right choice for a service with a single rule set. Multi-tenant services — or tests that need rule-set isolation — construct one `Masker` per tenant:

```go
tenantA := mask.New()
_ = tenantA.Register("employee_id", mask.KeepFirstNFunc(9))

tenantB := mask.New()
_ = tenantB.Register("employee_id", mask.KeepLastNFunc(4)) // different shape

// tenantA.Apply("employee_id", "EMP-ACME-12345") → "EMP-ACME-*****"
// tenantB.Apply("employee_id", "EMP-ACME-12345") → "**********2345"
```

Register rules during program initialisation only — see [Thread Safety](../README.md#-thread-safety) in the README.

> **Factory vs. closure for the mask character.** Factories like `KeepFirstNFunc` capture `DefaultMaskChar` at construction and ignore later `SetMaskChar` / `WithMaskChar` overrides. If the rule must react to the configured character, use the closure pattern from §3 instead of the factory.

### Compile-time safety

Every built-in rule has an exported string constant of the form `mask.RuleX` — `mask.RuleEmailAddress`, `mask.RulePaymentCardPAN`, `mask.RuleUSSSN`, and so on. A call using a constant becomes a compile error on typo:

```go
// Safe — typo is caught by the compiler.
masked := mask.Apply(mask.RuleEmailAddress, "alice@example.com")

// Works today but a typo ("emial_address") silently falls back to [REDACTED]
// because the rule is unknown.
masked = mask.Apply("email_address", "alice@example.com")
```

Both forms are supported. The library's own tests and examples use string literals for brevity in documentation; production call sites benefit from the typed form.
