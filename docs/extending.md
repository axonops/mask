# Extending mask

<sub>← [Back to README](../README.md) · [Rule Catalogue](./rules.md) · **Extending**</sub>

Two concerns, one page:

- **[Utility Primitives](#utility-primitives)** — the composable building blocks exposed both as Go helper functions and as factory `RuleFunc`s.
- **[Custom Rules](#custom-rules)** — patterns for registering your own rule on top of those primitives, from one-liner factories through regex to fully custom `RuleFunc` implementations.

## Table of contents

- [Utility Primitives](#utility-primitives)
  - [Direct-call examples](#direct-call-examples)
  - [Factory examples](#factory-examples)
- [Custom Rules](#custom-rules)
  - [Regex-based rules](#regex-based-rules) — the most common extension path
    - [Anatomy of a regex rule](#anatomy-of-a-regex-rule)
    - [Capture groups for partial preservation](#capture-groups-for-partial-preservation)
    - [A cookbook of useful patterns](#a-cookbook-of-useful-patterns)
    - [Performance and compilation caching](#performance-and-compilation-caching)
    - [ReDoS safety — Go uses RE2](#redos-safety--go-uses-re2)
    - [When NOT to use regex](#when-not-to-use-regex)
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
| `PreserveDelimiters` | `PreserveDelimiters(v, delim string, c rune) string` | `PreserveDelimitersFunc(delim string) RuleFunc` | — |
| `ReplaceRegex` | — | `ReplaceRegexFunc(pattern, replacement string) (RuleFunc, error)` | — |
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

Reach for a **regex-based rule** first — it is the most common extension path and covers the majority of ad-hoc identifier shapes. For everything else, the five patterns further down the page (factory, closure, per-instance config, hashing, fully custom) cover the situations you're likely to hit.

### Regex-based rules

**If you need to extend `mask` and your data has a predictable textual shape, reach for `ReplaceRegexFunc` first.** Regex is the default tool when the built-in catalogue doesn't cover your format: internal ticket IDs, proprietary employee numbers, tenant-scoped identifiers, secrets embedded in free-text log lines, API keys with a recognisable prefix, anything with a regular shape surrounded by context bytes you want to keep.

`ReplaceRegexFunc(pattern, replacement)` compiles `pattern` **once**, at factory-call time (typically inside `init()`), and returns a `RuleFunc` that reuses the compiled matcher for every `Apply`. The returned function is concurrency-safe and allocation-efficient. An invalid pattern returns `(nil, err)` so a programmer typo surfaces at init rather than at first use in production.

#### Anatomy of a regex rule

```go
import (
    "log"

    "github.com/axonops/mask"
)

func init() {
    // Pattern: any run of 6 or more ASCII digits embedded in free text.
    // Replacement: the literal string "[REDACTED]".
    r, err := mask.ReplaceRegexFunc(`\d{6,}`, "[REDACTED]")
    if err != nil {
        // An invalid pattern is a programmer bug, not a runtime
        // condition — fail the process at init rather than silently
        // skipping the rule.
        log.Fatalf("mask: compile free_text_digits: %v", err)
    }
    _ = mask.Register("free_text_digits", r)
}

// mask.Apply("free_text_digits", "Order #1234567 shipped")
//   → "Order #[REDACTED] shipped"
```

Every regex rule follows the same three-step shape: compile at init, register under a name, let `Apply` route to it. The compilation is a one-time cost; every subsequent `Apply` reuses the compiled matcher.

#### Capture groups for partial preservation

`ReplaceAllString`'s replacement string supports `$1`, `$2`, … back-references into parenthesised capture groups. Combine groups with literal replacement text to keep context around the secret and mask only the sensitive bytes:

```go
// Preserve the "ORDER-<YYYY>-" prefix; mask the trailing ID.
r, _ := mask.ReplaceRegexFunc(`(ORDER-\d{4}-)\d+`, "$1****")
_ = mask.Register("order_id", r)
// mask.Apply("order_id", "ORDER-2026-001234") → "ORDER-2026-****"
```

Multiple groups work the same way — each `$N` emits the matched bytes of group N verbatim:

```go
// Keep the AWS access-key prefix ("AKIA" or "ASIA"), mask the 16-char body.
r, _ := mask.ReplaceRegexFunc(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`, "${1}****************")
_ = mask.Register("aws_access_key", r)
// mask.Apply("aws_access_key", "id=AKIAIOSFODNN7EXAMPLE here")
//   → "id=AKIA**************** here"
```

> **Naming gotcha.** `$1` followed by alphanumerics is ambiguous (`$1F` could mean group 1 then `F`, or group 1F). Use the explicit `${1}` form whenever the back-reference is followed by a letter or digit.

#### A cookbook of useful patterns

Starting points you can adapt; all of them compile once at init and are safe to register concurrently.

| Goal | Pattern | Replacement |
|---|---|---|
| Any 6+ digit run | `` `\d{6,}` `` | `[REDACTED]` |
| Bearer token tail | `` `(Bearer\s+)[\w-]+` `` | `${1}****` |
| JWT-shaped token | `` `\beyJ[\w-]*\.[\w-]*\.[\w-]*` `` | `[REDACTED]` |
| `password=…` in a config or log line (case-insensitive) | `` `(?i)(password[=:])\s*\S+` `` | `${1}****` |
| Email-shaped substring in free text (use `email_address` for a bare email field — the built-in understands the format better) | `` `\b[\w._%+-]+@[\w.-]+\.\w{2,}\b` `` | `[REDACTED]` |
| Alphanumeric IDs with a known prefix | `` `\bINT-[A-Z0-9]{6,}\b` `` | `[REDACTED]` |
| Cloud resource ARNs (AWS) | `` `\barn:aws:[^\s"']+` `` | `[REDACTED]` |
| MongoDB ObjectId | `` `\b[0-9a-f]{24}\b` `` | `[REDACTED]` |

Use `\b` word boundaries to avoid chewing through surrounding text; use `(?i)` at the start of a pattern for case-insensitive matching; use `(?s)` only if you need `.` to span newlines (rarely what a log-line masker wants). The full list of supported flags and syntax is documented at [pkg.go.dev/regexp/syntax](https://pkg.go.dev/regexp/syntax) — worth a skim before copying cookbook patterns from PCRE-oriented blog posts.

#### Performance and compilation caching

Regex compilation is expensive — Go's `regexp` parses the pattern and builds an internal representation before the first match. Fortunately, **you do not need to write your own cache**: `ReplaceRegexFunc` already compiles exactly once and returns a closure that captures the compiled `*regexp.Regexp`. Every subsequent `Apply` reuses that compiled matcher.

```go
// Compiled once at init — no recompilation on any subsequent Apply call.
r, _ := mask.ReplaceRegexFunc(`\d{6,}`, "[REDACTED]")
_ = mask.Register("free_text_digits", r)
```

**The anti-pattern to avoid: compiling inside the closure body.** This looks plausible if you are writing a fully custom `RuleFunc` but recompiles the pattern on every single call, which will dominate the hot path:

```go
// BAD — recompiles on every Apply.
_ = mask.Register("free_text_digits", func(v string) string {
    re := regexp.MustCompile(`\d{6,}`) // ❌ runs on every call
    return re.ReplaceAllString(v, "[REDACTED]")
})

// GOOD — compile once at package init, capture the *Regexp in the closure.
var freeTextDigitsRE = regexp.MustCompile(`\d{6,}`)

_ = mask.Register("free_text_digits", func(v string) string {
    return freeTextDigitsRE.ReplaceAllString(v, "[REDACTED]")
})

// BEST — let the factory do it.
r, _ := mask.ReplaceRegexFunc(`\d{6,}`, "[REDACTED]")
_ = mask.Register("free_text_digits", r)
```

Sharing one compiled pattern across multiple rules is safe — `*regexp.Regexp` is explicitly documented as concurrency-safe:

```go
var employeeRE = regexp.MustCompile(`\bEMP-[A-Z]+-\d+\b`)

_ = mask.Register("employee_internal", func(v string) string {
    return employeeRE.ReplaceAllString(v, "[REDACTED]")
})
_ = mask.Register("employee_audit_log", func(v string) string {
    // Same compiled matcher, different replacement — no recompilation.
    return employeeRE.ReplaceAllString(v, "[EMP]")
})
```

> **There is no Apply-time regex caching inside `mask` itself.** The library does not accept patterns at `Apply` time; patterns are supplied at `Register` time, where they compile once and the closure owns the compiled matcher for its lifetime. A cache would protect against a usage pattern the API does not expose — don't write one.

#### ReDoS safety — Go uses RE2

Regex-based masking in general is infamous for catastrophic backtracking: a hostile input can force the engine into exponential-time matching and stall the service (a ReDoS attack). **This is not a concern in Go.** Go's standard `regexp` package is backed by [RE2](https://github.com/google/re2), which executes every pattern in guaranteed linear time regardless of input.

The trade-off is that RE2 does not support features that would require backtracking:

- **Backreferences in the pattern itself** (e.g. `(.)\1` to match a doubled character)
- **Lookahead assertions**: `(?=...)`, `(?!...)`
- **Lookbehind assertions**: `(?<=...)`, `(?<!...)`

`ReplaceRegexFunc` returns a compile error if the pattern uses any of these, so cookbook patterns copied from PCRE-oriented blog posts may need a small rewrite. For masking rules these absences are rarely a real limitation.

You can feed `ReplaceRegexFunc` adversarial-looking patterns like `(a|a|a|a)*b` against hostile inputs and the match will complete in linear time. Register regex rules with the same confidence you register any other rule.

#### When NOT to use regex

Regex is the right tool for ad-hoc textual formats. It is the **wrong** tool when:

- **A built-in rule exists.** `payment_card_pan`, `iban`, `ipv4_address`, `uuid`, `email_address`, `jwt_token` and the other format-specific rules understand their format's structure (check digits, field lengths, country codes) in ways a regex cannot. Use the built-in.
- **The format has structural constraints you care about.** IBAN has a mod-97 check digit; a Visa PAN has a Luhn check digit; a valid UUID has a specific nibble layout. A regex that matches "16 digits with dashes" will happily match invalid PANs and produce confusing output. Write a `RuleFunc` that parses the format and fails closed on malformed input — see pattern §5 below.
- **You need to honour the configured mask character.** A literal `****` in a regex replacement is just the character `*` four times — it does not react to `SetMaskChar('#')` or `WithMaskChar('#')`. Callers who want their custom rule to follow the configured mask rune should compose primitives via a closure — see pattern §3 below.
- **The match is a long substring you want to mask rune-by-rune.** `ReplaceAllString` emits the replacement string verbatim; it does not length-match the input. Use `regexp.Regexp.ReplaceAllStringFunc` inside a closure if you need length-preservation:

  ```go
  import (
      "regexp"
      "github.com/axonops/mask"
  )

  var digitRunRE = regexp.MustCompile(`\d{6,}`)

  _ = mask.Register("preserve_length_digits", func(v string) string {
      return digitRunRE.ReplaceAllStringFunc(v, func(match string) string {
          return mask.SameLengthMask(match, '*')
      })
  })
  // mask.Apply("preserve_length_digits", "Order #1234567 shipped")
  //   → "Order #******* shipped"
  ```

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

Other factories in the same shape: `PreserveDelimitersFunc(delim)`, `ReducePrecisionFunc(decimals)`, `FixedReplacementFunc(s)`, `DeterministicHashFunc(opts...)`. Regex rules are a dedicated section above — see [Regex-based rules](#regex-based-rules).

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
		mask.WithKeyedSalt(os.Getenv("MASK_SALT"), "v1"),
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
