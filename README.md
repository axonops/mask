# mask

Mask PII, PCI, and PHI in Go strings with 68 built-in rules and zero runtime dependencies.

[![CI](https://github.com/axonops/mask/actions/workflows/ci.yml/badge.svg)](https://github.com/axonops/mask/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/axonops/mask.svg)](https://pkg.go.dev/github.com/axonops/mask)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

## Install

```sh
go get github.com/axonops/mask
```

Requires Go 1.26 or later.

## Quick start

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

### Fail-closed contract

Every built-in rule is fail-closed. Two guarantees you can rely on at every call site:

- An unknown rule name returns `[REDACTED]` — the original value is never echoed.
- A known rule that cannot parse its input returns a same-length mask — the original value is never echoed.

`Apply` never returns an error. Masking is pure compute — no I/O, no goroutines, no context. `Register`, by contrast, returns `ErrDuplicateRule` or `ErrInvalidRule` on misuse — check it at init time.

## Why

- **Fail-closed by default.** Malformed input never leaks; unknown rule returns `[REDACTED]`.
- **Pure functions, stdlib only.** No goroutines, no config files, no init surprises.
- **68 built-in rules** across identity, financial, healthcare, telecom, technology, and country-specific catalogues.
- **Composable primitives.** Build custom rules with `KeepFirstN`, `KeepLastN`, `DeterministicHash`, and friends.
- **Thread-safe after init.** Same contract as `database/sql.Register`.

## Common tasks

If you're looking for the right rule for a common field, start here.

| I want to mask... | Use rule | Example |
|---|---|---|
| An email address | [`email_address`](#identity) | `alice@example.com` → `a****@example.com` |
| A credit card number | [`payment_card_pan`](#financial) | `4111-1111-1111-1111` → `4111-11**-****-1111` |
| A US Social Security Number | [`us_ssn`](#country-specific-identity) | `123-45-6789` → `***-**-6789` |
| A phone number | [`phone_number`](#telecom-and-location) | `+44 7911 123456` → `+44 **** **3456` |
| An IPv4 address | [`ipv4_address`](#technology) | `192.168.1.42` → `192.168.*.*` |
| A UUID | [`uuid`](#technology) | `550e8400-e29b-41d4-a716-446655440000` → `550e8400-****-****-****-********0000` |
| An IBAN | [`iban`](#financial) | `GB82WEST12345698765432` → `GB82**************5432` |
| A medical record number | [`medical_record_number`](#health) | `MRN-123456789` → `MRN-*****6789` |
| A JWT | [`jwt_token`](#technology) | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc` → `eyJh****.****.****.` |
| A UK postcode | [`postal_code`](#telecom-and-location) | `SW1A 2AA` → `SW1A ***` |
| A UK National Insurance Number | [`uk_nino`](#country-specific-identity) | `AB123456C` → `AB******C` |
| Any free-text secret | [`full_redact`](#utility-primitives) | anything → `[REDACTED]` |
| A password field | [`password`](#technology) | any non-empty value → `********` |
| An internal / bespoke ID | see [Custom rules](#custom-rules) | compose with `KeepFirstN`, `KeepLastN`, `KeepFirstLast` |

For the full catalogue, see [Built-in rules](#built-in-rules) or call `mask.Rules()` at runtime.

## Built-in rules

68 rules registered out of the box. Every rule is fail-closed and honours the configured mask character (`SetMaskChar` / `WithMaskChar`). Use `mask.Rules()` to list every registered name and `mask.Describe(name)` to get the category, jurisdiction, and description.

### Utility primitives

Four general-purpose rules registered as masking rules. These are also exposed as Go functions (see [Utility primitives, direct call](#utility-primitives-direct-call)).

| Rule | Description | Example |
|---|---|---|
| `full_redact` | Replaces any value with the constant `[REDACTED]`. | `anything` → `[REDACTED]` |
| `same_length_mask` | Replaces every rune of the input with the configured mask character, preserving length. | `Hello` → `*****` |
| `nullify` | Replaces any value with the empty string. | `anything` → (empty) |
| `deterministic_hash` | Replaces the value with a truncated SHA-256 digest. Pseudonymisation, not anonymisation — see [SECURITY.md](./SECURITY.md) for the salt and version policy. | `alice@example.com` → `sha256:ff8d9819fc0e12bf` |

### Identity

Personal and identity fields common to most jurisdictions. See [Country-specific identity](#country-specific-identity) for regional IDs.

| Rule | Description | Example |
|---|---|---|
| `date_of_birth` | Preserves the year and masks month and day across three common formats (ISO, slash, month-name); separator style is unchanged. | `1985-03-15` → `1985-**-**` |
| `driver_license_number` | Preserves the first 2 and last 3 or 4 non-separator characters of a driver licence number. | `DL-1234-5678` → `DL-****-5678` |
| `email_address` | Preserves the first character of the local-part and the full domain; masks the rest of the local-part. | `alice@example.com` → `a****@example.com` |
| `family_name` | Preserves the first character of the surname. | `Smith` → `S****` |
| `generic_national_id` | Preserves the first 2 and last 2 characters; use sparingly — prefer country-specific rules where available. | `AB123456CD` → `AB******CD` |
| `given_name` | Preserves the first character of the given name. | `Alice` → `A****` |
| `passport_number` | Preserves a two-letter country prefix (if present) and the last 2 characters. | `GB1234567` → `GB*****67` |
| `person_name` | Preserves the first initial of each space-separated name component. | `Alice Smith` → `A**** S****` |
| `street_address` | Keeps the leading house number and recognised trailing street type; masks the street-name body. | `42 Wallaby Way` → `42 ******* Way` |
| `tax_identifier` | Preserves the last 3 or 4 non-separator characters; preserves separators. | `12-3456789` → `**-***6789` |
| `username` | Preserves the first 2 characters of a username. | `johndoe42` → `jo*******` |

### Country-specific identity

Jurisdiction-qualified identity fields. All report `category = "identity"` with a specific `Jurisdiction`.

<details>
<summary>14 rules — expand</summary>

| Rule | Description | Example |
|---|---|---|
| `au_medicare_number` | Preserves the last 2 digits of a 10-digit Australian Medicare number. | `2123 45670 1` → `**** ****0 1` |
| `br_cnpj` | Preserves the last 2 digits of a 14-digit Brazilian CNPJ; accepts canonical and compact forms. | `12.345.678/0001-95` → `**.***.***/****-95` |
| `br_cpf` | Preserves the last 2 digits of an 11-digit Brazilian CPF; accepts canonical and compact forms. | `123.456.789-09` → `***.***.***-09` |
| `ca_sin` | Preserves the last 3 digits of a 9-digit Canadian Social Insurance Number. | `123-456-789` → `***-***-789` |
| `cn_resident_id` | Preserves the first 6 (region code) and last 4 characters of an 18-character PRC Resident Identity Card number. | `110101199003074578` → `110101********4578` |
| `es_dni_nif_nie` | Preserves the leading character (for NIE/NIF) and trailing control letter of a 9-character Spanish DNI/NIF/NIE. | `12345678Z` → `********Z` |
| `in_aadhaar` | Preserves the last 4 digits of a 12-digit Aadhaar number. | `1234 5678 9012` → `**** **** 9012` |
| `in_pan` | Preserves the first 3 and last 2 characters of a 10-character Indian Permanent Account Number. | `ABCDE1234F` → `ABC*****4F` |
| `mx_curp` | Preserves the first 4 and last 3 characters of an 18-character Mexican CURP. | `GAPA850101HDFRRL09` → `GAPA***********L09` |
| `mx_rfc` | Preserves the first 3 and last 3 characters of a 12- or 13-character Mexican RFC. | `GAPA8501014T3` → `GAP*******4T3` |
| `sg_nric_fin` | Preserves the leading letter and trailing letter of a 9-character Singapore NRIC/FIN. | `S1234567A` → `S*******A` |
| `uk_nino` | Preserves the 2 prefix letters and 1 suffix letter of a UK National Insurance Number. | `AB123456C` → `AB******C` |
| `us_ssn` | Preserves the last 4 digits of a 9-digit US Social Security Number. | `123-45-6789` → `***-**-6789` |
| `za_national_id` | Preserves the first 6 (date of birth) and last 4 digits of a 13-digit South African national ID. | `8501015009087` → `850101***9087` |

</details>

### Financial

Payment-card, banking, and tax-identifier rules. The `payment_card_pan_first6`, `payment_card_pan_last4`, and `payment_card_pan` rules together cover the three common PCI DSS display modes.

<details>
<summary>11 rules — expand</summary>

| Rule | Description | Example |
|---|---|---|
| `bank_account_number` | Preserves the last 4 digits of a bank account number, masks the rest. | `12345678` → `****5678` |
| `iban` | Preserves the country code, check digits, and last 4 non-separator characters. | `GB82WEST12345698765432` → `GB82**************5432` |
| `monetary_amount` | Full redact. Length-preserving output would leak the order of magnitude of the amount. | `$1,234.56` → `[REDACTED]` |
| `payment_card_cvv` | Same-length mask — CVV is Sensitive Authentication Data that MUST NOT be retained post-authorisation. | `123` → `***` |
| `payment_card_pan` | Preserves the first 6 and last 4 digits of a Primary Account Number (PCI DSS display mode). | `4111-1111-1111-1111` → `4111-11**-****-1111` |
| `payment_card_pan_first6` | Preserves the first 6 digits; masks the rest. | `4111-1111-1111-1111` → `4111-11**-****-****` |
| `payment_card_pan_last4` | Preserves the last 4 digits; masks the rest. | `4111-1111-1111-1111` → `****-****-****-1111` |
| `payment_card_pin` | Same-length mask; callers concerned about PIN-width leakage should register `full_redact` under this name. | `1234` → `****` |
| `swift_bic` | Preserves the 4-character bank code; accepts 8- or 11-character uppercase ASCII alphanumerics. | `BARCGB2L` → `BARC****` |
| `uk_sort_code` | Preserves the first 2 digits of a UK 6-digit sort code (the bank identifier); preserves separators. | `12-34-56` → `12-**-**` |
| `us_aba_routing_number` | Preserves the last 4 digits of a 9-digit US ABA routing number. | `123456789` → `*****6789` |

</details>

### Health

Healthcare identifiers and clinical content. Identifier rules are pseudonymisation, not HIPAA Safe Harbor de-identification — combined with any quasi-identifier (date of service, ZIP, age) they remain re-identifiable. Register a stricter rule (for example `full_redact`) under the same name if your use case requires Safe Harbor compliance.

| Rule | Description | Example |
|---|---|---|
| `diagnosis_code` | Full redact. ICD-10 codes are quasi-identifiers when combined with dates or ZIP codes. | `J45.20` → `[REDACTED]` |
| `health_plan_beneficiary_id` | Preserves the leading alpha-and-separator prefix and keeps the last 4 non-separator characters. | `HPB-987654321` → `HPB-*****4321` |
| `medical_device_identifier` | Preserves the leading alpha-and-separator prefix (including multi-segment prefixes like `DEV-SN-`) and keeps the last 4 non-separator characters. | `DEV-SN-12345678` → `DEV-SN-****5678` |
| `medical_record_number` | Preserves the leading alpha-and-separator prefix and keeps the last 4 non-separator characters of the body. | `MRN-123456789` → `MRN-*****6789` |
| `prescription_text` | Full redact. Free-text prescription fields may expose conditions and clinical details. | `Metformin 500mg twice daily` → `[REDACTED]` |

### Technology

Infrastructure and application-security fields. The URL family never emits `net/url`'s re-encoded output — every rule rebuilds from validated raw fields so percent-encoding and userinfo bytes cannot leak.

<details>
<summary>14 rules — expand</summary>

| Rule | Description | Example |
|---|---|---|
| `api_key` | Preserves the first 4 and last 4 runes and same-length-masks the middle; input shorter than 9 runes fails closed. | `AKIAIOSFODNN7EXAMPLE` → `AKIA************MPLE` |
| `bearer_token` | Preserves the `Bearer ` scheme and the first 6 runes of the token, then appends the literal elision marker `****...` (four mask runes plus three dots — the dots are not the configured mask character, they distinguish the marker from a masked token). | `Bearer abc123def456` → `Bearer abc123****...` |
| `connection_string` | Preserves scheme, host, port, path and non-secret query parameters; redacts userinfo and the values of known secret query parameters. | `postgresql://admin:s3cret@db.example.com:5432/myapp` → `postgresql://****:****@db.example.com:5432/myapp` |
| `database_dsn` | Parses the Go MySQL DSN form and redacts userinfo. | `user:password@tcp(localhost:3306)/dbname` → `****:****@tcp(localhost:3306)/dbname` |
| `hostname` | Preserves the first label and same-length-masks the remaining labels; single-label inputs fail closed. | `web-01.prod.example.com` → `web-01.****.*******.***` |
| `ipv4_address` | Preserves the first 2 octets and masks the last 2 as single mask runes. | `192.168.1.42` → `192.168.*.*` |
| `ipv6_address` | Preserves the first 4 hextets and masks the interface identifier; compressed form is preserved when `::` is in the tail. | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` → `2001:0db8:85a3:0000:****:****:****:****` |
| `jwt_token` | Preserves the first 4 runes of the header segment and masks all three segments with fixed 4-rune blocks; the output ends with a trailing dot. | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc` → `eyJh****.****.****.` |
| `mac_address` | Preserves the OUI (first 3 octets) and masks the device identifier; accepts `:` and `-` separators. | `AA:BB:CC:DD:EE:FF` → `AA:BB:CC:**:**:**` |
| `password` | Emits a fixed 8-rune mask regardless of source length so password length is not leaked; empty input returns empty. | `MyP@ssw0rd!` → `********` |
| `private_key_pem` | Full redact. Private key material must never be partially revealed. | `-----BEGIN RSA PRIVATE KEY-----...` → `[REDACTED]` |
| `url` | Preserves scheme, host, and port; same-length-masks path segments; masks query values and fragment with fixed 4-rune blocks; redacts userinfo defensively. | `https://example.com/users/42?token=abc` → `https://example.com/*****/**?token=****` |
| `url_credentials` | Preserves scheme, host, path, query and fragment; redacts userinfo only. | `https://admin:s3cret@db.example.com/mydb` → `https://****:****@db.example.com/mydb` |
| `uuid` | Preserves the first 8 and last 4 hex runes of a canonical UUID; non-canonical forms fail closed. | `550e8400-e29b-41d4-a716-446655440000` → `550e8400-****-****-****-********0000` |

</details>

### Telecom and location

Phone numbers, mobile identifiers, postcodes, and geographic coordinates.

<details>
<summary>9 rules — expand</summary>

| Rule | Description | Example |
|---|---|---|
| `geo_coordinates` | Splits on a single comma and applies `geo_latitude` / `geo_longitude` to each half. | `37.7749,-122.4194` → `37.77**,-122.41**` |
| `geo_latitude` | Reduces decimal precision to 2 places by truncation; integer input fails closed. Roughly 1.1 km resolution. | `37.7749295` → `37.77*****` |
| `geo_longitude` | Reduces decimal precision to 2 places by truncation; integer input fails closed. | `-122.4194155` → `-122.41*****` |
| `imei` | Preserves the last 4 digits of a 15-digit IMEI. | `353456789012345` → `***********2345` |
| `imsi` | Preserves the first 5 (MCC+MNC) and last 4 digits of a 15-digit IMSI. | `310260123456789` → `31026******6789` |
| `mobile_phone_number` | Alias of `phone_number`. | `+44 7911 123456` → `+44 **** **3456` |
| `msisdn` | Preserves the first 2 and last 4 digits of a 10-15 digit MSISDN. | `447911123456` → `44******3456` |
| `phone_number` | Preserves a leading `+NN` country code (if present) and the last 4 digits; masks middle digits while preserving structural separators. | `+44 7911 123456` → `+44 **** **3456` |
| `postal_code` | Shape-aware across UK (outward code), US 5-digit ZIP (first 3), and Canada (FSA); other shapes fail closed. | `SW1A 2AA` → `SW1A ***` |

</details>

## Utility primitives (direct call)

The masking primitives are also exposed as Go functions. Call them directly inside a custom `RuleFunc`, or use the `…Func` factory to register a parametric rule at any name of your choosing.

> Factories (`KeepFirstNFunc`, `ReplaceRegexFunc`, etc.) capture `DefaultMaskChar` at construction and ignore per-instance overrides. Callers who need per-instance mask-character customisation should register a closure that captures the desired mask rune at construction time rather than using a factory.

### Direct-call helpers

| Primitive | Signature | Description | Example |
|---|---|---|---|
| `FullRedact` | `func(string) string` | Returns the constant `[REDACTED]`. | `FullRedact("anything")` → `[REDACTED]` |
| `Nullify` | `func(string) string` | Returns the empty string. | `Nullify("anything")` → `` |
| `SameLengthMask` | `func(v string, c rune) string` | Replaces every rune of v with c. | `SameLengthMask("Hello", '*')` → `*****` |
| `KeepFirstN` | `func(v string, n int, c rune) string` | Preserves the first n runes. | `KeepFirstN("Sensitive", 4, '*')` → `Sens*****` |
| `KeepLastN` | `func(v string, n int, c rune) string` | Preserves the last n runes. | `KeepLastN("Sensitive", 4, '*')` → `*****tive` |
| `KeepFirstLast` | `func(v string, first, last int, c rune) string` | Preserves the first and last runes; masks the middle. | `KeepFirstLast("SensitiveData", 4, 4, '*')` → `Sens*****Data` |
| `TruncateVisible` | `func(v string, n int) string` | Returns the first n runes with no mask. Not fail-closed — use only in composition. | `TruncateVisible("Sensitive", 4)` → `Sens` |
| `PreserveDelimiters` | `func(v, delim string, c rune) string` | Masks every rune except those in delim. | `PreserveDelimiters("ab-cd", "-", '*')` → `**-**` |
| `ReplaceRegex` | `func(v, pattern, replacement string) (string, error)` | Replaces regex matches. Compiles on every call. | `ReplaceRegex("id-42", "\\d+", "N")` → `("id-N", nil)` |
| `ReducePrecision` | `func(v string, decimals int, c rune) string` | Reduces decimal precision of a numeric string by masking trailing digits. | `ReducePrecision("37.7749", 2, '*')` → `37.77**` |
| `DeterministicHash` | `func(v string) string` | SHA-256 truncated to 16 hex characters; pseudonymisation only. | `DeterministicHash("alice@example.com")` → `sha256:ff8d9819fc0e12bf` |

### Factory functions

Each factory returns a `RuleFunc` suitable for passing to `Register`. Every example below uses the default mask character `*`.

| Factory | Behaviour | Example |
|---|---|---|
| `FixedReplacementFunc(s)` | Returns the literal string `s` regardless of input. | `FixedReplacementFunc("[HIDDEN]")("anything")` → `[HIDDEN]` |
| `KeepFirstNFunc(n)` | Keeps the first `n` runes, masks the rest. | `KeepFirstNFunc(4)("Sensitive")` → `Sens*****` |
| `KeepLastNFunc(n)` | Keeps the last `n` runes, masks the rest. | `KeepLastNFunc(4)("Sensitive")` → `*****tive` |
| `KeepFirstLastFunc(first, last)` | Keeps both ends, masks the middle. | `KeepFirstLastFunc(4, 4)("SensitiveData")` → `Sens*****Data` |
| `TruncateVisibleFunc(n)` | Returns the first `n` runes with no mask. Not fail-closed. | `TruncateVisibleFunc(4)("Sensitive")` → `Sens` |
| `PreserveDelimitersFunc(delim)` | Masks every rune except those listed in `delim`. | `PreserveDelimitersFunc("-")("ab-cd")` → `**-**` |
| `ReplaceRegexFunc(pattern, replacement)` | Pre-compiles `pattern` once; returns `(nil, err)` on an invalid pattern. | `ReplaceRegexFunc("\\d+", "N")` applied to `"id-42"` → `id-N` |
| `ReducePrecisionFunc(decimals)` | Reduces decimal precision of a numeric string by masking trailing digits. | `ReducePrecisionFunc(2)("37.7749")` → `37.77**` |
| `DeterministicHashFunc(opts...)` | Hashes via `DeterministicHash`; salt, version, and algorithm are configured via `HashOption` arguments. | `DeterministicHashFunc()("alice@example.com")` → `sha256:ff8d9819fc0e12bf` |

See [`pkg.go.dev`](https://pkg.go.dev/github.com/axonops/mask) for the full API reference.

## Custom rules

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

For pseudonymisation — stable but opaque identifiers — register `DeterministicHashFunc` with a salt and a version. Both are required; see the [Deterministic hashing](#deterministic-hashing-salt-and-version) section below for the full policy.

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

Register rules during program initialisation only — see [Thread safety](#thread-safety).

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

## Configuration

### Mask character

The default mask character is `*`. Override it globally (for the package-level registry) or per instance.

```go
// Global — mutates the package-level registry.
mask.SetMaskChar('#')

// Per instance — isolated to this Masker only.
m := mask.New(mask.WithMaskChar('#'))
```

Built-in rules read the configured character at apply time, so changes are picked up on the next call. The `password` rule honours the configured character for the 8-rune mask output.

### Deterministic hashing (salt and version)

`deterministic_hash` is registered by default with no salt. For production pseudonymisation you MUST configure both a salt (`WithSalt`) AND a salt version (`WithSaltVersion`):

```go
m := mask.New()
_ = m.Register(
	"user_id",
	mask.DeterministicHashFunc(
		mask.WithSalt("your-secret-salt"),
		mask.WithSaltVersion("v1"),
	),
)
```

The output format is `<algo>:<version>:<hex16>` when a salt is configured, and `<algo>:<hex16>` otherwise. See [SECURITY.md](./SECURITY.md) for the full salt-rotation and versioning policy.

## Thread safety

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

## Regulatory positioning

Masking is one control in a broader compliance strategy — it is not a substitute for access control, encryption, or retention policy. The table below summarises where the library fits against common regulatory regimes. See [SECURITY.md](./SECURITY.md) for the full threat model.

| Use case | Fit | Notes |
|---|---|---|
| PCI DSS display modes for PAN | Yes | `payment_card_pan`, `payment_card_pan_first6`, `payment_card_pan_last4` match the three common display modes. `payment_card_cvv` is same-length — CVV is Sensitive Authentication Data that MUST NOT be retained post-authorisation. |
| HIPAA Safe Harbor de-identification | No | Identifier rules (including `medical_record_number`, `health_plan_beneficiary_id`) are pseudonymisation, not de-identification. Retained trailing digits combined with a date or ZIP remain re-identifiable. Register `full_redact` under the same rule name if you need Safe Harbor. |
| GDPR pseudonymisation (Art. 4(5)) | Yes, with configured salt | `deterministic_hash` with `WithSalt(salt)` + `WithSaltVersion(version)` meets the GDPR definition. Salt management, rotation, and additional access controls are the operator's responsibility. |
| GDPR anonymisation | No | No rule in this library is anonymisation — all preserved-window rules leak structure, and `deterministic_hash` is reversible given the input space. |

## Fallback behaviour

`mask.Apply` always returns a string and never an error.

- Unknown rule name → `[REDACTED]` (the value of `mask.FullRedactMarker`).
- Known rule, malformed input → a same-length mask of the configured mask character.
- Empty input → empty output (except for full-redact rules, which always return `[REDACTED]`).

This contract is uniform across every rule in the catalogue. Consumers can rely on it without per-rule knowledge.

## API reference

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

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for branching, commit, PR, and release guidance. Issues and pull requests are welcome.

## Licence

Apache Licence 2.0. See [LICENSE](./LICENSE) for the full text.
