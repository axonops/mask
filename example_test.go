// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mask_test

import (
	"fmt"
	"strings"

	"github.com/axonops/mask"
)

// ExampleApply shows the simplest usage: look up a built-in rule by name
// and mask a value with it. The default mask character is `*` and every
// built-in rule fails closed on input it cannot parse — the original value
// is never returned.
func ExampleApply() {
	fmt.Println(mask.Apply("email_address", "alice@example.com"))
	// Output: a****@example.com
}

// ExampleApply_typedRuleName uses one of the exported rule-name
// constants (`mask.RuleEmailAddress`) instead of a string literal.
// The output is identical — but a typo such as `mask.RuleEmialAddress`
// is a compile error rather than a silent fail-closed at runtime.
// Prefer the typed form in production code; string literals stay
// supported for scripts, tests, and documentation.
func ExampleApply_typedRuleName() {
	fmt.Println(mask.Apply(mask.RuleEmailAddress, "alice@example.com"))
	// Output: a****@example.com
}

// ExampleApply_unknownRule demonstrates the fail-closed contract for
// unknown rule names: Apply always returns [FullRedactMarker] rather than
// the original value. This is the same behaviour consumers can rely on
// for every rule in the catalogue.
func ExampleApply_unknownRule() {
	fmt.Println(mask.Apply("no_such_rule", "alice@example.com"))
	// Output: [REDACTED]
}

// ExampleApply_failClosed pairs with ExampleApply_unknownRule to
// document the uniform fail-closed contract: unknown rule names
// return [FullRedactMarker] and the original value is never echoed.
// Treat this as the library's safety rail — Apply never returns an
// error, and never leaks the input on a misconfigured rule name.
func ExampleApply_failClosed() {
	// Typo'd rule name — returns [REDACTED] instead of the email.
	fmt.Println(mask.Apply("emial_address", "alice@example.com"))
	// Output: [REDACTED]
}

// ExampleApply_malformedFallsBack demonstrates the second leg of
// the fail-closed contract: when a known rule cannot parse its
// input, it returns a same-length mask of the whole value instead
// of the original bytes. The caller never has to check for
// malformed input at the call site.
func ExampleApply_malformedFallsBack() {
	// "nope" is 4 bytes of nonsense, not a PAN — the rule falls
	// back to same-length mask over the whole value.
	fmt.Println(mask.Apply("payment_card_pan", "nope"))
	// Output: ****
}

// ExampleRegister adds a custom masking rule to the package-level
// registry and applies it. The registry is process-global; pick rule
// names that cannot collide with the built-in catalogue.
func ExampleRegister() {
	// Reverse is a trivial custom rule — real rules would wrap one of
	// the utility primitives in this package (KeepFirstN, KeepLastN,
	// KeepFirstLast, PreserveDelimiters, etc.).
	reverse := func(v string) string {
		runes := []rune(v)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes)
	}

	if err := mask.Register("example_reverse", reverse); err != nil {
		panic(err)
	}
	fmt.Println(mask.Apply("example_reverse", "hello"))
	// Output: olleh
}

// ExampleNew_withMaskChar constructs an isolated [Masker] with a custom
// mask character. Built-in rules read the configured character at apply
// time, so changing the mask character affects every subsequent call on
// that instance.
func ExampleNew_withMaskChar() {
	m := mask.New(mask.WithMaskChar('#'))
	fmt.Println(m.Apply("us_ssn", "123-45-6789"))
	// Output: ###-##-6789
}

// ExampleSetMaskChar overrides the default mask character used by the
// package-level registry. The defer resets it so other tests in the same
// process see the original default — production callers typically set
// it once during program initialisation and never change it.
func ExampleSetMaskChar() {
	defer mask.SetMaskChar(mask.DefaultMaskChar)

	mask.SetMaskChar('#')
	fmt.Println(mask.Apply("us_ssn", "123-45-6789"))
	// Output: ###-##-6789
}

// ExampleKeepFirstN calls the utility primitive directly without going
// through the registry. Useful when writing a custom rule that needs a
// keep-first window with a specific preservation count.
func ExampleKeepFirstN() {
	fmt.Println(mask.KeepFirstN("Sensitive", 4, '*'))
	// Output: Sens*****
}

// ExampleKeepFirstNFunc builds a parametric masking rule via the factory
// and registers it under a custom name. The factory captures the
// [DefaultMaskChar] at construction — callers who need per-instance
// mask-character customisation should register a closure directly.
func ExampleKeepFirstNFunc() {
	m := mask.New()
	if err := m.Register("my_token", mask.KeepFirstNFunc(4)); err != nil {
		panic(err)
	}
	fmt.Println(m.Apply("my_token", "SensitiveToken"))
	// Output: Sens**********
}

// ExampleMasker_isolation shows that two Maskers constructed via
// [New] keep their registries isolated. Rules registered on one are
// invisible to the other — a key property for multi-tenant services
// that need per-tenant rule sets or for tests that need clean state.
func ExampleMasker_isolation() {
	a := mask.New()
	b := mask.New()
	_ = a.Register("tenant_only", mask.KeepFirstNFunc(3))

	fmt.Println("a has tenant_only:", a.HasRule("tenant_only"))
	fmt.Println("b has tenant_only:", b.HasRule("tenant_only"))
	// Output:
	// a has tenant_only: true
	// b has tenant_only: false
}

// ExampleDescribe prints the metadata registered with a built-in rule.
// Use [Rules] together with Describe to iterate the full catalogue at
// runtime — consumers building dashboards or configuration UIs often
// do this to enumerate available rules.
func ExampleDescribe() {
	info, ok := mask.Describe("email_address")
	fmt.Println("found:", ok)
	fmt.Println("name:", info.Name)
	fmt.Println("category:", info.Category)
	fmt.Println("jurisdiction:", info.Jurisdiction)
	// Output:
	// found: true
	// name: email_address
	// category: identity
	// jurisdiction: global
}

// ExampleApply_structuredLogRedaction shows a realistic use case: masking
// several fields of a structured log line before writing it out. Each
// field is routed to the rule that fits its semantic. Production code
// typically prefers the typed rule-name constants (mask.RuleX) so a
// typo becomes a compile error.
func ExampleApply_structuredLogRedaction() {
	fields := []struct{ rule, value string }{
		{mask.RuleEmailAddress, "alice@example.com"},
		{mask.RulePaymentCardPAN, "4111-1111-1111-1111"},
		{mask.RuleUSSSN, "123-45-6789"},
		{mask.RuleIPv4Address, "192.168.1.42"},
		{mask.RuleJWTToken, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"},
	}

	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.rule+"="+mask.Apply(f.rule, f.value))
	}
	fmt.Println(strings.Join(out, " "))
	// Output: email_address=a****@example.com payment_card_pan=4111-11**-****-1111 us_ssn=***-**-6789 ipv4_address=192.168.*.* jwt_token=eyJh****.****.****.
}

// ---------------------------------------------------------------------------
// Per-rule worked examples. Each example demonstrates a common rule with
// a real-shaped input and the expected masked output, so readers of
// pkg.go.dev can see at a glance what "PAN masking" or "IBAN masking"
// actually produces.
// ---------------------------------------------------------------------------

// ExampleApply_paymentCardPAN shows the PCI DSS display mode implemented
// by `payment_card_pan`: preserve the first 6 (issuer identification
// number) and last 4 digits, mask the middle.
func ExampleApply_paymentCardPAN() {
	fmt.Println(mask.Apply(mask.RulePaymentCardPAN, "4111-1111-1111-1111"))
	// Output: 4111-11**-****-1111
}

// ExampleApply_iban preserves the country code, check digits, and last
// four characters of an IBAN — the same display mode most banking UIs
// use for account identifiers.
func ExampleApply_iban() {
	fmt.Println(mask.Apply(mask.RuleIBAN, "GB82WEST12345698765432"))
	// Output: GB82**************5432
}

// ExampleApply_uuid preserves the first 8 and last 4 hex runes of a
// canonical UUID; non-canonical forms fail closed to a same-length mask.
func ExampleApply_uuid() {
	fmt.Println(mask.Apply(mask.RuleUUID, "550e8400-e29b-41d4-a716-446655440000"))
	// Output: 550e8400-****-****-****-********0000
}

// ExampleApply_ipv4Address preserves the first two octets and masks the
// last two — enough to keep a network-level view without leaking the
// host identifier.
func ExampleApply_ipv4Address() {
	fmt.Println(mask.Apply(mask.RuleIPv4Address, "192.168.1.42"))
	// Output: 192.168.*.*
}

// ExampleApply_jwtToken masks a JWT's three segments with fixed 4-rune
// blocks and keeps the first 4 runes of the header segment, so log
// viewers can tell two different JWTs apart without exposing any claim.
func ExampleApply_jwtToken() {
	fmt.Println(mask.Apply(mask.RuleJWTToken, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"))
	// Output: eyJh****.****.****.
}

// ExampleApply_bearerToken masks an HTTP Authorization header value,
// preserving the `Bearer` scheme and the first 6 runes of the token so
// two different tokens produce distinguishable log output.
func ExampleApply_bearerToken() {
	fmt.Println(mask.Apply(mask.RuleBearerToken, "Bearer abc123def456"))
	// Output: Bearer abc123****...
}

// ExampleApply_urlCredentials redacts the userinfo segment of a URL
// (e.g. embedded basic-auth credentials) while preserving scheme, host,
// path, and query — useful when logging third-party service URLs that
// sometimes carry credentials inline.
func ExampleApply_urlCredentials() {
	fmt.Println(mask.Apply(mask.RuleURLCredentials, "https://admin:s3cret@db.example.com/mydb"))
	// Output: https://****:****@db.example.com/mydb
}

// ExampleApply_apiKey preserves the first 4 and last 4 runes of an API
// key (enough for log triage) and same-length-masks the middle.
func ExampleApply_apiKey() {
	fmt.Println(mask.Apply(mask.RuleAPIKey, "AKIAIOSFODNN7EXAMPLE"))
	// Output: AKIA************MPLE
}

// ExampleApply_password always emits a fixed 8-rune mask regardless of
// the source length so the password's length is not inferable from the
// masked output.
func ExampleApply_password() {
	fmt.Println(mask.Apply(mask.RulePassword, "MyP@ssw0rd!"))
	// Output: ********
}

// ExampleApply_phoneNumber preserves the country-code literal (`+NN`)
// and the last four digits while masking the rest.
func ExampleApply_phoneNumber() {
	fmt.Println(mask.Apply(mask.RulePhoneNumber, "+44 7911 123456"))
	// Output: +44 **** **3456
}

// ExampleApply_ukNINO preserves the 2-letter prefix and 1-letter suffix
// of a UK National Insurance Number, masking the six middle digits.
func ExampleApply_ukNINO() {
	fmt.Println(mask.Apply(mask.RuleUKNINO, "AB123456C"))
	// Output: AB******C
}

// ExampleApply_postalCode shows the shape-aware UK postcode masker:
// the outward code (`SW1A`) is preserved and the inward code is masked.
func ExampleApply_postalCode() {
	fmt.Println(mask.Apply(mask.RulePostalCode, "SW1A 2AA"))
	// Output: SW1A ***
}

// ExampleApply_geoCoordinates reduces a "lat,lon" pair to roughly 1.1 km
// precision by truncating each half to two decimal places.
func ExampleApply_geoCoordinates() {
	fmt.Println(mask.Apply(mask.RuleGeoCoordinates, "37.7749,-122.4194"))
	// Output: 37.77**,-122.41**
}

// ---------------------------------------------------------------------------
// Primitive worked examples. Use these inside a custom RuleFunc when the
// masking shape is exactly one primitive.
// ---------------------------------------------------------------------------

// ExampleKeepLastN keeps the last n runes and masks the rest.
func ExampleKeepLastN() {
	fmt.Println(mask.KeepLastN("Sensitive", 4, '*'))
	// Output: *****tive
}

// ExampleKeepFirstLast keeps the first and last runes, masks the middle —
// the typical shape for long account numbers.
func ExampleKeepFirstLast() {
	fmt.Println(mask.KeepFirstLast("SensitiveData", 4, 4, '*'))
	// Output: Sens*****Data
}

// ExamplePreserveDelimiters masks every rune except those listed in
// `delim`, which are kept verbatim. Useful when a format's separators
// carry structural meaning (e.g. the dashes in a card number).
func ExamplePreserveDelimiters() {
	fmt.Println(mask.PreserveDelimiters("AB-12-CD", "-", '*'))
	// Output: **-**-**
}

// ExampleReducePrecision reduces the decimal precision of a numeric
// string by masking trailing digits. Negative numbers keep their sign.
func ExampleReducePrecision() {
	fmt.Println(mask.ReducePrecision("37.7749295", 2, '*'))
	// Output: 37.77*****
}

// ---------------------------------------------------------------------------
// Factory worked examples. These return a RuleFunc ready for Register.
// ---------------------------------------------------------------------------

// ExampleReplaceRegexFunc shows the canonical "redact a free-text format
// not in the built-in catalogue" shape. The pattern is compiled once at
// factory-call time and the returned RuleFunc reuses the compiled matcher
// for every Apply. Go's `regexp` is RE2-backed, so there is no ReDoS risk.
func ExampleReplaceRegexFunc() {
	r, err := mask.ReplaceRegexFunc(`\d{6,}`, "[REDACTED]")
	if err != nil {
		panic(err) // an invalid pattern is a programmer bug
	}
	fmt.Println(r("Order #1234567 shipped"))
	// Output: Order #[REDACTED] shipped
}

// ExampleDeterministicHashFunc shows zero-option use of the hashing
// factory — output is a truncated SHA-256 hex digest with an algo
// prefix. For production pseudonymisation, pair with [WithKeyedSalt].
func ExampleDeterministicHashFunc() {
	r := mask.DeterministicHashFunc()
	fmt.Println(r("alice@example.com"))
	// Output: sha256:ff8d9819fc0e12bf
}

// ExampleDeterministicHashFunc_salted shows the keyed-hashing production
// path: one atomic `WithKeyedSalt(salt, version)` call configures both
// halves. The output format is `<algo>:<version>:<hex16>`. Load the
// salt from a secret store, not a literal — this example uses a literal
// only for runnability.
func ExampleDeterministicHashFunc_salted() {
	r := mask.DeterministicHashFunc(mask.WithKeyedSalt("example-salt", "v1"))
	out := r("alice@example.com")
	// The specific hex depends on HMAC-SHA256(salt, value); demonstrate
	// the stable output shape instead of pinning the exact digest.
	fmt.Println(strings.HasPrefix(out, "sha256:v1:") && len(out) == len("sha256:v1:")+16)
	// Output: true
}
