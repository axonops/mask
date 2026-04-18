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
