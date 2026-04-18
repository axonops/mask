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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/mask"
)

// countryRuleNames is the authoritative list used by cross-cutting
// matrices below and by TestDescribe_CountryRules.
var countryRuleNames = []string{
	"us_ssn", "ca_sin", "uk_nino", "in_aadhaar", "in_pan",
	"au_medicare_number", "sg_nric_fin", "br_cpf", "br_cnpj",
	"mx_curp", "mx_rfc", "cn_resident_id", "za_national_id",
	"es_dni_nif_nie",
}

// ---------- us_ssn ----------

func TestApply_USSSN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec hyphenated", "123-45-6789", "***-**-6789"},
		{"spec compact", "123456789", "*****6789"},
		{"empty", "", ""},
		{"wrong hyphen positions fails closed", "12-345-6789", "***********"},
		{"eight digits fails closed", "12345678", "********"},
		{"ten digits fails closed", "1234567890", "**********"},
		{"letters fail closed", "abc-de-6789", "***********"},
		// Real-world variants: extraneous whitespace is not accepted
		// by the canonical-shape validator — must fail closed.
		{"leading whitespace fails closed", " 123-45-6789", "************"},
		{"trailing whitespace fails closed", "123-45-6789 ", "************"},
		{"tab separator fails closed", "123\t45\t6789", "***********"},
		{"embedded nul fails closed", "123-45-67\x0089", "************"},
		// Only hyphen is a valid separator — en-dash and Unicode
		// minus must fail closed.
		{"en-dash separators fail closed", "123\u201345\u20136789", "***********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("us_ssn", tc.in))
		})
	}
}

// ---------- ca_sin ----------

func TestApply_CASIN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec hyphenated", "123-456-789", "***-***-789"},
		{"spec compact", "123456789", "******789"},
		{"empty", "", ""},
		{"wrong hyphen positions fails closed", "1234-56-789", "***********"},
		{"eight digits fails closed", "12345678", "********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("ca_sin", tc.in))
		})
	}
}

// ---------- uk_nino ----------

func TestApply_UKNINO(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec compact", "AB123456C", "AB******C"},
		{"spec spaced", "AB 12 34 56 C", "AB ** ** ** C"},
		{"empty", "", ""},
		{"lowercase fails closed", "ab123456c", "*********"},
		{"no suffix fails closed", "AB1234567", "*********"},
		{"no prefix fails closed", "1B123456C", "*********"},
		{"too short fails closed", "AB12345C", "********"},
		{"missing space fails closed", "AB1234 56 C", "***********"},
		// Spaced form with wrong space positions must fail closed —
		// exercises the isSpacedUKNINO early-exit branch where v is
		// 13 bytes but the spacer indexes are wrong.
		{"spaced wrong positions fails closed", "A B12 34 56C ", "*************"},
		// Real-world hyphenated form is not accepted.
		{"hyphenated fails closed", "AB-12-34-56-C", "*************"},
		// Trailing lowercase suffix letter fails closed.
		{"compact trailing lowercase fails closed", "AB123456c", "*********"},
		// NINO with lowercase leading letters (common copy-paste).
		{"spaced lowercase fails closed", "ab 12 34 56 C", "*************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("uk_nino", tc.in))
		})
	}
}

// ---------- in_aadhaar ----------

func TestApply_INAadhaar(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec grouped", "1234 5678 9012", "**** **** 9012"},
		{"spec compact", "123456789012", "********9012"},
		{"empty", "", ""},
		{"eleven digits fails closed", "12345678901", "***********"},
		{"wrong grouping fails closed", "12345 6789 012", "**************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("in_aadhaar", tc.in))
		})
	}
}

// ---------- in_pan ----------

func TestApply_INPAN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "ABCDE1234F", "ABC*****4F"},
		{"empty", "", ""},
		{"lowercase fails closed", "abcde1234f", "**********"},
		{"wrong letter count fails closed", "ABCD1234FG", "**********"},
		{"nine chars fails closed", "ABCDE1234", "*********"},
		// Letters where digits should be — exercises the v[5:9]
		// all-digits branch of isValidINPAN that was otherwise
		// unreachable via other cases.
		{"letters in digit block fails closed", "ABCDEXXXXF", "**********"},
		// Trailing position must be an upper letter.
		{"trailing digit fails closed", "ABCDE12345", "**********"},
		// Lowercase trailing letter.
		{"trailing lowercase fails closed", "ABCDE1234f", "**********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("in_pan", tc.in))
		})
	}
}

// ---------- au_medicare_number ----------

func TestApply_AUMedicareNumber(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec grouped", "2123 45670 1", "**** ****0 1"},
		{"compact", "2123456701", "********01"},
		{"empty", "", ""},
		{"nine digits fails closed", "212345670", "*********"},
		{"wrong grouping fails closed", "21234 5670 1", "************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("au_medicare_number", tc.in))
		})
	}
}

// ---------- sg_nric_fin ----------

func TestApply_SGNRICFIN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "S1234567A", "S*******A"},
		{"lowercase fails closed", "s1234567a", "*********"},
		{"empty", "", ""},
		{"too short fails closed", "S123A", "*****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("sg_nric_fin", tc.in))
		})
	}
}

// ---------- br_cpf ----------

func TestApply_BRCPF(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		// spec canonical: keep last 2 digits
		{"spec canonical formatted", "123.456.789-09", "***.***.***-09"},
		// deliberate deviation from the spec's unformatted example:
		// the spec shows last-4-kept (`*******8909`) for the same
		// rule that keeps last-2 for the formatted case. We honour
		// "last 2" consistently to match the check-digit convention.
		{"compact keeps last 2", "12345678909", "*********09"},
		// Leading-zero CPFs are valid and common (CPF check digits
		// permit any 2-digit prefix).
		{"leading zero formatted", "001.234.567-89", "***.***.***-89"},
		{"leading zero compact", "00123456789", "*********89"},
		{"empty", "", ""},
		{"ten digits fails closed", "1234567890", "**********"},
		{"wrong punctuation fails closed", "123-456-789.09", "**************"},
		// Only `.` and `-` are canonical CPF separators — spaces
		// and slashes must fail closed.
		{"spaced fails closed", "123 456 789 09", "**************"},
		{"slash fails closed", "123/456/789-09", "**************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("br_cpf", tc.in))
		})
	}
}

// ---------- br_cnpj ----------

func TestApply_BRCNPJ(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "12.345.678/0001-95", "**.***.***/****-95"},
		{"compact keeps last 2", "12345678000195", "************95"},
		{"empty", "", ""},
		{"wrong length fails closed", "12.345.678/0001-9", "*****************"},
		// Exercises the isFormattedBRCNPJ early-exit where v is
		// 18 bytes but one of the punctuation positions is wrong.
		{"wrong punctuation fails closed", "12-345.678/0001-95", "******************"},
		{"dash instead of slash fails closed", "12.345.678-0001-95", "******************"},
		// Digit where punctuation is expected.
		{"digit at separator fails closed", "123456.678/0001-95", "******************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("br_cnpj", tc.in))
		})
	}
}

// ---------- mx_curp ----------

func TestApply_MXCURP(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		// Spec's 10-star output would be 17 chars for an 18-char
		// input; we emit 11 stars to preserve same-length output.
		{"spec same-length", "GAPA850101HDFRRL09", "GAPA***********L09"},
		{"empty", "", ""},
		{"lowercase fails closed", "gapa850101hdfrrl09", "******************"},
		{"wrong length fails closed", "GAPA850101HDFRRL0", "*****************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("mx_curp", tc.in))
		})
	}
}

// ---------- mx_rfc ----------

func TestApply_MXRFC(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec individual 13", "GAPA8501014T3", "GAP*******4T3"},
		{"company 12", "ABC850101DEF", "ABC******DEF"},
		// Anonymous foreign-buyer RFC — all digits in the middle.
		{"anonymous foreign buyer", "XAXX010101000", "XAX*******000"},
		{"empty", "", ""},
		{"wrong length fails closed", "ABC", "***"},
		{"length 11 fails closed", "GAPA850101D", "***********"},
		{"length 14 fails closed", "GAPA850101DEFG", "**************"},
		{"lowercase fails closed", "gapa8501014t3", "*************"},
		{"contains hyphen fails closed", "GAPA-85010-14T3", "***************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("mx_rfc", tc.in))
		})
	}
}

// ---------- cn_resident_id ----------

func TestApply_CNResidentID(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "110101199003074578", "110101********4578"},
		{"last char X uppercase", "11010119900307457X", "110101********457X"},
		{"last char x lowercase", "11010119900307457x", "110101********457x"},
		{"empty", "", ""},
		{"seventeen digits fails closed", "11010119900307457", "*****************"},
		{"non-digit in body fails closed", "1101011990030745X8", "******************"},
		// Real-world variants: hyphen-grouped Chinese IDs are not
		// a canonical form — must fail closed.
		{"hyphenated fails closed", "110101-19900307-457X", "********************"},
		{"leading whitespace fails closed", " 110101199003074578", "*******************"},
		{"letter other than X fails closed", "11010119900307457Y", "******************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("cn_resident_id", tc.in))
		})
	}
}

// ---------- za_national_id ----------

func TestApply_ZANationalID(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "8501015009087", "850101***9087"},
		{"empty", "", ""},
		{"twelve digits fails closed", "850101500908", "************"},
		{"fourteen digits fails closed", "85010150090876", "**************"},
		{"letters fail closed", "8501015ABC087", "*************"},
		// Real-world variants: spaced or hyphenated forms are not
		// accepted — must fail closed.
		{"spaced fails closed", "850101 5009 087", "***************"},
		{"hyphenated fails closed", "850101-5009-087", "***************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("za_national_id", tc.in))
		})
	}
}

// ---------- es_dni_nif_nie ----------

func TestApply_ESDNINIFNIE(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec dni", "12345678Z", "********Z"},
		{"spec nie", "X1234567L", "X*******L"},
		{"nie with Y prefix", "Y1234567M", "Y*******M"},
		{"nie with Z prefix", "Z1234567N", "Z*******N"},
		{"empty", "", ""},
		{"missing trailing letter fails closed", "123456789", "*********"},
		{"lowercase trailing fails closed", "12345678z", "*********"},
		{"letter in middle fails closed", "12A45678Z", "*********"},
		// 9 characters but neither DNI (8 digits + letter) nor NIE
		// (letter + 7 digits + letter) — all upper letters for
		// example. Exercises the final SameLengthMask fallback of
		// maskESDNINIFNIE after both shape branches miss.
		{"all letters fails closed", "ABCDEFGHI", "*********"},
		// Leading letter without 7 digits in body.
		{"nie malformed body fails closed", "XAB34567L", "*********"},
		// Real-world variant: hyphenated DNI is not accepted.
		{"hyphenated fails closed", "12345678-Z", "**********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("es_dni_nif_nie", tc.in))
		})
	}
}

// ---------- mask-character override ----------

func TestCountry_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	cases := []struct{ rule, in, want string }{
		{"us_ssn", "123-45-6789", "XXX-XX-6789"},
		{"ca_sin", "123-456-789", "XXX-XXX-789"},
		{"uk_nino", "AB123456C", "ABXXXXXXC"},
		{"in_aadhaar", "1234 5678 9012", "XXXX XXXX 9012"},
		{"in_pan", "ABCDE1234F", "ABCXXXXX4F"},
		{"au_medicare_number", "2123 45670 1", "XXXX XXXX0 1"},
		{"sg_nric_fin", "S1234567A", "SXXXXXXXA"},
		{"br_cpf", "123.456.789-09", "XXX.XXX.XXX-09"},
		{"br_cnpj", "12.345.678/0001-95", "XX.XXX.XXX/XXXX-95"},
		{"mx_curp", "GAPA850101HDFRRL09", "GAPAXXXXXXXXXXXL09"},
		{"mx_rfc", "GAPA8501014T3", "GAPXXXXXXX4T3"},
		{"cn_resident_id", "110101199003074578", "110101XXXXXXXX4578"},
		{"za_national_id", "8501015009087", "850101XXX9087"},
		{"es_dni_nif_nie", "12345678Z", "XXXXXXXXZ"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply(tc.rule, tc.in))
		})
	}
}

// ---------- registrations and metadata ----------

func TestDescribe_CountryRules(t *testing.T) {
	t.Parallel()
	m := mask.New()
	for _, n := range countryRuleNames {
		t.Run(n, func(t *testing.T) {
			info, ok := m.Describe(n)
			require.True(t, ok, "rule %q not registered", n)
			assert.Equal(t, "identity", info.Category)
			assert.NotEmpty(t, info.Jurisdiction)
			assert.Equal(t, n, info.Name)
			assert.Contains(t, info.Description, "Example:",
				"rule %q description must include an Example", n)
		})
	}
}

// TestCountry_FailClosedOnMalformed confirms every rule produces a
// same-length mask on a malformed input and never echoes the input.
func TestCountry_FailClosedOnMalformed(t *testing.T) {
	t.Parallel()
	m := mask.New()
	malformed := "totally-not-a-jurisdictional-id-xyz"
	for _, n := range countryRuleNames {
		t.Run(n, func(t *testing.T) {
			got := m.Apply(n, malformed)
			assert.NotEqual(t, malformed, got, "rule %q echoed malformed input", n)
			assert.Equal(t, strings.Repeat("*", utf8.RuneCountInString(malformed)), got,
				"rule %q did not produce same-length mask on malformed input", n)
		})
	}
}

// TestCountry_NoPanicOnAdversarialInput mirrors the phase 4a-e
// contract — every rule must handle adversarial bytes without
// panicking and emit well-formed UTF-8.
//
// The adversarial corpus deliberately includes invalid-UTF-8 byte
// sequences at every canonical-shape length used by the country
// validators (9, 10, 11, 12, 13, 14, 18) so that every length-
// branch of every validator is probed with bytes that would pass
// the length check but fail the content check.
func TestCountry_NoPanicOnAdversarialInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	invalidUTF8 := func(n int) string {
		return strings.Repeat("\xff", n)
	}
	adversarial := []string{
		"",
		"\xff\xfe\xfd",
		"\x00",
		strings.Repeat("9", 500),
		"\u200B123-45-6789",
		"\u202E123456789",
		"AB 12 34 56 \u00a0C",
		// Length-targeted invalid UTF-8 — one per canonical length.
		invalidUTF8(9),  // us_ssn, ca_sin, uk_nino compact, sg_nric_fin, es_dni_nif_nie
		invalidUTF8(10), // au_medicare_number compact, in_pan
		invalidUTF8(11), // us_ssn spaced, ca_sin spaced, br_cpf compact
		invalidUTF8(12), // au_medicare_number spaced, in_aadhaar compact, mx_rfc
		invalidUTF8(13), // uk_nino spaced, mx_rfc, za_national_id
		invalidUTF8(14), // in_aadhaar spaced, br_cpf formatted, br_cnpj compact
		invalidUTF8(18), // mx_curp, br_cnpj formatted, cn_resident_id
		// A surrogate half would be invalid if present — guarded
		// by length checks in all rules.
		"\xed\xa0\x80\xed\xa0\x80\xed\xa0\x80",
	}
	for _, n := range countryRuleNames {
		for _, in := range adversarial {
			var got string
			assert.NotPanics(t, func() { got = m.Apply(n, in) },
				"rule %q panicked on input %q", n, in)
			assert.True(t, utf8.ValidString(got),
				"rule %q produced invalid UTF-8 for input %q: %q", n, in, got)
		}
	}
}

// TestCountry_MaskCharOverride_FailClosed confirms the configured
// mask rune flows through the fail-closed path as well as the
// canonical path — a malformed input masked with override char 'X'
// must be X-filled, not '*'-filled.
func TestCountry_MaskCharOverride_FailClosed(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	malformed := "totally-not-an-id"
	want := strings.Repeat("X", utf8.RuneCountInString(malformed))
	for _, n := range countryRuleNames {
		t.Run(n, func(t *testing.T) {
			got := m.Apply(n, malformed)
			assert.Equal(t, want, got,
				"rule %q did not honour override mask rune on fallback", n)
		})
	}
}

// TestCountry_CountryRuleNamesDriftGuard ensures countryRuleNames —
// the slice all cross-cutting matrices iterate over — stays in sync
// with the actual registration table. If a new country rule is
// added without adding it here, this test fails immediately; no
// matrix is silently narrower than the catalogue.
func TestCountry_CountryRuleNamesDriftGuard(t *testing.T) {
	t.Parallel()
	m := mask.New()
	for _, n := range countryRuleNames {
		info, ok := m.Describe(n)
		require.True(t, ok, "countryRuleNames entry %q is not registered", n)
		require.Equal(t, "identity", info.Category,
			"rule %q is in countryRuleNames but is not category=identity", n)
		require.False(t, strings.HasPrefix(info.Jurisdiction, "global"),
			"rule %q is in countryRuleNames but has global jurisdiction %q",
			n, info.Jurisdiction)
	}
	// Inverse: every identity rule with a concrete (non-`global`)
	// jurisdiction must be in countryRuleNames. Rules in
	// rules_identity.go all carry `global` or `global (…)`.
	names := map[string]bool{}
	for _, n := range countryRuleNames {
		names[n] = true
	}
	for _, ruleName := range m.Rules() {
		info, ok := m.Describe(ruleName)
		if !ok || info.Category != "identity" {
			continue
		}
		if strings.HasPrefix(info.Jurisdiction, "global") || info.Jurisdiction == "" {
			continue
		}
		assert.True(t, names[ruleName],
			"rule %q has Jurisdiction=%q but is missing from countryRuleNames",
			ruleName, info.Jurisdiction)
	}
}

// TestCountry_IdempotencyMatrix: every rule is non-idempotent
// because the mask rune is not a valid digit / letter in any of
// the canonical-shape validators — a second pass collapses to
// SameLengthMask.
func TestCountry_IdempotencyMatrix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in string }{
		{"us_ssn", "123-45-6789"},
		{"ca_sin", "123-456-789"},
		{"uk_nino", "AB123456C"},
		{"in_aadhaar", "1234 5678 9012"},
		{"in_pan", "ABCDE1234F"},
		{"au_medicare_number", "2123 45670 1"},
		{"sg_nric_fin", "S1234567A"},
		{"br_cpf", "123.456.789-09"},
		{"br_cnpj", "12.345.678/0001-95"},
		{"mx_curp", "GAPA850101HDFRRL09"},
		{"mx_rfc", "GAPA8501014T3"},
		{"cn_resident_id", "110101199003074578"},
		{"za_national_id", "8501015009087"},
		{"es_dni_nif_nie", "12345678Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := m.Apply(tc.name, tc.in)
			second := m.Apply(tc.name, first)
			assert.NotEqual(t, first, second,
				"rule %q was expected to be non-idempotent", tc.name)
		})
	}
}
