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

// ---------- email_address ----------

func TestApply_EmailAddress(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "alice@example.com", "a****@example.com"},
		{"plus subaddress", "bob.smith+work@company.co.uk", "b*************@company.co.uk"},
		{"single char local fails closed", "x@y.com", "*@y.com"},
		{"malformed no at", "not-an-email", "************"},
		{"empty", "", ""},
		{"empty local", "@example.com", "************"},
		{"empty domain", "alice@", "******"},
		{"at only", "@", "*"},
		{"multiple ats split on last", "a@b@c.com", "a**@c.com"},
		{"preserve case in domain", "Alice@EXAMPLE.COM", "A****@EXAMPLE.COM"},
		{"unicode local single rune", "佐@example.com", "*@example.com"},
		{"unicode local multi rune", "佐藤@example.com", "佐*@example.com"},
		{"already masked", "****@example.com", "****@example.com"},
		{"whitespace only", "   ", "***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("email_address", tc.in))
		})
	}
}

func TestApply_EmailAddress_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.Equal(t, "aXXXX@example.com", m.Apply("email_address", "alice@example.com"))
}

// ---------- person_name ----------

func TestApply_PersonName(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "John Doe", "J*** D**"},
		{"accented with hyphen", "María García-López", "M**** G*****-L****"},
		{"apostrophe separator", "D'Angelo Smith", "D'A***** S****"},
		{"empty", "", ""},
		{"single rune fails closed", "A", "*"},
		{"whitespace only", "  ", "**"},
		{"double space preserved", "John  Doe", "J***  D**"},
		{"leading separator", "-John", "-J***"},
		{"o brien family", "O'Brien", "O'B****"},
		// CJK without separators is a documented deviation from the spec
		// example (佐藤太郎 → 佐*太* requires a language-aware segmenter). We
		// treat CJK-without-space as a single token. Pinned here so the
		// behaviour does not regress silently; see godoc on maskPersonName.
		{"cjk single token deviation", "佐藤太郎", "佐***"},
		{"cjk with space", "佐藤 太郎", "佐* 太*"},
		{"period not a separator", "J. Doe", "J* D**"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("person_name", tc.in))
		})
	}
}

// ---------- given_name / family_name ----------

func TestApply_GivenName(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "Alice", "A****"},
		{"accented", "María", "M****"},
		{"cjk", "佐藤", "佐*"},
		{"empty", "", ""},
		{"single rune fails closed", "A", "*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("given_name", tc.in))
		})
	}
}

func TestApply_FamilyName(t *testing.T) {
	t.Parallel()
	m := mask.New()
	assert.Equal(t, "S****", m.Apply("family_name", "Smith"))
	assert.Equal(t, "O******", m.Apply("family_name", "O'Brien"))
	assert.Equal(t, "", m.Apply("family_name", ""))
	// Single-rune input fails closed to a same-length mask so the
	// identifier is never echoed verbatim.
	assert.Equal(t, "*", m.Apply("family_name", "A"))
}

// ---------- street_address ----------

func TestApply_StreetAddress(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "42 Wallaby Way", "42 ******* Way"},
		{"multi word suffix", "1600 Pennsylvania Avenue NW", "1600 ************ Avenue NW"},
		{"no suffix keep leading digits", "42 Main", "42 ****"},
		{"suffix at start not recognised", "Way 42", "******"},
		{"empty", "", ""},
		{"digits only fails closed", "42", "**"},
		{"digits with trailing space fails closed", "42 ", "***"},
		{"case insensitive suffix", "42 Wallaby way", "42 ******* way"},
		{"suffix trailing period tolerated", "42 Wallaby St.", "42 ******* St."},
		{"no signals fallback", "Apt 3", "*****"},
		// Arabic-Indic digits are not recognised as a house number (ASCII
		// only), so the leading digit run is 0. The trailing "Ave" still
		// matches, so the rule masks the body rune-wise and keeps the
		// trailing type.
		{"arabic indic digits no house number", "١٦٠٠ Pennsylvania Ave", "**** ************ Ave"},
		// Regression: a recognised single-letter direction token ("N",
		// "S", "E", "W") must not consume the entire body and echo the
		// input. Fail-closed guard in maskStreet converts these to a
		// masked tail.
		{"single letter direction alone", "42 N", "42 *"},
		{"compass pair alone", "1 NE", "1 **"},
		{"all direction tokens", "42 N S E W", "42 * * * *"},
		// Pin the head == "" arm of the fail-closed guard: a bare
		// recognised suffix with no house number must not echo.
		{"bare direction no house number", "N", "*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("street_address", tc.in))
		})
	}
}

// ---------- date_of_birth ----------

func TestApply_DateOfBirth(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"iso canonical", "1985-03-15", "1985-**-**"},
		{"iso single digit month and day", "1985-3-5", "1985-*-*"},
		{"slash spec example", "15/03/1985", "**/**/1985"},
		{"slash single digit day month", "5/3/1985", "*/*/1985"},
		{"slash single digit day, two digit month", "1/10/2000", "*/**/2000"},
		{"slash two digit day, single digit month", "10/1/2000", "**/*/2000"},
		{"slash both two digit", "10/10/2000", "**/**/2000"},
		{"slash zero padded", "01/01/2000", "**/**/2000"},
		{"month name canonical", "March 15, 1985", "***** **, 1985"},
		{"month name case insensitive", "march 15, 1985", "***** **, 1985"},
		{"year only fallback", "1985", "****"},
		{"iso with time fallback", "1985-03-15T00:00:00Z", "********************"},
		{"dotted european fallback", "15.03.1985", "**********"},
		{"slashed iso fallback", "1985/03/15", "**********"},
		{"month name with suffix fallback", "March 15, 1985, AD", "******************"},
		{"empty", "", ""},
		// No semantic validation of the date itself.
		{"syntactically valid garbage", "0000-00-00", "0000-**-**"},
		{"syntactically valid nonsense", "9999-99-99", "9999-**-**"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("date_of_birth", tc.in))
		})
	}
}

// ---------- username ----------

func TestApply_Username(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "johndoe42", "jo*******"},
		{"short", "admin", "ad***"},
		{"two runes fails closed", "ab", "**"},
		{"single rune fails closed", "a", "*"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("username", tc.in))
		})
	}
}

// ---------- passport_number ----------

func TestApply_PassportNumber(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"alpha prefix", "GB1234567", "GB*****67"},
		{"numeric only", "123456789", "*****6789"},
		{"lowercase alpha prefix", "gb1234567", "gb*****67"},
		{"mixed prefix falls to numeric branch", "1A234567", "****4567"},
		{"single digit prefix numeric branch", "A1234567", "****4567"},
		{"all digits short", "12345", "*2345"},
		{"alpha prefix shorter than keep window fails closed", "GB", "**"},
		{"numeric shorter than keep window fails closed", "1234", "****"},
		{"alpha prefix four runes fails closed", "GBCD", "****"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("passport_number", tc.in))
		})
	}
}

// ---------- driver_license_number ----------

func TestApply_DriverLicenseNumber(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"dashed short", "DL-1234-5678", "DL-****-5678"},
		// SMITH901015JN9AA has 16 non-separator runes. Rule branch is ≥ 13 →
		// keep last 3. Output preserves length: 2 first + 11 masked + 3 last
		// = 16. An earlier draft of the requirements doc showed
		// SM**********9AA (15 chars) — believed to be a typo; we follow
		// the stronger length-preservation invariant here.
		{"spec long length preserved", "SMITH901015JN9AA", "SM***********9AA"},
		// Fail-closed: inputs whose non-separator count would be fully
		// covered by the keep window now mask rather than echo. The
		// SameLengthMask path replaces separator runes with the mask rune
		// too, since once the rule has decided the whole input is too
		// short to preserve structurally, preserving separators only
		// would be misleading.
		{"separators only fails closed", "---", "***"},
		{"single separator fails closed", "A-B", "***"},
		{"empty", "", ""},
		{"only non separator short fails closed", "AB", "**"},
		{"space separated fails closed", "A B C D E", "*********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("driver_license_number", tc.in))
		})
	}
}

// ---------- generic_national_id ----------

func TestApply_GenericNationalID(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "AB123456CD", "AB******CD"},
		{"four runes fails closed", "ABCD", "****"},
		{"three runes fails closed", "AB1", "***"},
		{"five runes one masked", "ABCDE", "AB*DE"},
		{"cjk", "佐藤1234太郎", "佐藤****太郎"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("generic_national_id", tc.in))
		})
	}
}

// ---------- tax_identifier ----------

func TestApply_TaxIdentifier(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "12-3456789", "**-***6789"},
		{"four digits", "1234", "*234"},
		// Fail-closed: ≤ 3 non-separator runes means the keep window would
		// span the full input, so the rule masks instead of echoing.
		{"three digits fails closed", "123", "***"},
		{"exactly eight keeps last four", "12345678", "****5678"},
		{"empty", "", ""},
		// 0 non-sep runes — SameLengthMask masks the separators too.
		{"separators only fails closed", "--", "**"},

		// 11 non-separator digits, rule keeps last 4 → "8", "9", "1", "0".
		{"brazilian style cpf shape", "123.456.789-10", "***.***.*89-10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("tax_identifier", tc.in))
		})
	}
}

// ---------- registrations and metadata ----------

func TestDescribe_IdentityRules(t *testing.T) {
	t.Parallel()
	m := mask.New()
	names := []string{
		"email_address", "person_name", "given_name", "family_name",
		"street_address", "date_of_birth", "username", "passport_number",
		"driver_license_number", "generic_national_id", "tax_identifier",
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			info, ok := m.Describe(n)
			require.True(t, ok, "rule %q not registered", n)
			assert.Equal(t, "identity", info.Category)
			assert.NotEmpty(t, info.Jurisdiction)
			assert.NotEmpty(t, info.Description)
			assert.Equal(t, n, info.Name)
		})
	}
}

func TestIdentity_FailClosedOnEveryRule(t *testing.T) {
	t.Parallel()
	m := mask.New()
	// Every rule must either return the empty string for empty input or
	// not echo a long malformed value verbatim. Rules that correctly return
	// short inputs unchanged (per spec, e.g. email_address single-rune
	// local) are not covered by this sweep; use `strings.Repeat` to build
	// inputs long enough to trigger their masking path.
	longMalformed := strings.Repeat("z", 50)
	for _, n := range []string{
		"email_address", "person_name", "street_address", "date_of_birth",
		"passport_number", "driver_license_number", "generic_national_id",
		"tax_identifier",
	} {
		got := m.Apply(n, longMalformed)
		assert.NotEqual(t, longMalformed, got, "rule %q echoed the input verbatim", n)
	}
}

func TestIdentity_NoPanicOnAdversarialInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	adversarial := []string{
		"",
		"\xff\xfe\xfd",
		"\x00",
		strings.Repeat("x", 1000),
		"D'\u202Eevil", // RTL override
		"\U0001F468\u200D\U0001F469\u200D\U0001F467", // ZWJ family
	}
	for _, n := range []string{
		"email_address", "person_name", "given_name", "family_name",
		"street_address", "date_of_birth", "username", "passport_number",
		"driver_license_number", "generic_national_id", "tax_identifier",
	} {
		for _, in := range adversarial {
			var got string
			assert.NotPanics(t, func() { got = m.Apply(n, in) },
				"rule %q panicked on input %q", n, in)
			assert.True(t, utf8.ValidString(got),
				"rule %q produced invalid UTF-8 for input %q: %q", n, in, got)
		}
	}
}
