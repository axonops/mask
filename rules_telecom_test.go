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

// ---------- phone_number ----------

func TestApply_PhoneNumber(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec e164 uk", "+44 7911 123456", "+44 **** **3456"},
		{"spec parens us", "(555) 123-4567", "(***) ***-4567"},
		{"spec e164 us", "+1-800-555-0199", "+1-***-***-0199"},
		{"empty", "", ""},
		{"plus alone fails closed", "+", "*"},
		{"plus then separator fails closed", "+ 7911", "******"},
		{"body with fewer than four digits fails closed", "+44 12", "******"},
		{"body exactly four digits keeps whole tail", "+44 1234", "********"},
		{"body five digits keeps last four", "+44 12345", "+44 *2345"},
		{"letters fail closed", "1-800-FLOWERS", "*************"},
		{"arabic-indic digits fail closed", "٠٧٩١١ ١٢٣٤٥٦", "************"},
		{"nbsp separator fails closed", "+44\u00a07911 123456", "***************"},
		{"nul byte fails closed", "+44 7911\x00123456", "***************"},
		{"four digit country code fails closed", "+1234 567 8901", "**************"},
		{"trailing space fails closed", "+44 7911 123456 ", "****************"},
		{"trailing hyphen fails closed", "(555) 123-4567-", "***************"},
		{"leading hyphen fails closed", "-(555) 123-4567", "***************"},
		{"bare country code fails closed", "+44", "***"},
		{"double plus fails closed", "++44 7911", "*********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("phone_number", tc.in))
		})
	}
}

func TestApply_MobilePhoneNumber_Alias(t *testing.T) {
	t.Parallel()
	m := mask.New()
	// mobile_phone_number is an alias for phone_number — identical
	// output for every input, per the spec's "prefer one
	// international abstraction" guidance.
	cases := []string{
		"+44 7911 123456",
		"(555) 123-4567",
		"07911 123456",
		"0044 7911 123456",
		"",
		"nonsense",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, m.Apply("phone_number", in), m.Apply("mobile_phone_number", in))
		})
	}
}

// TestApply_phone_number_00_prefix exercises the `00<CC>` international
// access prefix path added for #55. Expected values are derived by
// applying the same masking pipeline as the `+<CC>` form: the prefix
// (including the `00` and the terminating separator when present) is
// echoed verbatim, every body digit except the last 4 is masked, and
// structural separators are preserved.
//
// Where the issue's hand-traced expected outputs disagree with this
// length-preserving rule (the multi-segment `0033 1 42 86 83 26` /
// `00352 26 12 34` cases), the test follows the rule, not the issue —
// the contract is "treat 00 as equivalent to +", and the actual `+`
// output for the parallel input is what defines that contract.
func TestApply_phone_number_00_prefix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spaced", "0044 7911 123456", "0044 **** **3456"},
		{"compact", "00441234567890", "00441*****7890"},
		{"dashed", "001-212-555-0100", "001-***-***-0100"},
		{"short_country_1_digit_cc", "001 555 0100", "001 *** 0100"},
		{"long_country", "00352 26 12 34", "00352 ** 12 34"},
		{"france_spaced", "0033 1 42 86 83 26", "0033 * ** ** 83 26"},
		{"compact_dashed", "001-555-0100", "001-***-0100"},
		{"00_alone", "00", "**"},
		{"00_country_only", "007", "***"},
		{"00_cc_only_no_body", "0044", "****"},
		{"domestic_0_not_affected", "07911 123456", "***** **3456"},
		{"no_cc_before_separator", "00 7911 123456", "** **** **3456"},
		// `"00 "` and `"00-"` route through the empty-prefix branch
		// (v[2] is not an ASCII digit, so split00Prefix is not
		// entered), then SameLengthMask collapses the input because
		// the body fails isTelecomBody on a trailing separator.
		{"00_then_separator_no_cc", "00 ", "***"},
		{"00_then_dash_no_cc", "00-", "***"},
		{"00_nul_at_v2", "00\x00", "***"},
		{"leading_zero_cc", "00044 7911 123456", "***** **** **3456"},
		// 4-digit "CC" in spaced form: v[2]=' ' is not a digit, so
		// split00Prefix isn't entered. The whole input becomes the
		// body, which IS well-formed (digit+sep+digit), so masking
		// proceeds normally — surprising but documented.
		{"spaced_4_digit_cc_routes_to_empty_prefix", "00 1234 5678901", "** **** ***8901"},
		// Letter inside a body that follows a successfully-parsed 00CC
		// prefix — split00Prefix returns the prefix, then isTelecomBody
		// rejects the body, then SameLengthMask collapses the whole.
		{"valid_00cc_then_letter_in_body", "00441234A567", "************"},
		// Compact form has inherent CC-length ambiguity. The parser
		// greedily consumes up to ccMaxDigits CC digits, so an input
		// like "001234567 8901" is interpreted as CC=123 (not CC=1,
		// 12, or 1234). Documented behaviour, not a bug — the issue's
		// stated heuristic is "same as the + path", and the + path
		// caps at 3 digits too. Pins the actual output so future
		// changes are visible.
		{"compact_greedy_three_digit_cc", "001234567 8901", "00123**** 8901"},
		{"compact_short_body", "0044123", "*******"},
		{"compact_body_exactly_four", "00441234", "********"},
		{"trailing_space_fails_closed", "0044 7911 123456 ", "*****************"},
		{"trailing_separator_fails_closed", "0044-", "*****"},
		{"nbsp_after_prefix_fails_closed", "0044 7911 123456", "****************"},
		{"nul_byte_fails_closed", "0044\x007911 123456", "****************"},
		{"arabic_indic_body_fails_closed", "0044 ٠٧٩١١ ١٢٣٤٥٦", "*****************"},
		// `é` is one rune (two bytes). SameLengthMask emits one mask
		// rune per input rune, so the expected length is 17 chars
		// (not 18 bytes).
		{"multibyte_after_prefix_fails_closed", "0044é 7911 123456", "*****************"},
		// ASCII control byte (BEL, \x07) after a valid 00CC — exercises
		// the same non-digit non-separator return path of split00Prefix
		// as the multibyte case, but with a single-byte rune.
		{"control_byte_after_cc_fails_closed", "0044\x07 7911 123456", "*****************"},
		// `+` after a valid 00CC — `+` is not a telecom separator, so
		// split00Prefix returns false. Pins behaviour against any
		// future change that adds `+` to the separator set.
		{"plus_after_cc_fails_closed", "0044+7911", "*********"},
		// Devanagari zero (U+0966, bytes 0xE0 0xA5 0xA6) inside the CC
		// window. The leading byte 0xE0 fails isASCIIDecDigit so the
		// loop exits, and 0xE0 is also not a telecom separator, so the
		// fail-closed arm fires. Pins the ASCII-only digit gate
		// against any future widening to unicode.IsDigit.
		{"unicode_digit_in_cc_window_fails_closed", "00०44 7911 123456", "*****************"},
		// Symmetric `+` branch case: a non-separator non-digit byte
		// directly after `+CC` fails closed. Mirrors
		// `control_byte_after_cc_fails_closed` on the `+` path so the
		// two branches stay in step.
		{"plus_then_non_separator_fails_closed", "+44A", "****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("phone_number", tc.in), "input %q", tc.in)
		})
	}
}

// TestApply_phone_number_00_prefix_spaced is named after the issue
// acceptance criterion verbatim so the issue-closer agent can match
// the AC text directly. Behaviour is exercised by the umbrella test;
// this is a thin assertion for traceability.
func TestApply_phone_number_00_prefix_spaced(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "0044 **** **3456", mask.New().Apply("phone_number", "0044 7911 123456"))
}

func TestApply_phone_number_00_prefix_compact(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "00441*****7890", mask.New().Apply("phone_number", "00441234567890"))
}

func TestApply_phone_number_00_prefix_dashed(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "001-***-***-0100", mask.New().Apply("phone_number", "001-212-555-0100"))
}

func TestApply_phone_number_00_prefix_short_country(t *testing.T) {
	t.Parallel()
	// 1-digit country code (US/NANP) with space separators — distinct
	// shape from the dashed variant.
	assert.Equal(t, "001 *** 0100", mask.New().Apply("phone_number", "001 555 0100"))
}

func TestApply_phone_number_00_prefix_long_country(t *testing.T) {
	t.Parallel()
	// 3-digit country code (Luxembourg). See the docstring on
	// TestApply_phone_number_00_prefix for the rationale on why the
	// expected output is "00352 ** 12 34" rather than the issue's
	// hand-traced "00352 ** **34".
	assert.Equal(t, "00352 ** 12 34", mask.New().Apply("phone_number", "00352 26 12 34"))
}

func TestApply_phone_number_00_alone(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "**", mask.New().Apply("phone_number", "00"))
}

func TestApply_phone_number_00_country_only(t *testing.T) {
	t.Parallel()
	// Country code with no subscriber body — fails closed over the
	// whole prefix, mirroring "+44" → "***".
	assert.Equal(t, "***", mask.New().Apply("phone_number", "007"))
}

func TestApply_phone_number_domestic_0_not_affected(t *testing.T) {
	t.Parallel()
	// Single domestic leading zero — must continue routing through
	// the empty-prefix branch, NOT the new 00-prefix branch.
	assert.Equal(t, "***** **3456", mask.New().Apply("phone_number", "07911 123456"))
}

func TestApply_mobile_phone_number_00_prefix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	// Alias inherits the 00-prefix fix automatically because it
	// shares the same masker closure. Assert equivalence with
	// phone_number for the new branch, mirroring the existing alias
	// test pattern.
	for _, in := range []string{
		"0044 7911 123456",
		"001-212-555-0100",
		"00",
		"007",
	} {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, m.Apply("phone_number", in), m.Apply("mobile_phone_number", in))
		})
	}
}

// ---------- imei ----------

func TestApply_IMEI(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "353456789012345", "***********2345"},
		{"empty", "", ""},
		{"fourteen digits fails closed", "35345678901234", "**************"},
		{"sixteen digits fails closed", "3534567890123456", "****************"},
		{"letter O masquerading as zero fails closed", "353456789O12345", "***************"},
		{"with separators fails closed", "35-345678-901234-5", "******************"},
		{"all zeros", "000000000000000", "***********0000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("imei", tc.in))
		})
	}
}

// ---------- imsi ----------

func TestApply_IMSI(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "310260123456789", "31026******6789"},
		{"empty", "", ""},
		{"fourteen digits fails closed", "31026012345678", "**************"},
		{"sixteen digits fails closed", "3102601234567890", "****************"},
		{"with separators fails closed", "310-260-123456789", "*****************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("imsi", tc.in))
		})
	}
}

// ---------- msisdn ----------

func TestApply_MSISDN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "447911123456", "44******3456"},
		{"empty", "", ""},
		{"minimum length ten", "4479111234", "44****1234"},
		{"maximum length fifteen", "447911123456789", "44*********6789"},
		{"nine digits fails closed", "479111234", "*********"},
		{"sixteen digits fails closed", "4479111234567891", "****************"},
		{"leading plus fails closed", "+447911123456", "*************"},
		{"letters fail closed", "447911abc456", "************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("msisdn", tc.in))
		})
	}
}

// ---------- postal_code ----------

func TestApply_PostalCode(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec uk 8-byte", "SW1A 2AA", "SW1A ***"},
		{"spec us", "94103", "941**"},
		{"spec canada", "M5V 2T6", "M5V ***"},
		{"empty", "", ""},
		{"uk short 6-byte", "M1 1AA", "M1 ***"},
		{"uk mid 7-byte", "M25 5AA", "M25 ***"},
		{"uk lowercase fails closed", "sw1a 2aa", "********"},
		{"uk missing space fails closed", "SW1A2AA", "*******"},
		{"us zip plus four fails closed", "94103-6789", "**********"},
		{"ca lowercase fails closed", "m5v 2t6", "*******"},
		{"ca missing space fails closed", "M5V2T6", "******"},
		{"de 5-digit masks as us shape", "10115", "101**"},
		{"random short fails closed", "AB123", "*****"},
		{"already masked uk fails closed", "SW1A ***", "********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("postal_code", tc.in))
		})
	}
}

// TestPostalCode_UKOutwardCodeValidation pins the six BS 7666 outward-
// code patterns recognised by isUKOutwardCode and the malformations
// the validator must reject. Surfaced during corpus authoring (#54);
// validator rewrite tracked in #71.
func TestPostalCode_UKOutwardCodeValidation(t *testing.T) {
	t.Parallel()
	m := mask.New()
	// Each valid outward code is paired with an arbitrary inward
	// "1AA" so the full mask call has something to redact.
	valid := []struct{ in, want string }{
		{"M1 1AA", "M1 ***"},     // AN
		{"B33 1AA", "B33 ***"},   // ANN
		{"CR2 1AA", "CR2 ***"},   // AAN
		{"DN55 1AA", "DN55 ***"}, // AANN
		{"W1A 1AA", "W1A ***"},   // A9A
		{"SW1A 1AA", "SW1A ***"}, // AA9A
	}
	for _, tc := range valid {
		t.Run("valid/"+tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("postal_code", tc.in))
		})
	}
	// Each malformation must fall through to same-length mask. The
	// first three were all silently accepted by the previous
	// over-permissive validator that only required "first byte
	// letter, rest [A-Z|0-9] with at least one digit".
	invalid := []struct{ in, want string }{
		{"A1AA 0AA", "********"}, // A9AA — not a BS 7666 form
		{"A11A 0AA", "********"}, // ANNA — not a BS 7666 form
		{"AAAA 1AA", "********"}, // no digit anywhere
		{"1A 1AA", "******"},     // doesn't start with a letter
		{"12 1AA", "******"},     // doesn't start with a letter
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("postal_code", tc.in))
		})
	}
}

// ---------- geo_latitude ----------

func TestApply_GeoLatitude(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "37.7749295", "37.77*****"},
		// Truncation, not rounding: ReducePrecision operates
		// byte-by-byte and preserves `-33.86`. The spec's
		// `-33.87***` example is a typo.
		{"spec negative truncates not rounds", "-33.8688197", "-33.86*****"},
		{"empty", "", ""},
		{"integer fails closed", "42", "**"},
		{"integer with sign fails closed", "-42", "***"},
		{"too few decimals fails closed", "37.7", "****"},
		{"exactly two decimals fails closed (nothing to mask)", "37.77", "*****"},
		{"scientific fails closed", "3.77e1", "******"},
		{"multiple dots fails closed", "37.77.49", "********"},
		{"leading plus fails closed", "+37.77", "******"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("geo_latitude", tc.in))
		})
	}
}

// ---------- geo_longitude ----------

func TestApply_GeoLongitude(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "-122.4194155", "-122.41*****"},
		{"empty", "", ""},
		{"positive", "139.6503", "139.65**"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("geo_longitude", tc.in))
		})
	}
}

// ---------- geo_coordinates ----------

func TestApply_GeoCoordinates(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "37.7749,-122.4194", "37.77**,-122.41**"},
		{"empty", "", ""},
		{"no comma fails closed", "37.7749", "*******"},
		{"two commas fails closed", "1,2,3", "*****"},
		{"space after comma fails closed", "37.77, -122.42", "**************"},
		{"partial malformed fails closed", "37.77,abc", "*********"},
		{"parens fails closed", "(37.77,-122.42)", "***************"},
		{"leading comma fails closed", ",37.77", "******"},
		{"trailing comma fails closed", "37.77,", "******"},
		{"multi-dot half leaks nothing", "37.77.49,-122.4194", "******************"},
		{"multi-dot second half leaks nothing", "37.7749,-122.42..", "*****************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("geo_coordinates", tc.in))
		})
	}
}

// ---------- mask-character override ----------

func TestTelecom_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	cases := []struct{ rule, in, want string }{
		{"phone_number", "+44 7911 123456", "+44 XXXX XX3456"},
		{"mobile_phone_number", "+44 7911 123456", "+44 XXXX XX3456"},
		{"imei", "353456789012345", "XXXXXXXXXXX2345"},
		{"imsi", "310260123456789", "31026XXXXXX6789"},
		{"msisdn", "447911123456", "44XXXXXX3456"},
		{"postal_code", "SW1A 2AA", "SW1A XXX"},
		{"geo_latitude", "37.7749295", "37.77XXXXX"},
		{"geo_longitude", "-122.4194155", "-122.41XXXXX"},
		{"geo_coordinates", "37.7749,-122.4194", "37.77XX,-122.41XX"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply(tc.rule, tc.in))
		})
	}
}

// ---------- registrations and metadata ----------

func TestDescribe_TelecomRules(t *testing.T) {
	t.Parallel()
	m := mask.New()
	telecomNames := []string{"phone_number", "mobile_phone_number", "imei", "imsi", "msisdn"}
	locationNames := []string{"postal_code", "geo_latitude", "geo_longitude", "geo_coordinates"}
	for _, n := range telecomNames {
		t.Run(n, func(t *testing.T) {
			info, ok := m.Describe(n)
			require.True(t, ok, "rule %q not registered", n)
			assert.Equal(t, "telecom", info.Category)
			assert.NotEmpty(t, info.Jurisdiction)
			assert.Contains(t, info.Description, "Example:", "rule %q description must include an Example", n)
			assert.Equal(t, n, info.Name)
		})
	}
	for _, n := range locationNames {
		t.Run(n, func(t *testing.T) {
			info, ok := m.Describe(n)
			require.True(t, ok, "rule %q not registered", n)
			assert.Equal(t, "location", info.Category)
			assert.NotEmpty(t, info.Jurisdiction)
			assert.Contains(t, info.Description, "Example:", "rule %q description must include an Example", n)
			assert.Equal(t, n, info.Name)
		})
	}
}

// TestTelecom_FailClosedOnMalformed confirms every rule either
// same-length-masks the input or registers as identical output
// shape — never echoes a malformed input verbatim.
func TestTelecom_FailClosedOnMalformed(t *testing.T) {
	t.Parallel()
	m := mask.New()
	malformed := "completely-not-a-telecom-value-xx"
	names := []string{
		"phone_number", "mobile_phone_number", "imei", "imsi",
		"msisdn", "postal_code", "geo_latitude", "geo_longitude",
		"geo_coordinates",
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			got := m.Apply(n, malformed)
			assert.NotEqual(t, malformed, got, "rule %q echoed malformed input", n)
			assert.Equal(t, strings.Repeat("*", utf8.RuneCountInString(malformed)), got,
				"rule %q did not produce same-length mask on malformed input", n)
		})
	}
}

// TestTelecom_NoPanicOnAdversarialInput mirrors the phase 4d / 4c
// contract — every rule must handle adversarial bytes without
// panicking and emit well-formed UTF-8.
func TestTelecom_NoPanicOnAdversarialInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	adversarial := []string{
		"",
		"\xff\xfe\xfd",
		"\x00",
		strings.Repeat("9", 1000),
		"\u200B+44 7911 123456",
		"37.77\u202E49,-122.42",
		"+44\x00 7911 123456",
		"SW1A\u00A02AA",
	}
	names := []string{
		"phone_number", "mobile_phone_number", "imei", "imsi",
		"msisdn", "postal_code", "geo_latitude", "geo_longitude",
		"geo_coordinates",
	}
	for _, n := range names {
		for _, in := range adversarial {
			var got string
			assert.NotPanics(t, func() { got = m.Apply(n, in) },
				"rule %q panicked on input %q", n, in)
			assert.True(t, utf8.ValidString(got),
				"rule %q produced invalid UTF-8 for input %q: %q", n, in, got)
		}
	}
}

// TestTelecom_IdempotencyMatrix pins the 2nd-pass behaviour of each
// rule. All 9 rules produce masked output that is NOT parseable by
// the same rule on a second application — mask runes aren't valid
// digits / hex / letters in any of the rule grammars — so every
// rule is non-idempotent by design.
func TestTelecom_IdempotencyMatrix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, rule, in string }{
		{"phone_number", "phone_number", "+44 7911 123456"},
		{"phone_number_00_prefix", "phone_number", "0044 7911 123456"},
		{"mobile_phone_number", "mobile_phone_number", "+44 7911 123456"},
		{"imei", "imei", "353456789012345"},
		{"imsi", "imsi", "310260123456789"},
		{"msisdn", "msisdn", "447911123456"},
		{"postal_code", "postal_code", "SW1A 2AA"},
		{"geo_latitude", "geo_latitude", "37.7749295"},
		{"geo_longitude", "geo_longitude", "-122.4194155"},
		{"geo_coordinates", "geo_coordinates", "37.7749,-122.4194"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := m.Apply(tc.rule, tc.in)
			second := m.Apply(tc.rule, first)
			assert.NotEqual(t, first, second,
				"rule %q was expected to be non-idempotent (output collapses to same-length mask)", tc.rule)
		})
	}
}
