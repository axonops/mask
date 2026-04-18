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
		"",
		"nonsense",
	}
	for _, in := range cases {
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
	cases := []struct{ name, in string }{
		{"phone_number", "+44 7911 123456"},
		{"mobile_phone_number", "+44 7911 123456"},
		{"imei", "353456789012345"},
		{"imsi", "310260123456789"},
		{"msisdn", "447911123456"},
		{"postal_code", "SW1A 2AA"},
		{"geo_latitude", "37.7749295"},
		{"geo_longitude", "-122.4194155"},
		{"geo_coordinates", "37.7749,-122.4194"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := m.Apply(tc.name, tc.in)
			second := m.Apply(tc.name, first)
			assert.NotEqual(t, first, second,
				"rule %q was expected to be non-idempotent (output collapses to same-length mask)", tc.name)
		})
	}
}
