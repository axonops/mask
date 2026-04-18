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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/mask"
)

// ---------- payment_card_pan ----------

func TestApply_PaymentCardPAN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"visa 16 unseparated", "4111222233334444", "411122******4444"},
		{"visa 16 dashed", "4111-2222-3333-4444", "4111-22**-****-4444"},
		{"amex 15", "371449635398431", "371449*****8431"},
		{"13 digit min", "4111222233334", "411122***3334"},
		{"19 digit max", "4111222233334444555", "411122*********4555"},
		{"12 digit below range fallback", "411122223333", "************"},
		{"20 digit above range fallback", "41112222333344445555", "********************"},
		{"trailing separator", "4111-2222-3333-4444-", "4111-22**-****-4444-"},
		{"leading separator", "-4111-2222-3333-4444", "-4111-22**-****-4444"},
		{"mixed dash and space", "4111 - 2222 - 3333 - 4444", "4111 - 22** - **** - 4444"},
		// NBSP separators are preserved in place; first 6 digits span the
		// first two groups (4 + 2) and last 4 is the final group.
		{"nbsp separator", "4111\u00a02222\u00a03333\u00a04444", "4111\u00a022**\u00a0****\u00a04444"},
		{"arabic indic digits fallback", "٤١١١٢٢٢٢٣٣٣٣٤٤٤٤", "****************"},
		{"letter mixed in fallback", "4111X222233334444", "*****************"},
		{"already masked fallback", "411122******4444", "****************"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("payment_card_pan", tc.in))
		})
	}
}

func TestApply_PaymentCardPAN_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.Equal(t, "411122XXXXXX4444", m.Apply("payment_card_pan", "4111222233334444"))
}

// ---------- payment_card_pan_first6 ----------

func TestApply_PaymentCardPANFirst6(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"visa 16 unseparated", "4111222233334444", "411122**********"},
		{"visa 16 dashed", "4111-2222-3333-4444", "4111-22**-****-****"},
		{"13 digit min", "4111222233334", "411122*******"},
		{"12 digit fallback", "411122223333", "************"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("payment_card_pan_first6", tc.in))
		})
	}
}

// ---------- payment_card_pan_last4 ----------

func TestApply_PaymentCardPANLast4(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"visa 16 unseparated", "4111222233334444", "************4444"},
		{"visa 16 dashed", "4111-2222-3333-4444", "****-****-****-4444"},
		{"four digits below range fallback", "4444", "****"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("payment_card_pan_last4", tc.in))
		})
	}
}

// ---------- payment_card_cvv / payment_card_pin ----------

func TestApply_PaymentCardCVV(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"three digit", "123", "***"},
		{"four digit", "1234", "****"},
		{"non digit", "abc", "***"},
		{"arabic indic", "١٢٣", "***"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("payment_card_cvv", tc.in))
		})
	}
}

func TestApply_PaymentCardPIN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"four digit", "1234", "****"},
		{"six digit", "123456", "******"},
		{"cjk", "一二三四", "****"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("payment_card_pin", tc.in))
		})
	}
}

// ---------- bank_account_number ----------

func TestApply_BankAccountNumber(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"eight digit", "12345678", "****5678"},
		{"dashed groups", "1234-5678-9012", "****-****-9012"},
		{"spaced groups", "12 34 5678", "** ** 5678"},
		// Fail-closed: ≤ 4 non-separator runes would echo the value; mask.
		{"four digit fails closed", "1234", "****"},
		{"three digit fails closed", "123", "***"},
		{"five digit", "12345", "*2345"},
		{"alpha mixed", "AB12345678", "******5678"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("bank_account_number", tc.in))
		})
	}
}

// ---------- uk_sort_code ----------

func TestApply_UKSortCode(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical dashed", "12-34-56", "12-**-**"},
		{"unseparated 6 digits", "123456", "12****"},
		{"spaced", "12 34 56", "12 ** **"},
		{"five digits fallback", "12345", "*****"},
		{"eight digits fallback", "12345678", "********"},
		{"letters fallback", "AB-CD-EF", "********"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("uk_sort_code", tc.in))
		})
	}
}

// ---------- us_aba_routing_number ----------

func TestApply_USABARoutingNumber(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"canonical", "021000021", "*****0021"},
		{"four digits fallback", "0021", "****"},
		{"three digits fallback", "021", "***"},
		{"eight digits fallback", "02100002", "********"},
		{"ten digits fallback", "0210000210", "**********"},
		{"with separators fallback", "021-000-021", "***********"},
		{"letters fallback", "ABCDEFGHI", "*********"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("us_aba_routing_number", tc.in))
		})
	}
}

// ---------- iban ----------

func TestApply_IBAN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		// The spec literal "GB82***************5432" has 15 stars (total
		// length 23 — longer than the input). Length-preservation takes
		// precedence over the literal example count: 22 non-sep runes,
		// first 4 + last 4 kept = 14 masked runes in the middle. The
		// second spec example shows `***4 32` which corresponds to
		// "last 3" kept, but the prose is explicit about last 4 — we
		// follow the prose, pin the output byte-for-byte, and treat the
		// example star counts as spec typos.
		{"canonical no space", "GB82WEST12345698765432", "GB82**************5432"},
		{"canonical de no space", "DE89370400440532013000", "DE89**************3000"},
		{"canonical gb grouped", "GB82 WEST 1234 5698 7654 32", "GB82 **** **** **** **54 32"},
		{"15 min length", "GB82WEST1234567", "GB82*******4567"},
		{"14 below min fallback", "GB82WEST123456", "**************"},
		// 34-char upper-inclusive boundary — pin the accept path at the
		// ISO 13616 maximum. Synthetic alphanumeric IBAN of length 34.
		{
			"34 max length accepted",
			"GB82WEST12345678901234567890123456",
			"GB82**************************3456",
		},
		{"35 above max fallback", strings.Repeat("A", 35), strings.Repeat("*", 35)},
		{"lowercase rejected", "gb82west12345698765432", "**********************"},
		{"mixed case rejected", "Gb82WeSt12345698765432", "**********************"},
		{"non alphanumeric fallback", "GB82-WEST-1234-5698-7654-32", "***************************"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("iban", tc.in))
		})
	}
}

// ---------- swift_bic ----------

func TestApply_SWIFTBIC(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"8 char canonical", "BARCGB2L", "BARC****"},
		{"11 char canonical", "DEUTDEFF500", "DEUT*******"},
		{"lowercase fallback", "barcgb2l", "********"},
		{"6 char fallback", "BARCGB", "******"},
		{"9 char fallback", "BARCGB2LX", "*********"},
		{"10 char fallback", "BARCGB2LXX", "**********"},
		{"12 char fallback", "DEUTDEFF5000", "************"},
		{"digits only 8", "12345678", "1234****"},
		{"non alpha fallback", "BARC!B2L", "********"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("swift_bic", tc.in))
		})
	}
}

// ---------- monetary_amount ----------

func TestApply_MonetaryAmount(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in string }{
		{"dollar", "$1,234.56"},
		{"euro", "€99.99"},
		{"negative", "-500"},
		{"scientific", "1.2e6"},
		{"zero", "0"},
		{"already redacted", "[REDACTED]"},
		{"very long", strings.Repeat("9", 1000)},
		{"empty treated same as any other", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, "[REDACTED]", m.Apply("monetary_amount", tc.in))
		})
	}
}

// ---------- cross-rule invariants ----------

func TestDescribe_FinancialRules(t *testing.T) {
	t.Parallel()
	m := mask.New()
	names := []string{
		"payment_card_pan", "payment_card_pan_first6", "payment_card_pan_last4",
		"payment_card_cvv", "payment_card_pin",
		"bank_account_number", "uk_sort_code", "us_aba_routing_number",
		"iban", "swift_bic", "monetary_amount",
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			info, ok := m.Describe(n)
			require.True(t, ok, "rule %q not registered", n)
			assert.Equal(t, "financial", info.Category, "rule %q has wrong category", n)
			assert.NotEmpty(t, info.Jurisdiction)
			assert.NotEmpty(t, info.Description)
			assert.Equal(t, n, info.Name)
		})
	}
}

func TestFinancial_FailClosedOnLongMalformedInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	long := strings.Repeat("z", 50)
	for _, n := range []string{
		"payment_card_pan", "payment_card_pan_first6", "payment_card_pan_last4",
		"payment_card_cvv", "payment_card_pin",
		"bank_account_number", "uk_sort_code", "us_aba_routing_number",
		"iban", "swift_bic",
	} {
		t.Run(n, func(t *testing.T) {
			got := m.Apply(n, long)
			assert.NotEqual(t, long, got, "rule %q echoed a long malformed input", n)
		})
	}
	// monetary_amount is FullRedact, always produces the marker.
	assert.Equal(t, "[REDACTED]", m.Apply("monetary_amount", long))
}

func TestFinancial_NoPanicOnAdversarialInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	adversarial := []string{
		"",
		"\xff\xfe\xfd",
		"\x00",
		strings.Repeat("x", 1000),
		"\u202Eevil",           // RTL override
		"4111\x00222233334444", // embedded NUL
	}
	for _, n := range []string{
		"payment_card_pan", "payment_card_pan_first6", "payment_card_pan_last4",
		"payment_card_cvv", "payment_card_pin",
		"bank_account_number", "uk_sort_code", "us_aba_routing_number",
		"iban", "swift_bic", "monetary_amount",
	} {
		for _, in := range adversarial {
			assert.NotPanics(t, func() { _ = m.Apply(n, in) },
				"rule %q panicked on input %q", n, in)
		}
	}
}

func TestFinancial_PANVariantsAreLengthPreserving(t *testing.T) {
	t.Parallel()
	m := mask.New()
	in := "4111-2222-3333-4444"
	for _, n := range []string{"payment_card_pan", "payment_card_pan_first6", "payment_card_pan_last4"} {
		got := m.Apply(n, in)
		assert.Equal(t, len(in), len(got), "rule %q changed length: in=%q out=%q", n, in, got)
		// dashes preserved at positions 4, 9, 14
		for _, idx := range []int{4, 9, 14} {
			assert.Equal(t, byte('-'), got[idx], "rule %q dropped dash at byte %d: out=%q", n, idx, got)
		}
	}
}
