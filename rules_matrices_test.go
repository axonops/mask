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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/axonops/mask"
)

// Cross-cutting per-category matrices for identity, financial, and
// health rules. Technology, telecom, and country have equivalent
// matrices in their own test files; these three categories were
// flagged by the test-analyst (issue #6) as missing.

// TestIdentity_IdempotencyMatrix asserts that applying a rule to its
// own output is either stable (idempotent) or strictly-length-reducing
// and non-revealing. Identity rules behave differently: some (person_name,
// given_name, family_name) produce output that re-parses as a valid
// input for the same rule and is therefore idempotent. Others collapse
// to a fall-back on second pass.
func TestIdentity_IdempotencyMatrix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ rule, in string }{
		{mask.RuleEmailAddress, "alice@example.com"},
		{mask.RulePersonName, "John Doe"},
		{mask.RuleGivenName, "Alice"},
		{mask.RuleFamilyName, "Smith"},
		{mask.RuleStreetAddress, "42 Wallaby Way"},
		{mask.RuleDateOfBirth, "1985-03-15"},
		{mask.RuleUsername, "johndoe42"},
		{mask.RulePassportNumber, "GB1234567"},
		{mask.RuleDriverLicenseNumber, "DL-1234-5678"},
		{mask.RuleGenericNationalID, "AB123456CD"},
		{mask.RuleTaxIdentifier, "12-3456789"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			first := m.Apply(tc.rule, tc.in)
			second := m.Apply(tc.rule, first)
			// The contract: re-applying the rule MUST NOT grow the output
			// and MUST NOT reveal any of the original input.
			assert.LessOrEqual(t, len(second), len(first),
				"rule %q expanded output on re-application", tc.rule)
			assert.NotContains(t, second, tc.in,
				"rule %q leaked original input on re-application", tc.rule)
		})
	}
}

// TestIdentity_MaskCharOverride confirms every identity rule honours
// the per-instance mask character. Rules that emit mask runes switch
// from `*` to `X` when the Masker is configured with WithMaskChar('X').
func TestIdentity_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	cases := []struct{ rule, in, want string }{
		{mask.RuleEmailAddress, "alice@example.com", "aXXXX@example.com"},
		{mask.RulePersonName, "John Doe", "JXXX DXX"},
		{mask.RuleGivenName, "Alice", "AXXXX"},
		{mask.RuleFamilyName, "Smith", "SXXXX"},
		{mask.RuleStreetAddress, "42 Wallaby Way", "42 XXXXXXX Way"},
		{mask.RuleDateOfBirth, "1985-03-15", "1985-XX-XX"},
		{mask.RuleUsername, "johndoe42", "joXXXXXXX"},
		{mask.RulePassportNumber, "GB1234567", "GBXXXXX67"},
		{mask.RuleDriverLicenseNumber, "DL-1234-5678", "DL-XXXX-5678"},
		{mask.RuleGenericNationalID, "AB123456CD", "ABXXXXXXCD"},
		{mask.RuleTaxIdentifier, "12-3456789", "XX-XXX6789"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply(tc.rule, tc.in))
		})
	}
}

// TestFinancial_IdempotencyMatrix: every financial rule's output
// either re-parses as a further-masked form or collapses to a fallback.
// None of them should ever echo the original on a second pass.
func TestFinancial_IdempotencyMatrix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ rule, in string }{
		{mask.RulePaymentCardPAN, "4111-1111-1111-1111"},
		{mask.RulePaymentCardPANFirst6, "4111-1111-1111-1111"},
		{mask.RulePaymentCardPANLast4, "4111-1111-1111-1111"},
		{mask.RulePaymentCardCVV, "123"},
		{mask.RulePaymentCardPIN, "1234"},
		{mask.RuleBankAccountNumber, "12345678"},
		{mask.RuleUKSortCode, "12-34-56"},
		{mask.RuleUSABARoutingNumber, "123456789"},
		{mask.RuleIBAN, "GB82WEST12345698765432"},
		{mask.RuleSWIFTBIC, "BARCGB2L"},
		{mask.RuleMonetaryAmount, "$1,234.56"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			first := m.Apply(tc.rule, tc.in)
			second := m.Apply(tc.rule, first)
			assert.LessOrEqual(t, len(second), len(first),
				"rule %q expanded output on re-application", tc.rule)
			assert.NotContains(t, second, tc.in,
				"rule %q leaked original input on re-application", tc.rule)
		})
	}
}

// TestFinancial_MaskCharOverride pins the mask-char override for every
// financial rule.
func TestFinancial_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	cases := []struct{ rule, in, want string }{
		{mask.RulePaymentCardPAN, "4111-1111-1111-1111", "4111-11XX-XXXX-1111"},
		{mask.RulePaymentCardPANFirst6, "4111-1111-1111-1111", "4111-11XX-XXXX-XXXX"},
		{mask.RulePaymentCardPANLast4, "4111-1111-1111-1111", "XXXX-XXXX-XXXX-1111"},
		{mask.RulePaymentCardCVV, "123", "XXX"},
		{mask.RulePaymentCardPIN, "1234", "XXXX"},
		{mask.RuleBankAccountNumber, "12345678", "XXXX5678"},
		{mask.RuleUKSortCode, "12-34-56", "12-XX-XX"},
		{mask.RuleUSABARoutingNumber, "123456789", "XXXXX6789"},
		{mask.RuleIBAN, "GB82WEST12345698765432", "GB82XXXXXXXXXXXXXX5432"},
		{mask.RuleSWIFTBIC, "BARCGB2L", "BARCXXXX"},
		// monetary_amount is a full redact — unchanged under mask-char override.
		{mask.RuleMonetaryAmount, "$1,234.56", "[REDACTED]"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply(tc.rule, tc.in))
		})
	}
}

// TestHealth_IdempotencyMatrix: identifier rules collapse to
// same-length mask on re-application (the mask rune isn't a valid
// digit/letter in the prefix parser); full-redact rules are trivially
// idempotent.
func TestHealth_IdempotencyMatrix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ rule, in string }{
		{mask.RuleMedicalRecordNumber, "MRN-123456789"},
		{mask.RuleHealthPlanBeneficiaryID, "HPB-987654321"},
		{mask.RuleMedicalDeviceIdentifier, "DEV-SN-12345678"},
		{mask.RuleDiagnosisCode, "J45.20"},
		{mask.RulePrescriptionText, "Metformin 500mg twice daily"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			first := m.Apply(tc.rule, tc.in)
			second := m.Apply(tc.rule, first)
			assert.LessOrEqual(t, len(second), len(first),
				"rule %q expanded output on re-application", tc.rule)
			assert.NotContains(t, second, tc.in,
				"rule %q leaked original input on re-application", tc.rule)
		})
	}
}

// TestHealth_MaskCharOverride pins the mask-char override for every
// health rule.
func TestHealth_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	cases := []struct{ rule, in, want string }{
		{mask.RuleMedicalRecordNumber, "MRN-123456789", "MRN-XXXXX6789"},
		{mask.RuleHealthPlanBeneficiaryID, "HPB-987654321", "HPB-XXXXX4321"},
		{mask.RuleMedicalDeviceIdentifier, "DEV-SN-12345678", "DEV-SN-XXXX5678"},
		// Full-redact rules emit [REDACTED] regardless of mask char.
		{mask.RuleDiagnosisCode, "J45.20", "[REDACTED]"},
		{mask.RulePrescriptionText, "Metformin 500mg twice daily", "[REDACTED]"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply(tc.rule, tc.in))
		})
	}
}
