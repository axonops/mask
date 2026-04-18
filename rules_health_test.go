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

// ---------- medical_record_number ----------

func TestApply_MedicalRecordNumber(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "MRN-123456789", "MRN-*****6789"},
		{"spec numeric only", "123456789", "*****6789"},
		{"empty", "", ""},
		// Body with ≤ 4 non-separators fails closed to full same-length mask
		// over the WHOLE input (prefix is NOT echoed).
		{"body length one fails closed", "MRN-1", "*****"},
		{"body length two fails closed", "MRN-12", "******"},
		{"body length three fails closed", "MRN-123", "*******"},
		{"body length four fails closed", "MRN-1234", "********"},
		{"body length five keeps last four", "MRN-12345", "MRN-*2345"},
		{"single rune no prefix fails closed", "7", "*"},
		{"four digits no prefix fails closed", "1234", "****"},
		{"five digits no prefix", "12345", "*2345"},
		{"prefix only fails closed", "MRN-", "****"},
		{"prefix only no separator fails closed", "MRN", "***"},
		// Separator-only inputs: 0 non-sep in body → fail-closed.
		{"separators only dashes", "---", "***"},
		{"separators only mixed", "/-/", "***"},
		{"separators only spaces", "   ", "***"},
		// Non-ASCII alpha in the prefix position is NOT recognised; the
		// first byte of `М` (Cyrillic) fails the ASCII-alpha check, so
		// the prefix walk terminates at byte 0 and the whole input is
		// the body. 12 non-sep runes (`М`,`R`,`N`,`1`-`9` with `-`
		// treated as separator) → keep last 4 masks the first 8.
		{"cyrillic prefix not letter", "МRN-123456789", "***-*****6789"},
		// Period is NOT a separator in health semantics; it routes to body
		// and is masked as a non-separator rune except for the last 4.
		// Body is `.123456789` — 10 non-separator runes; keep last 4
		// means 6 masked runes (period + first five digits).
		{"period in body is data", "MRN.123456789", "MRN******6789"},
		// Already-masked input is idempotent under the rule because the
		// stars are non-separator runes; last 4 are preserved.
		{"idempotent on prior output", "MRN-*****6789", "MRN-*****6789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("medical_record_number", tc.in))
		})
	}
}

func TestApply_MedicalRecordNumber_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.Equal(t, "MRN-XXXXX6789", m.Apply("medical_record_number", "MRN-123456789"))
}

// ---------- health_plan_beneficiary_id ----------

func TestApply_HealthPlanBeneficiaryID(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "HPB-987654321", "HPB-*****4321"},
		{"empty", "", ""},
		{"prefix only fails closed", "HPB-", "****"},
		{"body length four fails closed", "HPB-1234", "********"},
		{"body length five keeps last four", "HPB-12345", "HPB-*2345"},
		{"numeric only", "987654321", "*****4321"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("health_plan_beneficiary_id", tc.in))
		})
	}
}

// ---------- medical_device_identifier ----------

func TestApply_MedicalDeviceIdentifier(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "DEV-SN-12345678", "DEV-SN-****5678"},
		{"empty", "", ""},
		{"slash separators", "DEV/SN/12345678", "DEV/SN/****5678"},
		{"space separators", "DEV SN 12345678", "DEV SN ****5678"},
		{"mixed separators", "DEV-SN/12345678", "DEV-SN/****5678"},
		{"three segment prefix", "DEV/SN/X/12345678", "DEV/SN/X/****5678"},
		{"prefix only fails closed", "DEV-SN-", "*******"},
		{"body length four fails closed", "DEV-SN-1234", "***********"},
		{"body length five keeps last four", "DEV-SN-12345", "DEV-SN-*2345"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("medical_device_identifier", tc.in))
		})
	}
}

// ---------- diagnosis_code ----------

func TestApply_DiagnosisCode(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in string }{
		{"asthma", "J45.20"},
		{"diabetes", "E11.9"},
		{"empty is still full redact", ""},
		{"unicode", "感冒 😷"},
		{"already redacted", "[REDACTED]"},
		{"very long", strings.Repeat("J", 5000)},
		{"nul bytes", "J45.20\x00E11.9"},
		{"invalid utf8", "\xff\xfe\xfd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, "[REDACTED]", m.Apply("diagnosis_code", tc.in))
		})
	}
}

// ---------- prescription_text ----------

func TestApply_PrescriptionText(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in string }{
		{"spec canonical", "Metformin 500mg twice daily"},
		{"empty is still full redact", ""},
		{"unicode", "メトホルミン 500mg"},
		{"already redacted", "[REDACTED]"},
		{"very long", strings.Repeat("pill", 500)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, "[REDACTED]", m.Apply("prescription_text", tc.in))
		})
	}
}

func TestApply_PrescriptionText_Idempotent(t *testing.T) {
	t.Parallel()
	m := mask.New()
	first := m.Apply("prescription_text", "Metformin 500mg twice daily")
	second := m.Apply("prescription_text", first)
	assert.Equal(t, first, second)
}

// ---------- registrations and metadata ----------

func TestDescribe_HealthRules(t *testing.T) {
	t.Parallel()
	m := mask.New()
	names := []string{
		"medical_record_number", "health_plan_beneficiary_id",
		"medical_device_identifier", "diagnosis_code", "prescription_text",
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			info, ok := m.Describe(n)
			require.True(t, ok, "rule %q not registered", n)
			assert.Equal(t, "health", info.Category)
			assert.NotEmpty(t, info.Jurisdiction)
			assert.NotEmpty(t, info.Description)
			assert.Equal(t, n, info.Name)
			assert.Contains(t, info.Description, "Example:",
				"rule %q description must include an Example", n)
		})
	}
}

func TestHealth_FailClosedOnLongMalformedInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	long := strings.Repeat("z", 50)
	// The three HIPAA identifier rules must not echo a 50-char all-letter
	// input. Under the prefix-aware rule, the prefix walk consumes every
	// byte (no digit ever appears), body is empty, fallback is
	// SameLengthMask.
	for _, n := range []string{
		"medical_record_number",
		"health_plan_beneficiary_id",
		"medical_device_identifier",
	} {
		t.Run(n, func(t *testing.T) {
			got := m.Apply(n, long)
			assert.NotEqual(t, long, got, "rule %q echoed long malformed input", n)
			assert.Equal(t, strings.Repeat("*", 50), got)
		})
	}
	// Full-redact rules always return the marker.
	assert.Equal(t, "[REDACTED]", m.Apply("diagnosis_code", long))
	assert.Equal(t, "[REDACTED]", m.Apply("prescription_text", long))
}

func TestHealth_NoPanicOnAdversarialInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	adversarial := []string{
		"",
		"\xff\xfe\xfd",
		"\x00",
		strings.Repeat("x", 1000),
		"MRN-12\x0034",        // embedded NUL
		"MRN-\u202E123456789", // RTL override
		"MRN-\U0001F468\u200D\U0001F469" + "12345", // ZWJ emoji in body
		"MRN-\u200B123456789",                      // zero-width space
	}
	for _, n := range []string{
		"medical_record_number", "health_plan_beneficiary_id",
		"medical_device_identifier", "diagnosis_code", "prescription_text",
	} {
		for _, in := range adversarial {
			var got string
			assert.NotPanics(t, func() { got = m.Apply(n, in) },
				"rule %q panicked on input %q", n, in)
			// Strengthen the contract: whatever a rule produces must be
			// well-formed UTF-8 so downstream logging / SIEM consumers
			// can treat rule output as text without a separate decode
			// step. Our builders emit via WriteRune (valid by
			// construction) or via the SameLengthMask / FullRedact
			// paths (both valid).
			assert.True(t, utf8.ValidString(got),
				"rule %q produced invalid UTF-8 for input %q: %q", n, in, got)
		}
	}
}
