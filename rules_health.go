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

package mask

// Health-category rules implement the healthcare masks documented
// in docs/rules.md §"Health". Each rule preserves the expected shape,
// fails closed on malformed input, and honours the configured mask
// character at apply time.
//
// Regulatory note: these rules are pseudonymisation, not HIPAA Safe
// Harbor de-identification. Retaining the last 4 runes of an MRN or a
// health-plan beneficiary ID does not by itself anonymise the record —
// combined with any quasi-identifier (date of service, ZIP, age), the
// rule falls short of §164.514(b). Each rule carries an inline warning
// to that effect. Callers with Safe-Harbor obligations should compose
// stricter rules (for example `full_redact`) under their own rule name.

// isHealthSeparator reports whether r is treated as a grouping separator
// in this category's inputs: ASCII hyphen, ASCII space, or ASCII forward
// slash. The period is deliberately NOT a separator — a period in an MRN
// is rare enough in practice that treating it as payload (and routing
// unusual shapes to the same-length-mask fallback) is safer than
// accepting it.
func isHealthSeparator(r rune) bool {
	switch r {
	case '-', ' ', '/':
		return true
	}
	return false
}

// isASCIIAlpha reports whether b is an ASCII letter A-Z or a-z.
// Non-ASCII letters are deliberately rejected: an MRN prefix is always
// Latin ASCII in practice, and admitting `unicode.IsLetter` would let
// Cyrillic or CJK runes pass as "format literals", which is not how
// operators tag a record.
func isASCIIAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// healthPrefixEnd returns the byte offset in v at which the leading
// "format literal" prefix ends. Everything in v[:off] is ASCII letters
// and health separators only; v[off:] is the first non-letter,
// non-separator rune (typically a digit) onwards.
//
// The walk is a byte loop rather than a rune loop because both the
// accept set (ASCII letters plus three ASCII separators) and the
// reject cases (digits, non-ASCII letters, invalid UTF-8, punctuation)
// are well-defined at the byte level for ASCII-only prefixes. Non-ASCII
// runes in leading position terminate the walk cleanly at their first
// byte — the whole rune ends up in the body, where it will fail the
// non-separator count at worst and route to [SameLengthMask].
func healthPrefixEnd(v string) int {
	i := 0
	for i < len(v) {
		b := v[i]
		if isASCIIAlpha(b) || isHealthSeparator(rune(b)) {
			i++
			continue
		}
		return i
	}
	return len(v)
}

// maskHealthIdentifier is the shared body of the three HIPAA identifier
// rules: medical_record_number, health_plan_beneficiary_id, and
// medical_device_identifier. Preserves the leading alpha-and-separator
// prefix verbatim, masks the body while preserving in-body separators,
// and keeps the last 4 non-separator runes. Bodies whose non-separator
// count is ≤ 4 fail closed to [SameLengthMask] over the whole input —
// the alphabetic prefix is NOT echoed on pathologically short inputs.
//
// Examples (matching the spec):
//
//	MRN-123456789   → MRN-*****6789
//	123456789       → *****6789
//	HPB-987654321   → HPB-*****4321
//	DEV-SN-12345678 → DEV-SN-****5678
//
// Multi-segment prefixes (for example "DEV-SN-") are a single prefix
// because separator runes are admitted to the prefix walk.
//
// WARNING: retaining the last 4 digits is NOT HIPAA Safe Harbor
// de-identification on its own. On any identifier space small enough to
// be enumerable (a single health system's MRN pool, a payer's
// beneficiary IDs, a vendor's device serials), the last-4 tail combined
// with a date of service or ZIP is re-identifiable. Consumers with
// Safe-Harbor obligations should register `full_redact` under the same
// rule name on a dedicated Masker, or switch their field binding to the
// existing `full_redact` primitive.
//
// Strict-mode note: the requirements doc defines an as-yet-unimplemented
// "strict mode" that replaces identifier values with a full redact.
// This library does not yet expose strict mode as a first-class concept;
// operators who need the stricter behaviour use one of the overrides
// above.
func maskHealthIdentifier(v string, c rune) string {
	if v == "" {
		return ""
	}
	off := healthPrefixEnd(v)
	body := v[off:]
	nonsep := countNonSep(body, isHealthSeparator)
	return keepFirstLastNonSepWithPrefix(v[:off], body, 0, 4, nonsep, c, isHealthSeparator)
}

// registerHealthRules wires every rule in this file against m.
func registerHealthRules(m *Masker) {
	m.mustRegisterBuiltin("medical_record_number",
		func(v string) string { return maskHealthIdentifier(v, m.maskChar()) },
		RuleInfo{
			Name: "medical_record_number", Category: "health", Jurisdiction: "global (HIPAA)",
			Description: "Preserves the leading alpha-and-separator prefix and keeps the last 4 non-separator characters of the body; fails closed when the body is too short to mask. Example: MRN-123456789 → MRN-*****6789.",
		})

	m.mustRegisterBuiltin("health_plan_beneficiary_id",
		func(v string) string { return maskHealthIdentifier(v, m.maskChar()) },
		RuleInfo{
			Name: "health_plan_beneficiary_id", Category: "health", Jurisdiction: "global (HIPAA)",
			Description: "Preserves the leading alpha-and-separator prefix and keeps the last 4 non-separator characters of the body. Example: HPB-987654321 → HPB-*****4321.",
		})

	m.mustRegisterBuiltin("medical_device_identifier",
		func(v string) string { return maskHealthIdentifier(v, m.maskChar()) },
		RuleInfo{
			Name: "medical_device_identifier", Category: "health", Jurisdiction: "global (HIPAA)",
			Description: "Preserves the leading alpha-and-separator prefix (including multi-segment prefixes like DEV-SN-) and keeps the last 4 non-separator characters of the body. Example: DEV-SN-12345678 → DEV-SN-****5678.",
		})

	m.mustRegisterBuiltin("diagnosis_code",
		FullRedact,
		RuleInfo{
			Name: "diagnosis_code", Category: "health", Jurisdiction: "global",
			Description: "Full redact. ICD-10 codes are debated as direct identifiers; combined with dates or ZIP codes they are quasi-identifiers, so the conservative default is full redact. Example: J45.20 → [REDACTED].",
		})

	m.mustRegisterBuiltin("prescription_text",
		FullRedact,
		RuleInfo{
			Name: "prescription_text", Category: "health", Jurisdiction: "global",
			Description: "Full redact. Free-text prescription fields may expose conditions and clinical details; the conservative default is full redact. Example: Metformin 500mg twice daily → [REDACTED].",
		})
}

func init() {
	builtinRegistrars = append(builtinRegistrars, registerHealthRules)
}
