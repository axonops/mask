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

import (
	"strings"
)

// Country-category rules implement the 14 jurisdiction-specific
// identifiers documented in docs/v0.9.0-requirements.md §"Personal
// and Identity" from `us_ssn` through `es_dni_nif_nie`. Each rule
// preserves a deterministic window (first N, last M, or both) and
// routes malformed input to [SameLengthMask]. The rules are
// registered under the `identity` category so `Describe()` answers
// `identity` + a jurisdiction string.

// ---------- shared separator predicates ----------

// isHyphen reports whether r is an ASCII hyphen. Shared by rules
// whose only separator is `-` (us_ssn, ca_sin).
func isHyphen(r rune) bool { return r == '-' }

// isSpace reports whether r is an ASCII space. Shared by rules
// whose only separator is ` ` (uk_nino, in_aadhaar, au_medicare).
func isSpace(r rune) bool { return r == ' ' }

// isCPFSeparator reports whether r is `.` or `-` — CPF canonical
// punctuation.
func isCPFSeparator(r rune) bool { return r == '.' || r == '-' }

// isCNPJSeparator reports whether r is `.`, `/`, or `-` — CNPJ
// canonical punctuation.
func isCNPJSeparator(r rune) bool { return r == '.' || r == '/' || r == '-' }

// ---------- us_ssn ----------

// maskUSSSN preserves the last 4 digits of a 9-digit US Social
// Security Number. Accepts `AAAGGSSSS` or `AAA-GG-SSSS` with
// hyphens at the canonical positions. Any other shape fails closed.
func maskUSSSN(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidSSN(v) {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSepCounted(v, 0, 4, 9, c, isHyphen)
}

// isValidSSN reports whether v is either 9 ASCII digits, or
// `AAA-GG-SSSS` (3-2-4 with hyphens at positions 3 and 6).
func isValidSSN(v string) bool {
	switch len(v) {
	case 9:
		return allASCIIDigits(v)
	case 11:
		return v[3] == '-' && v[6] == '-' &&
			allASCIIDigits(v[:3]) && allASCIIDigits(v[4:6]) && allASCIIDigits(v[7:])
	}
	return false
}

// ---------- ca_sin ----------

// maskCASIN preserves the last 3 digits of a 9-digit Canadian
// Social Insurance Number. Accepts `AAABBBCCC` or `AAA-BBB-CCC`.
func maskCASIN(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidCASIN(v) {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSepCounted(v, 0, 3, 9, c, isHyphen)
}

func isValidCASIN(v string) bool {
	switch len(v) {
	case 9:
		return allASCIIDigits(v)
	case 11:
		return v[3] == '-' && v[7] == '-' &&
			allASCIIDigits(v[:3]) && allASCIIDigits(v[4:7]) && allASCIIDigits(v[8:])
	}
	return false
}

// ---------- uk_nino ----------

// maskUKNINO preserves the 2 prefix letters and 1 suffix letter
// of a UK National Insurance Number; masks the 6 middle digits.
// Accepts the compact form `AB123456C` and the spaced form
// `AB 12 34 56 C`.
func maskUKNINO(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidUKNINO(v) {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSepCounted(v, 2, 1, 9, c, isSpace)
}

func isValidUKNINO(v string) bool {
	switch len(v) {
	case 9:
		return isCompactUKNINO(v)
	case 13:
		return isSpacedUKNINO(v)
	}
	return false
}

// isCompactUKNINO reports whether v is a 9-byte UK NINO with no
// separators: 2 upper letters + 6 digits + 1 upper letter.
func isCompactUKNINO(v string) bool {
	return isASCIIUpperLetter(v[0]) && isASCIIUpperLetter(v[1]) &&
		allASCIIDigits(v[2:8]) && isASCIIUpperLetter(v[8])
}

// isSpacedUKNINO reports whether v is a 13-byte UK NINO in the
// `AB 12 34 56 C` space-separated form.
func isSpacedUKNINO(v string) bool {
	if v[2] != ' ' || v[5] != ' ' || v[8] != ' ' || v[11] != ' ' {
		return false
	}
	return isASCIIUpperLetter(v[0]) && isASCIIUpperLetter(v[1]) &&
		allASCIIDigits(v[3:5]) && allASCIIDigits(v[6:8]) && allASCIIDigits(v[9:11]) &&
		isASCIIUpperLetter(v[12])
}

// ---------- in_aadhaar ----------

// maskINAadhaar preserves the last 4 digits of a 12-digit Aadhaar.
// Accepts compact `123456789012` or grouped `1234 5678 9012`.
func maskINAadhaar(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidAadhaar(v) {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSepCounted(v, 0, 4, 12, c, isSpace)
}

func isValidAadhaar(v string) bool {
	switch len(v) {
	case 12:
		return allASCIIDigits(v)
	case 14:
		return v[4] == ' ' && v[9] == ' ' &&
			allASCIIDigits(v[:4]) && allASCIIDigits(v[5:9]) && allASCIIDigits(v[10:])
	}
	return false
}

// ---------- in_pan ----------

// maskINPAN preserves the first 3 and last 2 characters of a
// 10-character Indian Permanent Account Number. Shape is 5 upper
// letters + 4 digits + 1 upper letter.
func maskINPAN(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidINPAN(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, 3, 2, c)
}

func isValidINPAN(v string) bool {
	if len(v) != 10 {
		return false
	}
	for i := 0; i < 5; i++ {
		if !isASCIIUpperLetter(v[i]) {
			return false
		}
	}
	if !allASCIIDigits(v[5:9]) {
		return false
	}
	return isASCIIUpperLetter(v[9])
}

// ---------- au_medicare_number ----------

// maskAUMedicareNumber preserves the last 2 digits of a 10-digit
// Australian Medicare number. Accepts compact `1234567890` or the
// canonical grouped `2123 45670 1` form (the spec example).
//
// Spec text says "Preserve last 3-4 digits" but the spec example
// `2123 45670 1 → **** ****0 1` keeps only the trailing 2 digits
// (the final group's single digit + the masked group's tail digit).
// We honour the example.
func maskAUMedicareNumber(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidAUMedicare(v) {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSepCounted(v, 0, 2, 10, c, isSpace)
}

func isValidAUMedicare(v string) bool {
	switch len(v) {
	case 10:
		return allASCIIDigits(v)
	case 12:
		// `NNNN NNNNN N` — 4 digits, space, 5 digits, space, 1 digit.
		return v[4] == ' ' && v[10] == ' ' &&
			allASCIIDigits(v[:4]) && allASCIIDigits(v[5:10]) && allASCIIDigits(v[11:])
	}
	return false
}

// ---------- sg_nric_fin ----------

// maskSGNRICFIN preserves the leading letter and the trailing
// letter of a Singapore NRIC/FIN (9 characters total: 1 letter + 7
// digits + 1 letter).
func maskSGNRICFIN(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidSGNRIC(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, 1, 1, c)
}

func isValidSGNRIC(v string) bool {
	if len(v) != 9 {
		return false
	}
	return isASCIIUpperLetter(v[0]) && allASCIIDigits(v[1:8]) && isASCIIUpperLetter(v[8])
}

// ---------- br_cpf ----------

// maskBRCPF preserves the last 2 digits of an 11-digit Brazilian
// CPF (taxpayer identifier). Accepts compact `12345678909` or
// canonical `123.456.789-09`. Keeping the last 2 matches the
// check-digit segment of the canonical form and the first spec
// example; the unformatted spec example `12345678909 →
// *******8909` (last 4) is treated as an inconsistency.
func maskBRCPF(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidBRCPF(v) {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSepCounted(v, 0, 2, 11, c, isCPFSeparator)
}

func isValidBRCPF(v string) bool {
	switch len(v) {
	case 11:
		return allASCIIDigits(v)
	case 14:
		return v[3] == '.' && v[7] == '.' && v[11] == '-' &&
			allASCIIDigits(v[:3]) && allASCIIDigits(v[4:7]) &&
			allASCIIDigits(v[8:11]) && allASCIIDigits(v[12:])
	}
	return false
}

// ---------- br_cnpj ----------

// maskBRCNPJ preserves the last 2 digits of a 14-digit Brazilian
// CNPJ (business taxpayer identifier). Accepts compact
// `12345678000195` or canonical `12.345.678/0001-95`. Keeping the
// last 2 matches the spec example and the check-digit segment of
// the canonical form; the spec's "last 4" text is treated as
// inconsistent with the example.
func maskBRCNPJ(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidBRCNPJ(v) {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSepCounted(v, 0, 2, 14, c, isCNPJSeparator)
}

func isValidBRCNPJ(v string) bool {
	switch len(v) {
	case 14:
		return allASCIIDigits(v)
	case 18:
		return isFormattedBRCNPJ(v)
	}
	return false
}

// isFormattedBRCNPJ validates the canonical 18-byte CNPJ form
// `NN.NNN.NNN/NNNN-NN`.
func isFormattedBRCNPJ(v string) bool {
	if v[2] != '.' || v[6] != '.' || v[10] != '/' || v[15] != '-' {
		return false
	}
	return allASCIIDigits(v[:2]) && allASCIIDigits(v[3:6]) &&
		allASCIIDigits(v[7:10]) && allASCIIDigits(v[11:15]) &&
		allASCIIDigits(v[16:])
}

// ---------- mx_curp ----------

// maskMXCURP preserves the first 4 characters (initials block) and
// the last 3 characters (check digits) of a Mexican CURP; the 11
// middle characters are masked. Total length is 18.
//
// The spec example `GAPA850101HDFRRL09 → GAPA**********L09` shows
// 10 stars — we emit 11 to preserve same-length output. The spec
// is treated as a typo (10-star output would be 17 chars for an
// 18-char input).
func maskMXCURP(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidMXCURP(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, 4, 3, c)
}

func isValidMXCURP(v string) bool {
	if len(v) != 18 {
		return false
	}
	for i := 0; i < 18; i++ {
		if !isCURPByte(v[i]) {
			return false
		}
	}
	return true
}

// isCURPByte reports whether b is a valid CURP character — upper
// ASCII letter or digit.
func isCURPByte(b byte) bool {
	return isASCIIUpperLetter(b) || isASCIIDecDigit(b)
}

// ---------- mx_rfc ----------

// maskMXRFC preserves the first 3 and last 3 characters of a
// Mexican RFC. Accepts 12- or 13-character inputs (companies use
// 12, individuals 13).
func maskMXRFC(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidMXRFC(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, 3, 3, c)
}

func isValidMXRFC(v string) bool {
	n := len(v)
	if n != 12 && n != 13 {
		return false
	}
	for i := 0; i < n; i++ {
		if !isCURPByte(v[i]) {
			return false
		}
	}
	return true
}

// ---------- cn_resident_id ----------

// maskCNResidentID preserves the first 6 (region code) and last 4
// characters of an 18-character PRC Resident Identity Card number.
// The 17th position can be a digit or `X` (check digit for cards
// whose check value is 10); all other positions are digits.
func maskCNResidentID(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !isValidCNResidentID(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, 6, 4, c)
}

func isValidCNResidentID(v string) bool {
	if len(v) != 18 {
		return false
	}
	for i := 0; i < 17; i++ {
		if !isASCIIDecDigit(v[i]) {
			return false
		}
	}
	last := v[17]
	return isASCIIDecDigit(last) || last == 'X' || last == 'x'
}

// ---------- za_national_id ----------

// maskZANationalID preserves the first 6 (date of birth YYMMDD)
// and last 4 characters of a 13-digit South African national ID
// number.
func maskZANationalID(v string, c rune) string {
	if v == "" {
		return ""
	}
	if len(v) != 13 || !allASCIIDigits(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, 6, 4, c)
}

// ---------- es_dni_nif_nie ----------

// maskESDNINIFNIE preserves the leading character (letter prefix
// for NIE inputs like `X1234567L`) only when present, and always
// preserves the trailing control letter. DNIs (`12345678Z`) have
// no leading letter; NIE/NIF inputs may. The input is 9 characters
// in all forms.
func maskESDNINIFNIE(v string, c rune) string {
	if v == "" {
		return ""
	}
	if len(v) != 9 {
		return SameLengthMask(v, c)
	}
	lastLetter := isASCIIUpperLetter(v[8])
	if !lastLetter {
		return SameLengthMask(v, c)
	}
	// DNI: 8 digits + letter; no leading letter.
	if allASCIIDigits(v[:8]) {
		return KeepLastN(v, 1, c)
	}
	// NIE/NIF: leading letter + 7 digits + letter.
	if isASCIIUpperLetter(v[0]) && allASCIIDigits(v[1:8]) {
		return KeepFirstLast(v, 1, 1, c)
	}
	return SameLengthMask(v, c)
}

// ---------- registration ----------

// registerCountryRules wires every rule in this file against m.
func registerCountryRules(m *Masker) {
	// Keep this table-driven so a reader can see the full catalogue
	// at a glance and spot missing registrations quickly.
	table := []struct {
		name, jurisdiction, description string
		fn                              func(v string, c rune) string
	}{
		{"us_ssn", "United States",
			"Preserves the last 4 digits of a 9-digit US SSN; accepts `AAA-GG-SSSS` and `AAAGGSSSS`. Example: 123-45-6789 → ***-**-6789.",
			maskUSSSN},
		{"ca_sin", "Canada",
			"Preserves the last 3 digits of a 9-digit Canadian SIN; accepts `AAA-BBB-CCC` and `AAABBBCCC`. Example: 123-456-789 → ***-***-789.",
			maskCASIN},
		{"uk_nino", "United Kingdom",
			"Preserves the 2 prefix letters and 1 suffix letter of a UK NINO; masks the 6 middle digits. Accepts `AB123456C` and `AB 12 34 56 C`. Example: AB123456C → AB******C.",
			maskUKNINO},
		{"in_aadhaar", "India",
			"Preserves the last 4 digits of a 12-digit Aadhaar number; accepts `123456789012` and `1234 5678 9012`. Example: 1234 5678 9012 → **** **** 9012.",
			maskINAadhaar},
		{"in_pan", "India",
			"Preserves the first 3 and last 2 characters of a 10-character Indian PAN. Example: ABCDE1234F → ABC*****4F.",
			maskINPAN},
		{"au_medicare_number", "Australia",
			"Preserves the last 2 digits of a 10-digit Australian Medicare number; accepts grouped `2123 45670 1` and compact `2123456701`. Example: 2123 45670 1 → **** ****0 1.",
			maskAUMedicareNumber},
		{"sg_nric_fin", "Singapore",
			"Preserves the leading letter and trailing letter of a 9-character Singapore NRIC/FIN. Example: S1234567A → S*******A.",
			maskSGNRICFIN},
		{"br_cpf", "Brazil",
			"Preserves the last 2 digits of an 11-digit Brazilian CPF; accepts compact and canonical forms. Example: 123.456.789-09 → ***.***.***-09.",
			maskBRCPF},
		{"br_cnpj", "Brazil",
			"Preserves the last 2 digits of a 14-digit Brazilian CNPJ; accepts compact and canonical forms. Example: 12.345.678/0001-95 → **.***.***/****-95.",
			maskBRCNPJ},
		{"mx_curp", "Mexico",
			"Preserves the first 4 and last 3 characters of an 18-character Mexican CURP. Example: GAPA850101HDFRRL09 → GAPA***********L09.",
			maskMXCURP},
		{"mx_rfc", "Mexico",
			"Preserves the first 3 and last 3 characters of a 12- or 13-character Mexican RFC. Example: GAPA8501014T3 → GAP*******4T3.",
			maskMXRFC},
		{"cn_resident_id", "China",
			"Preserves the first 6 (region code) and last 4 characters of an 18-character PRC Resident Identity Card number; the final character may be `X`. Example: 110101199003074578 → 110101********4578.",
			maskCNResidentID},
		{"za_national_id", "South Africa",
			"Preserves the first 6 (date of birth) and last 4 digits of a 13-digit South African national ID. Example: 8501015009087 → 850101***9087.",
			maskZANationalID},
		{"es_dni_nif_nie", "Spain",
			"Preserves the trailing control letter (and the leading letter for NIE/NIF inputs) of a 9-character Spanish DNI/NIF/NIE; masks the numeric body. Example: 12345678Z → ********Z.",
			maskESDNINIFNIE},
	}
	for _, r := range table {
		fn := r.fn
		m.mustRegisterBuiltin(r.name,
			func(v string) string { return fn(v, m.maskChar()) },
			RuleInfo{
				Name:         r.name,
				Category:     "identity",
				Jurisdiction: r.jurisdiction,
				Description:  strings.TrimSpace(r.description),
			})
	}
}

func init() {
	builtinRegistrars = append(builtinRegistrars, registerCountryRules)
}
