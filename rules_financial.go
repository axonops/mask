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

// Financial-category rules implement the payment-card, banking, and
// monetary masks documented in docs/rules.md §"Financial". Each rule
// preserves separators where the format demands, falls closed on
// malformed input, and reads the Masker's configured mask character
// at apply time.
//
// Regulatory note: payment_card_* rules are aligned with the PCI DSS
// display-limit guidance of "at most the first 6 and last 4" — consumers
// with stricter policies should compose payment_card_pan_last4 or
// full_redact. CVV and PIN are Sensitive Authentication Data that must not
// be retained after authorisation; the library masks them but does not
// govern storage decisions.

// isFinancialSeparator reports whether r is treated as a grouping
// separator in this category's inputs: ASCII hyphen, ASCII space, or
// U+00A0 non-breaking space. Periods and slashes are deliberately NOT
// separators — a decimal point in a card number is malformed input, not
// a structural break.
func isFinancialSeparator(r rune) bool {
	return r == '-' || r == ' ' || r == '\u00A0'
}

// countDigitsAllDigits walks v, counts non-separator runes (via isSep), and
// reports whether every non-separator rune is an ASCII digit. The single
// pass is zero-alloc because range-looping a string does not allocate.
func countDigitsAllDigits(v string, isSep func(rune) bool) (count int, allDigits bool) {
	allDigits = true
	for _, r := range v {
		if isSep(r) {
			continue
		}
		count++
		// Range-check on rune rather than byte: only ASCII digits 0-9
		// pass, so any non-ASCII or non-digit rune trips the flag.
		if r < '0' || r > '9' {
			allDigits = false
		}
	}
	return count, allDigits
}

// --- PAN family ---

// maskPaymentCardPAN keeps the first 6 and last 4 non-separator digits of
// a 13-to-19-digit card number, preserving dashes, ASCII spaces, and
// non-breaking spaces between digit groups. Non-ASCII digits, mixed
// letters, and anything outside the 13–19 digit envelope fall back to a
// same-length mask.
//
// PCI DSS note: the first 6 + last 4 display limit is "at most" — this
// rule implements the maximum. Consumers needing a stricter display
// should use payment_card_pan_last4 or full_redact instead.
func maskPaymentCardPAN(v string, c rune) string {
	return maskPANWindow(v, 6, 4, c)
}

// maskPaymentCardPANFirst6 keeps the first 6 non-separator digits and
// masks the rest; same validation and separator handling as
// maskPaymentCardPAN.
func maskPaymentCardPANFirst6(v string, c rune) string {
	return maskPANWindow(v, 6, 0, c)
}

// maskPaymentCardPANLast4 keeps the last 4 non-separator digits and masks
// the rest; same validation and separator handling as maskPaymentCardPAN.
func maskPaymentCardPANLast4(v string, c rune) string {
	return maskPANWindow(v, 0, 4, c)
}

// maskPANWindow is the shared implementation for the three PAN variants.
// Validates digit count in [13,19] and ASCII-only digits, then delegates
// to keepFirstLastNonSep. Fails closed to same-length mask on any
// validation failure.
func maskPANWindow(v string, first, last int, c rune) string {
	if v == "" {
		return ""
	}
	count, allDigits := countDigitsAllDigits(v, isFinancialSeparator)
	if !allDigits || count < 13 || count > 19 {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSep(v, first, last, c, isFinancialSeparator)
}

// --- Sensitive authentication data ---

// maskPaymentCardCVV masks the card verification value with a same-length
// replacement.
//
// WARNING: length-preserving output leaks card-family information — a
// 3-digit CVV is Visa/Mastercard/Discover, a 4-digit CVV is American
// Express. The spec's examples are length-preserving (`123` → `***`,
// `1234` → `****`), so that is the implemented behaviour. Consumers who
// need length-hiding should register `full_redact` under their own rule
// name. See PCI DSS §3.2 — CVV is Sensitive Authentication Data and must
// not be retained after authorisation, which is the caller's concern.
func maskPaymentCardCVV(v string, c rune) string {
	return SameLengthMask(v, c)
}

// maskPaymentCardPIN masks the card personal identification number with a
// same-length replacement. See maskPaymentCardCVV for the length-leak
// rationale — a 4-digit PIN vs a 6-digit PIN is observable.
func maskPaymentCardPIN(v string, c rune) string {
	return SameLengthMask(v, c)
}

// --- Bank account / sort code / ABA ---

// maskBankAccountNumber keeps the last 4 non-separator runes, preserving
// dashes and spaces. Inputs with 4 or fewer non-separator runes — where
// the keep window would span the whole value and leak it verbatim — fall
// back to a same-length mask, honouring the library's fail-closed
// contract.
func maskBankAccountNumber(v string, c rune) string {
	if v == "" {
		return ""
	}
	nonsep := countNonSep(v, isFinancialSeparator)
	if nonsep <= 4 {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSep(v, 0, 4, c, isFinancialSeparator)
}

// maskUKSortCode keeps the first 2 digits of a UK sort code and masks
// the remaining 4, preserving dashes and spaces. Non-digit content or
// wrong digit count (UK sort codes are exactly 6 digits) falls back to a
// same-length mask.
func maskUKSortCode(v string, c rune) string {
	if v == "" {
		return ""
	}
	count, allDigits := countDigitsAllDigits(v, isFinancialSeparator)
	if !allDigits || count != 6 {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSep(v, 2, 0, c, isFinancialSeparator)
}

// maskUSABARoutingNumber keeps the last 4 digits of a US ABA routing
// number (9 digits). Wrong digit count, non-digit content, or the
// presence of separators falls back to a same-length mask — ABA routing
// numbers have no separator convention, so separators are malformed.
func maskUSABARoutingNumber(v string, c rune) string {
	if v == "" {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if !isASCIIDecDigit(v[i]) {
			return SameLengthMask(v, c)
		}
	}
	if len(v) != 9 {
		return SameLengthMask(v, c)
	}
	return keepFirstLastNonSep(v, 0, 4, c, isFinancialSeparator)
}

// --- IBAN ---

// isUpperAlphanumeric reports whether r is A–Z or 0–9. Used by IBAN
// validation, which is uppercase ASCII per ISO 13616.
func isUpperAlphanumeric(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	return false
}

// isIBANSeparator reports whether r is a recognised IBAN grouping
// separator. Per ISO 13616 the only recognised separator is the ASCII
// space; hyphens, NBSPs, and other punctuation are not standard and are
// treated as payload characters (which then fail the alphanumeric check
// and route the input to same-length mask).
//
// Deliberately distinct from [isFinancialSeparator]: a future
// "simplify to call isFinancialSeparator" would silently accept NBSP and
// hyphens in IBANs, which ISO 13616 does not. Keep them separate.
func isIBANSeparator(r rune) bool {
	return r == ' '
}

// maskIBAN masks an International Bank Account Number per ISO 13616.
// Keeps the country code (first 2) + check digits (next 2) and the last
// 4 non-separator runes, preserving grouping spaces. The non-separator
// payload must be 15–34 uppercase ASCII alphanumeric characters; anything
// else (lowercase, hyphens, other punctuation) falls back to a
// same-length mask without mutating input.
func maskIBAN(v string, c rune) string {
	if v == "" {
		return ""
	}
	nonsep := 0
	valid := true
	for _, r := range v {
		if isIBANSeparator(r) {
			continue
		}
		nonsep++
		if !isUpperAlphanumeric(r) {
			valid = false
		}
	}
	if !valid || nonsep < 15 || nonsep > 34 {
		return SameLengthMask(v, c)
	}
	// Count pass above already produced nonsep; pass it through to avoid a
	// redundant second walk inside keepFirstLastNonSep.
	return keepFirstLastNonSepCounted(v, 4, 4, nonsep, c, isIBANSeparator)
}

// --- SWIFT / BIC ---

// maskSWIFTBIC masks a SWIFT/BIC code per ISO 9362. Keeps the 4-character
// bank code and masks the remainder. Length must be exactly 8 or 11
// uppercase ASCII alphanumeric characters; anything else falls back to a
// same-length mask.
//
// The 4-character bank code is registry-public data and is not treated as
// a privacy leak by itself.
func maskSWIFTBIC(v string, c rune) string {
	if v == "" {
		return ""
	}
	if len(v) != 8 && len(v) != 11 {
		return SameLengthMask(v, c)
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if (b < 'A' || b > 'Z') && !isASCIIDecDigit(b) {
			return SameLengthMask(v, c)
		}
	}
	return KeepFirstN(v, 4, c)
}

// --- monetary_amount ---

// maskMonetaryAmount returns the full-redact marker regardless of input.
//
// Signature note: unlike every other rule in this file, this function
// does not take a mask-character argument — the output is the constant
// [FullRedactMarker], so no mask rune is ever emitted. The registrar at
// the bottom of the file therefore wires it into the Masker without a
// mask-character closure.
//
// Length preservation is deliberately NOT used: the width of `$9.99`
// versus `$9,999,999.99` leaks order of magnitude, which is usually the
// opposite of what a monetary mask should do. Consumers needing
// range-bucketing or precision reduction should register a custom rule.
func maskMonetaryAmount(_ string) string {
	return FullRedactMarker
}

// registerFinancialRules wires every rule in this file against m.
func registerFinancialRules(m *Masker) {
	m.mustRegisterBuiltin("payment_card_pan",
		func(v string) string { return maskPaymentCardPAN(v, m.maskChar()) },
		RuleInfo{
			Name: "payment_card_pan", Category: "financial", Jurisdiction: "global (PCI DSS)",
			Description: "Keeps the first 6 (BIN) and the last 4 digits; preserves dashes and spaces; requires 13-19 ASCII digits. Example: 4111-1111-1111-1111 → 4111-11**-****-1111.",
		})

	m.mustRegisterBuiltin("payment_card_pan_first6",
		func(v string) string { return maskPaymentCardPANFirst6(v, m.maskChar()) },
		RuleInfo{
			Name: "payment_card_pan_first6", Category: "financial", Jurisdiction: "global (PCI DSS)",
			Description: "Keeps only the first 6 digits (BIN); preserves dashes and spaces. Example: 4111-1111-1111-1111 → 4111-11**-****-****.",
		})

	m.mustRegisterBuiltin("payment_card_pan_last4",
		func(v string) string { return maskPaymentCardPANLast4(v, m.maskChar()) },
		RuleInfo{
			Name: "payment_card_pan_last4", Category: "financial", Jurisdiction: "global (PCI DSS)",
			Description: "Keeps only the last 4 digits; preserves dashes and spaces. Example: 4111-1111-1111-1111 → ****-****-****-1111.",
		})

	m.mustRegisterBuiltin("payment_card_cvv",
		func(v string) string { return maskPaymentCardCVV(v, m.maskChar()) },
		RuleInfo{
			Name: "payment_card_cvv", Category: "financial", Jurisdiction: "global (PCI DSS)",
			Description: "Same-length mask; CVV is Sensitive Authentication Data that must not be retained post-authorisation. Example: 123 → ***.",
		})

	m.mustRegisterBuiltin("payment_card_pin",
		func(v string) string { return maskPaymentCardPIN(v, m.maskChar()) },
		RuleInfo{
			Name: "payment_card_pin", Category: "financial", Jurisdiction: "global",
			Description: "Same-length mask for the PIN value. Length-preserving output leaks PIN width; callers concerned about that should register full_redact under a custom rule name. Example: 1234 → ****.",
		})

	m.mustRegisterBuiltin("bank_account_number",
		func(v string) string { return maskBankAccountNumber(v, m.maskChar()) },
		RuleInfo{
			Name: "bank_account_number", Category: "financial", Jurisdiction: "global",
			Description: "Keeps the last 4 non-separator characters and preserves dashes and spaces. Example: 1234-5678-9012 → ****-****-9012.",
		})

	m.mustRegisterBuiltin("uk_sort_code",
		func(v string) string { return maskUKSortCode(v, m.maskChar()) },
		RuleInfo{
			Name: "uk_sort_code", Category: "financial", Jurisdiction: "United Kingdom",
			Description: "Keeps the first 2 digits of a UK 6-digit sort code; preserves dashes and spaces. Example: 12-34-56 → 12-**-**.",
		})

	m.mustRegisterBuiltin("us_aba_routing_number",
		func(v string) string { return maskUSABARoutingNumber(v, m.maskChar()) },
		RuleInfo{
			Name: "us_aba_routing_number", Category: "financial", Jurisdiction: "United States",
			Description: "Keeps the last 4 digits of a US ABA routing number (9 digits, no separators). Example: 021000021 → *****0021.",
		})

	m.mustRegisterBuiltin("iban",
		func(v string) string { return maskIBAN(v, m.maskChar()) },
		RuleInfo{
			Name: "iban", Category: "financial", Jurisdiction: "global (ISO 13616)",
			Description: "Keeps the country code, check digits, and the last 4 uppercase ASCII alphanumeric characters; preserves grouping spaces. Example: GB82WEST12345698765432 → GB82**************5432.",
		})

	m.mustRegisterBuiltin("swift_bic",
		func(v string) string { return maskSWIFTBIC(v, m.maskChar()) },
		RuleInfo{
			Name: "swift_bic", Category: "financial", Jurisdiction: "global (ISO 9362)",
			Description: "Keeps the 4-character bank code; requires 8 or 11 uppercase ASCII alphanumeric characters. Example: BARCGB2L → BARC****.",
		})

	m.mustRegisterBuiltin("monetary_amount",
		maskMonetaryAmount,
		RuleInfo{
			Name: "monetary_amount", Category: "financial", Jurisdiction: "global",
			Description: "Replaces any value with [REDACTED]. Length-preserving output would leak order of magnitude. Example: $1,234.56 → [REDACTED].",
		})
}

func init() {
	builtinRegistrars = append(builtinRegistrars, registerFinancialRules)
}
