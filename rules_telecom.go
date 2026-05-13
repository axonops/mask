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

// Telecom-category rules implement the masks documented in
// docs/rules.md §"Telecom and location". Identifier rules (phone,
// mobile_phone_number, imei, imsi, msisdn) preserve a deterministic
// prefix (country code or fixed index) plus the last 2-4 digits;
// location rules reduce numeric precision or dispatch on postal-code
// shape. Every rule is fail-closed: malformed input routes to
// [SameLengthMask].

// ---------- file-local constants ----------

// imeiLen is the canonical IMEI length (14 digits + Luhn check
// digit). The rule does not verify the Luhn digit — masking is not
// validation — but any length other than 15 fails closed.
const imeiLen = 15

// imsiLen is the canonical IMSI length (3-digit MCC + 2-3 digit MNC
// + subscriber ID). We accept exactly 15 ASCII digits; 14-digit
// variants fail closed to keep the rule unambiguous.
const imsiLen = 15

// imsiKeepFirst / imsiKeepLast are the preserved window counts per
// the spec example (first 5 MCC+MNC digits + last 4 subscriber).
const (
	imsiKeepFirst = 5
	imsiKeepLast  = 4
)

// msisdnKeepFirst / msisdnKeepLast are the preserved window counts
// on MSISDN. The spec example uses a 2-digit country code (UK 44);
// country codes can be 1-3 digits but a strict lookup table is out
// of scope for the initial release. Operators needing strict
// per-country handling should route such fields through
// `phone_number` in E.164 form instead.
const (
	// msisdnMinLen and msisdnMaxLen are inclusive bounds; inputs
	// outside this range fail closed to SameLengthMask.
	msisdnKeepFirst = 2
	msisdnKeepLast  = 4
	msisdnMinLen    = 10
	msisdnMaxLen    = 15
)

// phoneKeepLast is the trailing digit window preserved by
// `phone_number` after the country-code literal.
const phoneKeepLast = 4

// ccMaxDigits is the cap on country-code length when parsing the
// leading `+NN` prefix of a phone number. ITU-T E.164 assigns up
// to 3-digit country codes, so 3 is the strict cap.
const ccMaxDigits = 3

// imeiKeepLast is the trailing digit window preserved by `imei`.
const imeiKeepLast = 4

// geoDecimals is the default decimal-place precision for
// `geo_latitude` and `geo_longitude`. Two decimals resolve to
// approximately 1.1 km at the equator — sufficient for "city
// district" granularity without identifying a street address.
const geoDecimals = 2

// ---------- rune / byte classifiers ----------

// isTelecomSeparator reports whether r is a character we admit as
// a phone-number structural separator. ASCII only — non-ASCII
// bytes in a phone number field fail closed elsewhere.
func isTelecomSeparator(r rune) bool {
	switch r {
	case ' ', '-', '.', '(', ')', '/':
		return true
	}
	return false
}

// ---------- phone_number / mobile_phone_number ----------

// maskPhoneNumber preserves a leading `+NN` country code literal OR
// the ITU-T `00NN` international access prefix and the last 4 digits,
// masking every other digit while keeping structural separators
// verbatim. The `00` prefix is preserved verbatim in the output — it
// is NOT rewritten to `+`. Inputs without a recognised prefix route
// through the same helper with an empty prefix — the whole input is
// treated as the body. Inputs whose body contains fewer than 4 digits
// fail closed over the whole value (the prefix is NOT echoed on short
// bodies).
//
// Spec examples:
//
//	+44 7911 123456    → +44 **** **3456
//	(555) 123-4567     → (***) ***-4567
//	+1-800-555-0199    → +1-***-***-0199
//	0044 7911 123456   → 0044 **** **3456
//	001-212-555-0100   → 001-***-***-0100
//
// `00<CC>` recognition is shape-based, not semantic: the parser does
// not validate the country code against an ITU-T table. Inputs
// starting with a single domestic `0` (e.g. `07911 123456`) fall
// through unchanged and are treated as having no country-code prefix.
//
// The rule accepts `mobile_phone_number` as an alias — the spec
// notes "prefer one international abstraction unless business rules
// differ". Operators needing jurisdiction-specific mobile rules
// should register a custom rule under the original name on a
// dedicated Masker.
func maskPhoneNumber(v string, c rune) string {
	if v == "" {
		return ""
	}
	prefix, body, ok := splitPhonePrefix(v)
	if !ok {
		return SameLengthMask(v, c)
	}
	if !isTelecomBody(body) {
		return SameLengthMask(v, c)
	}
	bodyDigits := countPhoneDigits(body)
	return keepFirstLastNonSepWithPrefix(prefix, body, 0, phoneKeepLast, bodyDigits, c, isTelecomSeparator)
}

// splitPhonePrefix dispatches on the leading byte of v and delegates
// to a prefix-shape-specific helper. Two prefix shapes are recognised:
//
//   - `+NN` followed by a separator (or end of string): see
//     [splitPlusPrefix]. 1-3 digit country code; no compact form.
//   - `00NN` followed by a separator OR another digit (compact form):
//     see [split00Prefix]. 1-3 digit country code; the leading CC
//     digit must be non-zero.
//
// Otherwise returns ("", v, true) — the whole value is the body.
// Returns (_, _, false) only when a recognised prefix is malformed.
//
// The caller must ensure v is non-empty; [maskPhoneNumber] guards
// this at its call site.
//
// DELIBERATE divergence between the two prefixes: compact form
// (`00CC<digits>` with no separator between CC and body) is accepted
// for `00`, rejected for `+`. The `00` access prefix is typographically
// packed against the CC in real dial strings (e.g. "00441234567890");
// `+` is a typographic sigil that is almost always followed by a
// separator. Do NOT mirror compact-form acceptance to `+` without
// revisiting #55 AC #5.
func splitPhonePrefix(v string) (string, string, bool) {
	switch v[0] {
	case '+':
		return splitPlusPrefix(v)
	case '0':
		if len(v) >= 3 && v[1] == '0' && isASCIIDecDigit(v[2]) && v[2] != '0' {
			return split00Prefix(v)
		}
	}
	return "", v, true
}

// splitPlusPrefix consumes the `+NN` shape. Caller must ensure
// v[0] == '+'.
func splitPlusPrefix(v string) (string, string, bool) {
	i := 1
	for i < len(v) && i-1 < ccMaxDigits && isASCIIDecDigit(v[i]) {
		i++
	}
	digits := i - 1
	if digits == 0 {
		return "", "", false
	}
	if i == len(v) {
		// `+44` with no body — body is empty, no separator required.
		return v, "", true
	}
	if !isTelecomSeparator(rune(v[i])) {
		return "", "", false
	}
	// Prefix includes the terminating separator so the body walk
	// starts on the first body digit/separator.
	return v[:i+1], v[i+1:], true
}

// split00Prefix consumes the `00<CC>` international access prefix.
// Caller must ensure len(v) >= 3, v[0] == '0', v[1] == '0', and v[2]
// is a non-zero ASCII digit. Inputs that fail those gates (e.g.
// `"00"` on length, `"00 "` / `"00-"` / `"00A"` / `"00\x00"` on the
// digit gate, `"00044"` on the non-zero gate) never enter here —
// they route through the empty-prefix branch in [splitPhonePrefix].
//
// Returns ("00<CC>", "", true) when the CC consumes the rest of v
// (e.g. `"0044"` alone). Returns ("00<CC>", body, true) when a
// separator terminates the CC. Returns ("00<CC>", body, true) with
// no separator between prefix and body when the compact form fires
// (e.g. `"00441234567890"`). Returns (_, _, false) on a non-digit
// non-separator byte after the CC.
func split00Prefix(v string) (string, string, bool) {
	i := 3
	for i < len(v) && i-2 < ccMaxDigits && isASCIIDecDigit(v[i]) {
		i++
	}
	if i == len(v) {
		// `0044` alone — whole value is the prefix, body empty.
		// Mirrors the `+44`-alone branch in splitPlusPrefix.
		// Downstream keepFirstLastNonSepWithPrefix sees bodyDigits=0
		// and falls back to SameLengthMask over the whole value.
		return v, "", true
	}
	if isASCIIDecDigit(v[i]) {
		// CC hit the cap of ccMaxDigits and the next byte is still a
		// digit. Accept as COMPACT form — see the divergence note on
		// splitPhonePrefix.
		return v[:i], v[i:], true
	}
	if isTelecomSeparator(rune(v[i])) {
		return v[:i+1], v[i+1:], true
	}
	// Non-digit, non-separator byte after the CC (e.g. multi-byte
	// UTF-8 lead byte, NUL, control char, `+`). Fail closed.
	return "", "", false
}

// isTelecomBody reports whether body consists only of ASCII digits
// and telecom separators. The last rune must NOT be a separator —
// trailing spaces / hyphens / dots would otherwise echo unmasked.
// The first rune is allowed to be `(` (US-format wrap character,
// matches the spec example `(555) 123-4567`); any other leading
// separator fails closed.
func isTelecomBody(body string) bool {
	if body == "" {
		return true
	}
	first := body[0]
	if isTelecomSeparator(rune(first)) && first != '(' {
		return false
	}
	if isTelecomSeparator(rune(body[len(body)-1])) {
		return false
	}
	for i := 0; i < len(body); i++ {
		b := body[i]
		if isASCIIDecDigit(b) {
			continue
		}
		if !isTelecomSeparator(rune(b)) {
			return false
		}
	}
	return true
}

// countPhoneDigits counts ASCII decimal digits in body. Body is
// guaranteed ASCII-only by [isTelecomBody].
func countPhoneDigits(body string) int {
	n := 0
	for i := 0; i < len(body); i++ {
		if isASCIIDecDigit(body[i]) {
			n++
		}
	}
	return n
}

// ---------- imei ----------

// maskIMEI preserves the last 4 digits of a 15-digit IMEI. Any
// length other than 15 or any non-digit byte fails closed.
func maskIMEI(v string, c rune) string {
	if v == "" {
		return ""
	}
	if len(v) != imeiLen || !allASCIIDigits(v) {
		return SameLengthMask(v, c)
	}
	return KeepLastN(v, imeiKeepLast, c)
}

// allASCIIDigits reports whether s is non-empty and every byte is an
// ASCII decimal digit.
func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isASCIIDecDigit(s[i]) {
			return false
		}
	}
	return true
}

// ---------- imsi ----------

// maskIMSI preserves the first 5 and last 4 digits of a 15-digit
// IMSI. Any length other than 15 or any non-digit byte fails closed.
func maskIMSI(v string, c rune) string {
	if v == "" {
		return ""
	}
	if len(v) != imsiLen || !allASCIIDigits(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, imsiKeepFirst, imsiKeepLast, c)
}

// ---------- msisdn ----------

// maskMSISDN preserves the first 2 and last 4 digits of a 10-15
// digit MSISDN. Any length outside that range, any non-digit byte,
// or a leading `+` (which would be E.164 territory — use
// `phone_number` instead) fails closed.
func maskMSISDN(v string, c rune) string {
	if v == "" {
		return ""
	}
	if len(v) < msisdnMinLen || len(v) > msisdnMaxLen || !allASCIIDigits(v) {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, msisdnKeepFirst, msisdnKeepLast, c)
}

// ---------- postal_code ----------

// maskPostalCode is a shape-dispatching rule. UK, US, and Canadian
// forms are recognised; any other shape fails closed. Uppercase
// ASCII required on alphabetic codes — lowercase variants fail
// closed.
//
// Spec examples:
//
//	SW1A 2AA  →  SW1A ***  (UK — keep outward code)
//	94103     →  941**     (US — keep first 3)
//	M5V 2T6   →  M5V ***   (Canada — keep FSA)
func maskPostalCode(v string, c rune) string {
	if v == "" {
		return ""
	}
	if out, ok := maskUKPostalCode(v, c); ok {
		return out
	}
	if out, ok := maskCAPostalCode(v, c); ok {
		return out
	}
	if out, ok := maskUSPostalCode(v, c); ok {
		return out
	}
	return SameLengthMask(v, c)
}

// maskUKPostalCode accepts 6-8 byte UK codes: outward code of 2-4
// ASCII characters (first byte letter, remainder letter/digit),
// single ASCII space, then `d[A-Z]{2}` inward code. Output
// preserves the outward code + space and masks the inward code.
func maskUKPostalCode(v string, c rune) (string, bool) {
	n := len(v)
	if n < 6 || n > 8 {
		return "", false
	}
	if v[n-4] != ' ' {
		return "", false
	}
	outward := v[:n-4]
	inward := v[n-3:]
	if !isUKOutwardCode(outward) || !isUKInwardCode(inward) {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(outward) + 1 + 3*safeRuneLen(c))
	b.WriteString(outward)
	b.WriteByte(' ')
	writeMaskRunes(&b, c, 3)
	return b.String(), true
}

// isUKOutwardCode reports whether s is a valid outward-code shape:
// first byte is A-Z; remaining 1-3 bytes are A-Z or 0-9 with at
// least one digit somewhere (outward codes always contain a
// district digit).
func isUKOutwardCode(s string) bool {
	if len(s) < 2 || len(s) > 4 {
		return false
	}
	if !isASCIIUpperLetter(s[0]) {
		return false
	}
	sawDigit := false
	for i := 1; i < len(s); i++ {
		b := s[i]
		switch {
		case isASCIIUpperLetter(b):
		case isASCIIDecDigit(b):
			sawDigit = true
		default:
			return false
		}
	}
	return sawDigit
}

// isUKInwardCode reports whether s is `d[A-Z]{2}`.
func isUKInwardCode(s string) bool {
	if len(s) != 3 {
		return false
	}
	return isASCIIDecDigit(s[0]) && isASCIIUpperLetter(s[1]) && isASCIIUpperLetter(s[2])
}

// maskCAPostalCode accepts `L#L #L#` (7 bytes): letter-digit-letter
// space digit-letter-digit. Output preserves the FSA (first 3
// bytes) + space and masks the LDU.
func maskCAPostalCode(v string, c rune) (string, bool) {
	if len(v) != 7 || v[3] != ' ' {
		return "", false
	}
	if !isASCIIUpperLetter(v[0]) || !isASCIIDecDigit(v[1]) || !isASCIIUpperLetter(v[2]) {
		return "", false
	}
	if !isASCIIDecDigit(v[4]) || !isASCIIUpperLetter(v[5]) || !isASCIIDecDigit(v[6]) {
		return "", false
	}
	var b strings.Builder
	b.Grow(4 + 3*safeRuneLen(c))
	b.WriteString(v[:4])
	writeMaskRunes(&b, c, 3)
	return b.String(), true
}

// maskUSPostalCode accepts exactly 5 ASCII digits (basic ZIP).
// ZIP+4 forms (`94103-6789`) are not currently recognised — they
// fail closed and can be added in a follow-up.
func maskUSPostalCode(v string, c rune) (string, bool) {
	if len(v) != 5 || !allASCIIDigits(v) {
		return "", false
	}
	// US ZIP codes are always exactly 5 ASCII digits, so we can use a
	// direct builder instead of KeepFirstN (which calls
	// utf8.RuneCountInString + byteOffsetAtRune over the whole string).
	// This matches the inline pattern used by maskCAPostalCode and
	// maskUKPostalCode and avoids the two extra O(n) scans.
	var b strings.Builder
	b.Grow(3 + 2*safeRuneLen(c))
	b.WriteString(v[:3])
	writeMaskRunes(&b, c, 2)
	return b.String(), true
}

// isASCIIUpperLetter reports whether b is A-Z.
func isASCIIUpperLetter(b byte) bool { return b >= 'A' && b <= 'Z' }

// ---------- geo_latitude / geo_longitude ----------

// maskGeoNumber applies [ReducePrecision] to v but fails closed
// when v has no fractional part or fewer digits after the decimal
// point than the masking would consume — those cases would make
// `ReducePrecision` echo the input verbatim.
func maskGeoNumber(v string, c rune) string {
	if v == "" {
		return ""
	}
	dot := strings.IndexByte(v, '.')
	if dot < 0 {
		return SameLengthMask(v, c)
	}
	if dot+1+geoDecimals >= len(v) {
		return SameLengthMask(v, c)
	}
	return ReducePrecision(v, geoDecimals, c)
}

// ---------- geo_coordinates ----------

// maskGeoCoordinates splits v on a single ASCII comma and applies
// [maskGeoNumber] to each half. Fails closed on zero or multiple
// commas, on whitespace around the comma, or on either half failing
// the plain-decimal-with-fractional-part check.
func maskGeoCoordinates(v string, c rune) string {
	if v == "" {
		return ""
	}
	comma := strings.IndexByte(v, ',')
	if comma <= 0 || comma == len(v)-1 {
		return SameLengthMask(v, c)
	}
	if strings.IndexByte(v[comma+1:], ',') >= 0 {
		return SameLengthMask(v, c)
	}
	lat := v[:comma]
	lon := v[comma+1:]
	if !isGeoMaskable(lat) || !isGeoMaskable(lon) {
		return SameLengthMask(v, c)
	}
	// Build the result in a single allocation. The output for each half
	// has the same length as the input when c is a single-byte rune; the
	// tail digits may expand by (cLen-1) bytes each when c is multi-byte.
	// Worst case: each byte in each half is masked → len*cLen bytes.
	cLen := safeRuneLen(c)
	var b strings.Builder
	b.Grow(len(lat)*cLen + 1 + len(lon)*cLen)
	writeReducePrecision(&b, lat, geoDecimals, c)
	b.WriteByte(',')
	writeReducePrecision(&b, lon, geoDecimals, c)
	return b.String()
}

// isGeoMaskable reports whether s has the shape [maskGeoNumber]
// would successfully mask — a plain decimal with a fractional
// portion long enough for at least one digit to be masked past the
// configured precision. Short-circuits the `maskGeoNumber`
// fail-closed path so [maskGeoCoordinates] can decide to fail
// closed on the WHOLE pair rather than produce half-masked output.
// Also rejects inputs with multiple `.` bytes; `ReducePrecision`
// would otherwise correctly fall back for the multi-dot half, but
// [maskGeoCoordinates] joins the halves directly so a per-half
// fallback would leak the other half of the pair.
func isGeoMaskable(s string) bool {
	if s == "" || s[0] == '+' {
		return false
	}
	dot := strings.IndexByte(s, '.')
	if dot < 0 ||
		strings.IndexByte(s[dot+1:], '.') >= 0 ||
		dot+1+geoDecimals >= len(s) {
		return false
	}
	return hasOnlyDecimalBytes(s)
}

// hasOnlyDecimalBytes reports whether s is composed solely of ASCII
// decimal digits, a single leading `-`, and (possibly) `.` bytes.
// The leading-sign and `.` placement are validated by the caller —
// this helper only gates the character class.
func hasOnlyDecimalBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case i == 0 && b == '-':
		case b == '.':
		case isASCIIDecDigit(b):
		default:
			return false
		}
	}
	return true
}

// ---------- registration ----------

// registerTelecomRules wires every rule in this file against m.
func registerTelecomRules(m *Masker) {
	phone := func(v string) string { return maskPhoneNumber(v, m.maskChar()) }
	m.mustRegisterBuiltin("phone_number", phone,
		RuleInfo{
			Name: "phone_number", Category: "telecom", Jurisdiction: "global",
			Description: "Preserves a leading +NN country code or 00NN international access prefix (if present) and the last 4 digits; masks middle digits while preserving structural separators. The 00 prefix is kept verbatim, not rewritten to +. Inputs with a single domestic leading 0 (e.g. 07911 123456) are treated as having no country-code prefix. The 00 parser accepts compact form (00CC<digits> with no separator); the + parser requires a separator after the country code. Example: +44 7911 123456 → +44 **** **3456; 0044 7911 123456 → 0044 **** **3456.",
		})
	m.mustRegisterBuiltin("mobile_phone_number", phone,
		RuleInfo{
			Name: "mobile_phone_number", Category: "telecom", Jurisdiction: "global",
			Description: "Alias of `phone_number` — identical input-to-output behaviour, including the 00NN international access prefix and compact-form support. Exists so callers with mobile-specific schema naming can register that name without re-wrapping. Prefer `phone_number` for new code; register a distinct custom rule if mobile-specific masking matters to your workload. Example: +44 7911 123456 → +44 **** **3456; 0044 7911 123456 → 0044 **** **3456.",
		})
	m.mustRegisterBuiltin("imei",
		func(v string) string { return maskIMEI(v, m.maskChar()) },
		RuleInfo{
			Name: "imei", Category: "telecom", Jurisdiction: "global",
			Description: "Preserves the last 4 digits of a 15-digit IMEI; all other inputs fail closed. Example: 353456789012345 → ***********2345.",
		})
	m.mustRegisterBuiltin("imsi",
		func(v string) string { return maskIMSI(v, m.maskChar()) },
		RuleInfo{
			Name: "imsi", Category: "telecom", Jurisdiction: "global",
			Description: "Preserves the first 5 (MCC+MNC) and last 4 digits of a 15-digit IMSI; other inputs fail closed. Example: 310260123456789 → 31026******6789.",
		})
	m.mustRegisterBuiltin("msisdn",
		func(v string) string { return maskMSISDN(v, m.maskChar()) },
		RuleInfo{
			Name: "msisdn", Category: "telecom", Jurisdiction: "global",
			Description: "Preserves the first 2 and last 4 digits of a 10-15 digit MSISDN; inputs with a leading `+` fail closed — use `phone_number` for E.164 input. Example: 447911123456 → 44******3456.",
		})
	m.mustRegisterBuiltin("postal_code",
		func(v string) string { return maskPostalCode(v, m.maskChar()) },
		RuleInfo{
			Name: "postal_code", Category: "location", Jurisdiction: "global (country-aware precision reduction)",
			Description: "Shape-aware across UK (keep outward code), US 5-digit ZIP (keep first 3), and Canada (keep FSA); other shapes fail closed. Example: SW1A 2AA → SW1A ***.",
		})
	m.mustRegisterBuiltin("geo_latitude",
		func(v string) string { return maskGeoNumber(v, m.maskChar()) },
		RuleInfo{
			Name: "geo_latitude", Category: "location", Jurisdiction: "global",
			Description: "Reduces decimal precision to 2 places by truncation (not rounding); input without a fractional part fails closed. Roughly 1.1 km resolution — not anonymisation. Example: 37.7749295 → 37.77*****.",
		})
	m.mustRegisterBuiltin("geo_longitude",
		func(v string) string { return maskGeoNumber(v, m.maskChar()) },
		RuleInfo{
			Name: "geo_longitude", Category: "location", Jurisdiction: "global",
			Description: "Reduces decimal precision to 2 places by truncation (not rounding); input without a fractional part fails closed. Example: -122.4194155 → -122.41*****.",
		})
	m.mustRegisterBuiltin("geo_coordinates",
		func(v string) string { return maskGeoCoordinates(v, m.maskChar()) },
		RuleInfo{
			Name: "geo_coordinates", Category: "location", Jurisdiction: "global",
			Description: "Splits on a single comma and applies `geo_latitude` / `geo_longitude` to each half; any other shape fails closed. Example: 37.7749,-122.4194 → 37.77**,-122.41**.",
		})
}

func init() {
	builtinRegistrars = append(builtinRegistrars, registerTelecomRules)
}
