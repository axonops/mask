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
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Identity-category rules implement the 11 personal-identifier masks listed
// in docs/v0.9.0-requirements.md §"Personal and Identity". Each rule is a
// thin wrapper over primitives in primitives.go with format-aware parsing.
//
// Grapheme note: the spec asks for "grapheme-aware" handling on name rules.
// The Go stdlib does not ship a grapheme-cluster iterator, so these rules
// operate on Unicode runes. In practice this matches user expectation for
// precomposed input. Decomposed forms (e.g. `e\u0301` for "é") expose the
// base letter and mask the combining mark as a separate rune — document on
// the affected rules.
//
// HIPAA Safe Harbor: rules in this category are pseudonymisation, not
// anonymisation. Retaining a year on `date_of_birth`, the full domain on
// `email_address`, or a 2-letter country prefix on `passport_number` does
// not by itself satisfy HIPAA Safe Harbor — each affected rule carries an
// explicit inline warning. See SECURITY.md for the library's overall
// threat model.

var (
	// Date-of-birth format patterns. Compiled once at package init; never
	// re-evaluated against user input, so no ReDoS surface.
	reDOBISO       = regexp.MustCompile(`^(\d{4})-(\d{1,2})-(\d{1,2})$`)
	reDOBSlash     = regexp.MustCompile(`^(\d{1,2})/(\d{1,2})/(\d{4})$`)
	reDOBMonthName = regexp.MustCompile(`^([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})$`)

	// monthNames is the closed set of full English month names recognised
	// by the date_of_birth rule in the month-name format. Match is
	// case-insensitive.
	monthNames = map[string]struct{}{
		"january": {}, "february": {}, "march": {}, "april": {},
		"may": {}, "june": {}, "july": {}, "august": {},
		"september": {}, "october": {}, "november": {}, "december": {},
	}

	// streetTypeSet is the small ASCII set of recognised trailing street
	// tokens for the `street_address` rule. Case-insensitive, and a
	// trailing period on an abbreviation is tolerated before lookup.
	// This list is intentionally short and English-biased; non-English
	// addresses fall through to the same_length_mask fallback.
	streetTypeSet = map[string]struct{}{
		"st": {}, "street": {},
		"rd": {}, "road": {},
		"ave": {}, "avenue": {},
		"blvd": {}, "boulevard": {},
		"ln": {}, "lane": {},
		"dr": {}, "drive": {},
		"way": {},
		"pl":  {}, "place": {},
		"ct": {}, "court": {},
		"nw": {}, "ne": {}, "sw": {}, "se": {},
		"n": {}, "s": {}, "e": {}, "w": {},
	}
)

// maskEmail masks an email address by keeping the first rune of the local
// part and the full domain (including the `@` separator). Input with no
// `@`, an empty local part, or an empty domain falls back to a
// same-length mask — never returns the original value. Inputs whose local
// part is a single rune are returned unchanged per the spec
// (`x@y.com` → `x@y.com`).
//
// WARNING: this rule retains the full domain. On low-cardinality internal
// domains (e.g. a corporate SSO domain with a few hundred users) the
// combination of one leading character + full domain provides very little
// re-identification resistance. When the domain itself is sensitive,
// compose with `deterministic_hash` or register a stricter custom rule.
func maskEmail(v string, c rune) string {
	if v == "" {
		return ""
	}
	i := strings.LastIndexByte(v, '@')
	if i <= 0 || i == len(v)-1 {
		return SameLengthMask(v, c)
	}
	local, domain := v[:i], v[i:] // domain includes '@'
	if utf8.RuneCountInString(local) <= 1 {
		return v
	}
	return KeepFirstN(local, 1, c) + domain
}

// nameSeparators reports whether r is treated as a separator by the name
// rules: Unicode whitespace, ASCII hyphen, or ASCII apostrophe. Periods
// and CJK punctuation are NOT separators — they remain part of the token.
func nameSeparators(r rune) bool {
	return unicode.IsSpace(r) || r == '-' || r == '\''
}

// maskPersonName masks a multi-token name by keeping the first rune of
// each separator-delimited token. Separators (whitespace, hyphen,
// apostrophe) are preserved verbatim. Empty input is returned unchanged.
// Whitespace-only input falls back to same-length mask.
//
// Token model: the stdlib has no grapheme-cluster iterator, so tokens are
// measured in Unicode runes. Precomposed accented characters (e.g. "María"
// normalised to NFC) behave as expected. Decomposed forms (base letter
// plus combining mark) are two runes — the base is kept, the combining
// mark is masked as a separate rune. Callers handling multilingual data
// should NFC-normalise input before masking.
//
// CJK without separators: `佐藤太郎` contains no separator character and is
// treated as a single 4-rune token (→ `佐***`). The spec example expects
// token-per-character for CJK, which requires a language-aware segmenter
// not present in stdlib. This is a documented deviation, pinned by BDD
// scenarios so it cannot regress silently.
func maskPersonName(v string, c rune) string {
	if v == "" {
		return ""
	}
	if strings.TrimSpace(v) == "" {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(len(v))
	inToken := false
	for _, r := range v {
		if nameSeparators(r) {
			b.WriteRune(r)
			inToken = false
			continue
		}
		if !inToken {
			b.WriteRune(r)
			inToken = true
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// maskGivenOrFamilyName keeps only the first rune of the whole input.
// Empty input returns empty; 1-rune input is returned unchanged via the
// underlying KeepFirstN.
func maskGivenOrFamilyName(v string, c rune) string {
	return KeepFirstN(v, 1, c)
}

// leadingDigits returns the byte-length prefix of s consisting of ASCII
// digits 0-9. Non-ASCII digit scripts (Arabic-Indic, Devanagari) are
// deliberately not matched — a house number is always ASCII in this
// library's scope.
func leadingDigits(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

// streetTypeSuffix returns the byte offset within s where the recognised
// trailing street-type suffix begins, or -1 if no recognised suffix is
// present. The detector is greedy: trailing tokens are consumed
// right-to-left while each one remains in streetTypeSet, so
// "Avenue NW" matches as a two-word suffix.
//
// Matching is ASCII case-insensitive; a single trailing period on an
// abbreviation ("St.") is tolerated when looking the token up.
func streetTypeSuffix(s string) int {
	// A scratch buffer sized to the longest street-type token in
	// streetTypeSet ("boulevard" = 9 bytes) keeps this loop zero-alloc.
	var scratch [16]byte
	end := len(s)
	out := -1
	for end > 0 {
		start, lookupEnd := lastTokenBounds(s, end)
		if !recognisedStreetToken(s, start, lookupEnd, scratch[:]) {
			return out
		}
		out = start
		end = start
		if end > 0 && s[end-1] == ' ' {
			end--
		}
	}
	return out
}

// lastTokenBounds returns the byte range [start, lookupEnd) of the last
// space-delimited token in s[:end]. A single trailing period on the token
// is stripped from lookupEnd so abbreviations like "St." look up as "St".
func lastTokenBounds(s string, end int) (start, lookupEnd int) {
	start = end
	for start > 0 && s[start-1] != ' ' {
		start--
	}
	lookupEnd = end
	if lookupEnd > start && s[lookupEnd-1] == '.' {
		lookupEnd--
	}
	return start, lookupEnd
}

// recognisedStreetToken reports whether s[start:lookupEnd] (ASCII
// case-insensitive) is present in streetTypeSet. The caller's scratch
// buffer must be at least as large as the longest key in the set.
func recognisedStreetToken(s string, start, lookupEnd int, scratch []byte) bool {
	tok := s[start:lookupEnd]
	if len(tok) == 0 || len(tok) > len(scratch) {
		return false
	}
	for i := 0; i < len(tok); i++ {
		scratch[i] = asciiToLower(tok[i])
	}
	_, ok := streetTypeSet[string(scratch[:len(tok)])]
	return ok
}

// asciiToLower returns the ASCII lowercase of b without allocation.
// Non-ASCII bytes are returned unchanged.
func asciiToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// maskStreet masks a street address by keeping the leading ASCII house
// number (if present) and the trailing recognised street type (if
// present). Everything between is masked rune-wise while internal spaces
// are preserved. When neither signal is present, the rule falls back to a
// same-length mask.
//
// WARNING: retaining the house number is a potent re-identification hint
// when combined with any postcode/ZIP on the same record. Compose with a
// postcode-masking rule when ZIP is present.
func maskStreet(v string, c rune) string {
	if v == "" {
		return ""
	}
	head, spaceAfterHead, rest := splitHouseNumber(v)
	tailOff := streetTypeSuffix(rest)
	if head == "" && tailOff < 0 {
		return SameLengthMask(v, c)
	}
	body, tail := splitBodyAndTail(rest, tailOff)
	// Fail-closed guard: if the recognised suffix consumed the entire
	// non-digit portion of the input, the rule would echo v unchanged.
	// That happens on inputs like "42 N" or "1 NE" where the whole
	// non-digit body is itself a recognised single-letter direction
	// token. Drop the suffix and mask the non-digit portion rune-wise,
	// preserving internal whitespace so the output matches input length.
	if strings.TrimSpace(body) == "" {
		if head == "" {
			return SameLengthMask(v, c)
		}
		var out strings.Builder
		out.Grow(len(v))
		out.WriteString(head)
		maskBodyPreservingSpaces(&out, v[len(head):], c)
		return out.String()
	}

	var out strings.Builder
	out.Grow(len(v))
	out.WriteString(head)
	out.WriteString(spaceAfterHead)
	maskBodyPreservingSpaces(&out, body, c)
	out.WriteString(tail)
	return out.String()
}

// splitHouseNumber returns the ASCII-digit house number prefix, the
// (optional) single space that follows it, and the remainder of the input.
func splitHouseNumber(v string) (head, spaceAfter, rest string) {
	n := leadingDigits(v)
	head = v[:n]
	rest = v[n:]
	if n > 0 && len(rest) > 0 && rest[0] == ' ' {
		spaceAfter = " "
		rest = rest[1:]
	}
	return head, spaceAfter, rest
}

// splitBodyAndTail separates the body to mask from the recognised trailing
// street-type suffix. When tailOff < 0 the whole string is body.
func splitBodyAndTail(rest string, tailOff int) (body, tail string) {
	if tailOff < 0 {
		return rest, ""
	}
	body = strings.TrimRight(rest[:tailOff], " ")
	tail = rest[tailOff:]
	// Preserve exactly one separating space between masked body and tail.
	if body != rest[:tailOff] {
		tail = " " + tail
	}
	return body, tail
}

// maskBodyPreservingSpaces writes the rune-wise mask of body into b,
// keeping whitespace verbatim.
func maskBodyPreservingSpaces(b *strings.Builder, body string, c rune) {
	for _, r := range body {
		if unicode.IsSpace(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteRune(c)
	}
}

// maskDateOfBirth preserves the four-digit year and masks month and day.
// Three formats are recognised:
//
//   - ISO `YYYY-M-D` (hyphen-separated, 1–2 digit M/D allowed)
//   - Slash `D/M/YYYY` (the middle group is always emitted as four mask
//     runes, regardless of M's rune count — this matches the spec
//     example `15/03/1985` → `**/****/1985` exactly)
//   - Month name `Month D, YYYY` (full English month names, case-insensitive)
//
// Any other shape — year only, time suffix, dotted European, two-digit
// year — falls back to same-length mask.
//
// WARNING: this rule does NOT by itself satisfy HIPAA Safe Harbor
// de-identification. Safe Harbor requires ages over 89 to be aggregated
// ("90 or above"); this rule preserves the year regardless. Combine with
// an age-banding transform upstream for Safe Harbor workflows. This rule
// is pseudonymisation of the month/day, not anonymisation of the date.
func maskDateOfBirth(v string, c rune) string {
	if v == "" {
		return ""
	}
	if m := reDOBISO.FindStringSubmatch(v); m != nil {
		return buildDOB(c, m[1], "-", len(m[2]), "-", len(m[3]), "")
	}
	if m := reDOBSlash.FindStringSubmatch(v); m != nil {
		// Per spec, the middle group is always 4 stars regardless of the
		// matched month width. See
		// docs/v0.9.0-requirements.md §"date_of_birth" example.
		return buildDOBPrefixedLiteral(c, len(m[1]), "/", 4, "/", m[3])
	}
	if m := reDOBMonthName.FindStringSubmatch(v); m != nil {
		if monthNameRecognised(m[1]) {
			return buildDOBPrefixedLiteral(c, len(m[1]), " ", len(m[2]), ", ", m[3])
		}
	}
	return SameLengthMask(v, c)
}

// buildDOB emits "<year><sep1><nMask1><sep2><nMask2><tail>" in one
// allocation via a pre-grown strings.Builder.
func buildDOB(c rune, year, sep1 string, n1 int, sep2 string, n2 int, tail string) string {
	var b strings.Builder
	b.Grow(len(year) + len(sep1) + n1*safeRuneLen(c) + len(sep2) + n2*safeRuneLen(c) + len(tail))
	b.WriteString(year)
	b.WriteString(sep1)
	writeMaskRunes(&b, c, n1)
	b.WriteString(sep2)
	writeMaskRunes(&b, c, n2)
	b.WriteString(tail)
	return b.String()
}

// buildDOBPrefixedLiteral emits "<nMask1><sep1><nMask2><sep2><yearLiteral>".
// Used by formats that start with a masked group (slash, month-name).
func buildDOBPrefixedLiteral(c rune, n1 int, sep1 string, n2 int, sep2, yearLiteral string) string {
	var b strings.Builder
	b.Grow(n1*safeRuneLen(c) + len(sep1) + n2*safeRuneLen(c) + len(sep2) + len(yearLiteral))
	writeMaskRunes(&b, c, n1)
	b.WriteString(sep1)
	writeMaskRunes(&b, c, n2)
	b.WriteString(sep2)
	b.WriteString(yearLiteral)
	return b.String()
}

// writeMaskRunes writes n copies of c into b.
func writeMaskRunes(b *strings.Builder, c rune, n int) {
	for i := 0; i < n; i++ {
		b.WriteRune(c)
	}
}

// monthNameRecognised reports whether s is a recognised full English
// month name. Matching is ASCII case-insensitive and zero-alloc for
// up-to-9-byte inputs (the longest month name, "September", is 9 bytes).
func monthNameRecognised(s string) bool {
	if len(s) < 3 || len(s) > 9 {
		return false
	}
	var scratch [9]byte
	for i := 0; i < len(s); i++ {
		scratch[i] = asciiToLower(s[i])
	}
	_, ok := monthNames[string(scratch[:len(s)])]
	return ok
}

// maskUsername keeps the first two runes of the input.
func maskUsername(v string, c rune) string {
	return KeepFirstN(v, 2, c)
}

// maskPassport keeps a 2-letter country prefix + last 2 chars when the
// input opens with two ASCII letters, otherwise keeps only the last 4
// chars. This reproduces both spec examples byte-for-byte:
//
//	GB1234567 → GB*****67  (alpha prefix branch)
//	123456789 → *****6789  (numeric branch)
//
// WARNING: the 2-letter country prefix is retained by design, but that
// prefix often reveals the issuing country. When country of issue is
// itself sensitive, prefer `full_redact` or register a stricter custom
// rule. The same caveat applies to `driver_license_number`.
func maskPassport(v string, c rune) string {
	if v == "" {
		return ""
	}
	// Decode the first two runes directly from the input — no []rune
	// allocation. We only need to know if both are letters.
	r0, sz0 := utf8.DecodeRuneInString(v)
	if sz0 == 0 {
		return KeepLastN(v, 4, c)
	}
	r1, sz1 := utf8.DecodeRuneInString(v[sz0:])
	if sz1 == 0 {
		return KeepLastN(v, 4, c)
	}
	if unicode.IsLetter(r0) && unicode.IsLetter(r1) {
		return KeepFirstLast(v, 2, 2, c)
	}
	return KeepLastN(v, 4, c)
}

// isLicenseSeparator reports whether r is a separator recognised by the
// driver_license_number and tax_identifier rules: ASCII hyphen, space,
// period, or ASCII forward slash.
func isLicenseSeparator(r rune) bool {
	switch r {
	case '-', ' ', '.', '/':
		return true
	}
	return false
}

// maskDriverLicense masks a driver-license-style identifier, preserving
// the documented separator set. The first 2 non-separator runes are
// kept; the last 3 (if ≥ 13 non-separator runes) or last 4 (otherwise)
// are kept; all other non-separator runes are masked. Separators are
// emitted verbatim.
//
// WARNING: the same country/issuer-prefix leakage as `passport_number`
// applies — the leading 2 characters can identify a state or issuer.
// (The documented "first 2 + last 3-or-4" semantics live on the function
// above; this implementation delegates to the shared separator-preserving
// helper.)
func maskDriverLicense(v string, c rune) string {
	nonsep := countNonSep(v, isLicenseSeparator)
	// Long-format licences (≥ 13 non-sep runes) keep the last 3 to
	// match the spec's SMITH901015JN9AA example; shorter dashed formats
	// keep the last 4.
	last := 4
	if nonsep >= 13 {
		last = 3
	}
	return keepFirstLastNonSepCounted(v, 2, last, nonsep, c, isLicenseSeparator)
}

// maskGenericNationalID is the fallback rule for national IDs that are
// not covered by a jurisdiction-specific rule. Keeps the first 2 and
// last 2 runes, masks the middle.
func maskGenericNationalID(v string, c rune) string {
	return KeepFirstLast(v, 2, 2, c)
}

// maskTaxIdentifier masks a tax identifier. Separators (`-`, ` `, `.`,
// `/`) are preserved verbatim. The last 4 non-separator runes are kept
// (or the last 3 if the input has fewer than 8 non-separator runes);
// everything else non-separator is masked.
// Empty input and inputs with too few non-separator runes are handled by
// the shared helper, which falls back to same-length mask rather than
// echoing the value.
func maskTaxIdentifier(v string, c rune) string {
	nonsep := countNonSep(v, isLicenseSeparator)
	// Short inputs (fewer than 8 non-sep runes) keep the last 3;
	// longer inputs keep the last 4.
	last := 4
	if nonsep < 8 {
		last = 3
	}
	return keepFirstLastNonSepCounted(v, 0, last, nonsep, c, isLicenseSeparator)
}

// registerIdentityRules wires every rule in this file against m. Invoked
// from init() via builtinRegistrars. Each closure reads m.maskChar() at
// apply time so later SetMaskChar / WithMaskChar calls take effect.
func registerIdentityRules(m *Masker) {
	m.mustRegisterBuiltin("email_address",
		func(v string) string { return maskEmail(v, m.maskChar()) },
		RuleInfo{
			Name: "email_address", Category: "identity", Jurisdiction: "global",
			Description: "Keeps the first character of the local part and the full domain; falls back to same-length mask on malformed input. Example: alice@example.com → a****@example.com.",
		})

	m.mustRegisterBuiltin("person_name",
		func(v string) string { return maskPersonName(v, m.maskChar()) },
		RuleInfo{
			Name: "person_name", Category: "identity", Jurisdiction: "global",
			Description: "Keeps the first character of each separator-delimited token and preserves whitespace, hyphen, and apostrophe separators. Example: John Doe → J*** D**.",
		})

	m.mustRegisterBuiltin("given_name",
		func(v string) string { return maskGivenOrFamilyName(v, m.maskChar()) },
		RuleInfo{
			Name: "given_name", Category: "identity", Jurisdiction: "global",
			Description: "Keeps the first character of the input. Example: Alice → A****.",
		})

	m.mustRegisterBuiltin("family_name",
		func(v string) string { return maskGivenOrFamilyName(v, m.maskChar()) },
		RuleInfo{
			Name: "family_name", Category: "identity", Jurisdiction: "global",
			Description: "Keeps the first character of the input. Example: Smith → S****.",
		})

	m.mustRegisterBuiltin("street_address",
		func(v string) string { return maskStreet(v, m.maskChar()) },
		RuleInfo{
			Name: "street_address", Category: "identity", Jurisdiction: "global",
			Description: "Keeps the leading house number and the recognised trailing street type; masks the street-name body; falls back to same-length mask when neither signal is present. Example: 42 Wallaby Way → 42 ******* Way.",
		})

	m.mustRegisterBuiltin("date_of_birth",
		func(v string) string { return maskDateOfBirth(v, m.maskChar()) },
		RuleInfo{
			Name: "date_of_birth", Category: "identity", Jurisdiction: "global",
			Description: "Preserves the year and masks month and day in three common formats; does not satisfy HIPAA Safe Harbor on its own. Example: 1985-03-15 → 1985-**-**.",
		})

	m.mustRegisterBuiltin("username",
		func(v string) string { return maskUsername(v, m.maskChar()) },
		RuleInfo{
			Name: "username", Category: "identity", Jurisdiction: "global",
			Description: "Keeps the first two characters of the input. Example: johndoe42 → jo*******.",
		})

	m.mustRegisterBuiltin("passport_number",
		func(v string) string { return maskPassport(v, m.maskChar()) },
		RuleInfo{
			Name: "passport_number", Category: "identity", Jurisdiction: "global",
			Description: "Keeps a two-letter country prefix and the last two characters when an alpha prefix is present; otherwise keeps the last four characters. Example: GB1234567 → GB*****67.",
		})

	m.mustRegisterBuiltin("driver_license_number",
		func(v string) string { return maskDriverLicense(v, m.maskChar()) },
		RuleInfo{
			Name: "driver_license_number", Category: "identity", Jurisdiction: "global",
			Description: "Keeps the first two and the last three-or-four non-separator characters while preserving separators. Example: DL-1234-5678 → DL-****-5678.",
		})

	m.mustRegisterBuiltin("generic_national_id",
		func(v string) string { return maskGenericNationalID(v, m.maskChar()) },
		RuleInfo{
			Name: "generic_national_id", Category: "identity", Jurisdiction: "global (fallback)",
			Description: "Keeps the first two and the last two characters; use sparingly — prefer country-specific rules. Example: AB123456CD → AB******CD.",
		})

	m.mustRegisterBuiltin("tax_identifier",
		func(v string) string { return maskTaxIdentifier(v, m.maskChar()) },
		RuleInfo{
			Name: "tax_identifier", Category: "identity", Jurisdiction: "global (fallback)",
			Description: "Keeps the last three or four non-separator characters and preserves separators. Example: 12-3456789 → **-***6789.",
		})
}

func init() {
	builtinRegistrars = append(builtinRegistrars, registerIdentityRules)
}
