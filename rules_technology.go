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
	"net/url"
	"strings"
	"unicode/utf8"
)

// Technology-category rules implement the infrastructure and
// application-security masks documented in docs/rules.md §"Technology".
// Every rule is fail-closed: malformed input routes to a
// [SameLengthMask] over the whole value rather than echoing it.
//
// Structural rules (url, url_credentials, connection_string) parse
// with net/url and NEVER emit u.String() or u.User.String() —
// net/url re-encodes percent sequences and re-orders query keys,
// which would change output bytes and could leak secrets. The
// output is rebuilt manually from validated raw fields.

// ---------- file-local constants ----------

// bearerElisionSuffix is the literal trailing marker spec'd for the
// bearer_token rule. Four mask runes (rendered by the rule) followed
// by three ASCII periods indicate elision; the three periods are NOT
// replaced by the configured mask character because they are a
// format literal, not masked payload.
const bearerElisionDots = "..."

// passwordMaskRunes is the fixed output length of the password rule
// — spec'd as "independent of source length".
const passwordMaskRunes = 8

// bearerSchemePrefix is the exact case-sensitive scheme we recognise.
// RFC 7235 says the scheme is case-insensitive, but the spec example
// shows `Bearer` — we fail closed on any other case so a `bearer`
// lowercase or `BEARER` upper variant routes to same_length_mask and
// does not produce a partially-masked token.
const bearerSchemePrefix = "Bearer "

// bearerTokenKeep is the rune count of the token prefix we retain
// before the elision marker.
const bearerTokenKeep = 6

// jwtHeaderKeep is the rune count we retain from the JWT header
// segment before the first `.`.
const jwtHeaderKeep = 4

// fixedMaskWidth is the rune count used for fixed-width mask blocks
// that do not track the original value length. Reused across the
// JWT segment mask, IPv6 hextet mask, URL fragment mask, URL query
// value mask, and connection-string secret-value mask. Each use is
// independently a policy choice; they happen to agree today, but
// the constant name is deliberately generic so changing one does
// not appear to couple them.
const fixedMaskWidth = 4

// apiKeyKeepEach is the rune count of the leading and trailing
// windows preserved on api_key values.
const apiKeyKeepEach = 4

// secretQueryKeys lists the connection_string query parameter names
// whose VALUES we redact. Keys match case-insensitively against the
// lowercase, percent-decoded form (see [isSecretKey]). Keep narrow —
// over-matching risks masking structural params consumers rely on.
//
// The list deliberately includes header-style names that are also
// commonly observed as query parameters in OAuth, SAML, and signed-URL
// flows (`bearer`, `authorization`). Header names that are NOT
// observed as query params in the wild (e.g. `cookie`) stay out.
var secretQueryKeys = map[string]struct{}{
	// Password family.
	"password": {},
	"passwd":   {},
	"pwd":      {},
	// API-key family.
	"apikey":  {},
	"api_key": {},
	// Generic token / secret.
	"token":        {},
	"secret":       {},
	"auth_token":   {},
	"access_token": {},
	// OAuth 2.0 / OIDC.
	"client_secret":      {},
	"client_credentials": {},
	"refresh_token":      {},
	"id_token":           {},
	// Cloud-provider keys observed as query params in signed-URL and
	// admin-API contexts.
	"aws_secret_access_key": {},
	"private_key":           {},
	"sas":                   {},
	"sastoken":              {},
	"signature":             {},
	"sig":                   {},
	// Azure-style key=value connection-string blobs sometimes appear
	// nested inside a parent connection string.
	"connectionstring": {},
	// Authorization-bearing values observed as query params (rarely)
	// in OAuth client-credentials and SAML redirect flows.
	"authorization": {},
	"bearer":        {},
}

// ---------- rune / byte classifiers ----------

func isASCIIDecDigit(b byte) bool { return b >= '0' && b <= '9' }

func isASCIIHexDigit(b byte) bool {
	return isASCIIDecDigit(b) ||
		(b >= 'a' && b <= 'f') ||
		(b >= 'A' && b <= 'F')
}

// isBase64URLByte reports whether b is a character from the base64url
// alphabet (RFC 4648 §5). Padding `=` is NOT accepted — JWTs use the
// unpadded form. Used as a cheap JWT-segment check.
func isBase64URLByte(b byte) bool {
	return isASCIIDecDigit(b) ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		b == '-' || b == '_'
}

// ---------- ipv4_address ----------

// maskIPv4 preserves the first 2 octets, masks the last 2 as single
// mask runes separated by literal dots. Fail-closed on anything
// other than a strict dotted quad of ASCII decimal octets ≤ 255.
func maskIPv4(v string, c rune) string {
	if v == "" {
		return ""
	}
	dots, ok := parseIPv4Dots(v)
	if !ok {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(dots[1] + 2 + 2*safeRuneLen(c))
	b.WriteString(v[:dots[1]])
	b.WriteByte('.')
	b.WriteRune(c)
	b.WriteByte('.')
	b.WriteRune(c)
	return b.String()
}

// parseIPv4Dots walks v and, if v is a strict dotted quad of ASCII
// decimal octets ≤ 255, returns the three dot positions and true.
func parseIPv4Dots(v string) ([3]int, bool) {
	var dots [3]int
	dotCount := 0
	octetStart := 0
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b == '.' {
			if dotCount == 3 || !validOctet(v[octetStart:i]) {
				return dots, false
			}
			dots[dotCount] = i
			dotCount++
			octetStart = i + 1
			continue
		}
		if !isASCIIDecDigit(b) {
			return dots, false
		}
	}
	if dotCount != 3 || !validOctet(v[octetStart:]) {
		return dots, false
	}
	return dots, true
}

// validOctet reports whether s is a 1-3 byte ASCII decimal string
// with value ≤ 255. Caller must have already verified all bytes are
// ASCII digits.
func validOctet(s string) bool {
	if s == "" || len(s) > 3 {
		return false
	}
	return octetInRange(s)
}

// octetInRange reports whether s is a 1-3 byte ASCII decimal string
// with value ≤ 255. Caller must have already verified all bytes are
// ASCII digits.
func octetInRange(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n <= 255
}

// ---------- ipv6_address ----------

// maskIPv6 preserves the first 4 hextets and masks the remaining
// hextets as one mask rune × 4 per hextet, separated by `:`. The
// compressed `::` form is preserved verbatim when the compression
// is entirely in the tail (i.e. fewer than 4 explicit left
// hextets): the implicit zeros then effectively fill the first-4
// preserved region. Inputs containing `.` (IPv4-embedded),
// `%` (zone ID), or more than one `::` fail closed.
func maskIPv6(v string, c rune) string {
	if v == "" {
		return ""
	}
	// Reject IPv4-embedded and zone IDs up-front — both are valid
	// IPv6 shapes in the wild but the rule's semantics ("preserve
	// first 4 hextets") does not extend to them cleanly, and a
	// partial match here would leak an IPv4 prefix.
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b == '.' || b == '%' {
			return SameLengthMask(v, c)
		}
	}
	// Find `::` position — there may be at most one.
	dcIdx := strings.Index(v, "::")
	if dcIdx >= 0 && strings.Contains(v[dcIdx+2:], "::") {
		return SameLengthMask(v, c)
	}
	if dcIdx < 0 {
		return maskIPv6Full(v, c)
	}
	return maskIPv6Compressed(v, dcIdx, c)
}

// maskIPv6Full handles the fully-expanded 8-hextet form. All 8
// colon positions are required; each hextet must be 1-4 ASCII hex
// chars. Output is `h1:h2:h3:h4:****:****:****:****`.
func maskIPv6Full(v string, c rune) string {
	// Count colons; require exactly 7.
	colons := 0
	var colonAt [7]int
	for i := 0; i < len(v); i++ {
		if v[i] == ':' {
			if colons == 7 {
				return SameLengthMask(v, c)
			}
			colonAt[colons] = i
			colons++
		}
	}
	if colons != 7 {
		return SameLengthMask(v, c)
	}
	// Validate each of the 8 hextets.
	prev := -1
	for i := 0; i <= 7; i++ {
		var start, end int
		if i == 0 {
			start = 0
		} else {
			start = prev + 1
		}
		if i == 7 {
			end = len(v)
		} else {
			end = colonAt[i]
			prev = end
		}
		if !isHexHextet(v[start:end]) {
			return SameLengthMask(v, c)
		}
	}
	// Preserve hextets 0..3 verbatim, mask 4..7.
	preserveEnd := colonAt[3] // byte index of the 4th colon
	var b strings.Builder
	b.Grow(preserveEnd + 4*(1+fixedMaskWidth*safeRuneLen(c)))
	b.WriteString(v[:preserveEnd])
	for i := 0; i < 4; i++ {
		b.WriteByte(':')
		writeMaskRunes(&b, c, 4)
	}
	return b.String()
}

// maskIPv6Compressed handles the `::`-compressed form. The `::` is
// preserved verbatim at its original position; the left side (≤ 4
// hextets, verbatim) is emitted as-is and the right side (each
// hextet → 4 mask runes) is masked. The right side must be
// non-empty — a `1::` / `::` input with no right hextets has no
// mask work to do and so fails closed to avoid echoing the input.
//
// Head-compression edge case: when the left side is empty and the
// right side would occupy positions that include the preserved
// first-4 band (`::a:b:c:d:e` expands to 0:0:0:a:b:c:d:e — hextet 4
// is the explicit `a`), we fail closed rather than mask a hextet
// that the rule's spec semantics say should be preserved.
func maskIPv6Compressed(v string, dcIdx int, c rune) string {
	left := v[:dcIdx]
	right := v[dcIdx+2:]
	leftCount, leftOK := countHextets(left, 4)
	if !leftOK || right == "" {
		return SameLengthMask(v, c)
	}
	rightCount, rightOK := countHextets(right, 7)
	if !rightOK || leftCount+rightCount > 7 {
		return SameLengthMask(v, c)
	}
	// Head-compression: when left is empty and right would reach into
	// the first-4 preserve band, we cannot honour the spec contract.
	if leftCount == 0 && rightCount > 4 {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(dcIdx + 2 + rightCount*(1+fixedMaskWidth*safeRuneLen(c)))
	b.WriteString(v[:dcIdx])
	b.WriteString("::")
	for i := 0; i < rightCount; i++ {
		if i > 0 {
			b.WriteByte(':')
		}
		writeMaskRunes(&b, c, 4)
	}
	return b.String()
}

// countHextets walks s (possibly empty) and returns the hextet count
// plus ok=true when s is `[hex{1,4}](:hex{1,4})*` with no trailing or
// internal empty hextet and the count is ≤ max. Empty s returns (0, true)
// — valid zero-hextet side of a `::`.
func countHextets(s string, max int) (int, bool) {
	if s == "" {
		return 0, true
	}
	count := 0
	for {
		colon := strings.IndexByte(s, ':')
		var hex string
		if colon < 0 {
			hex = s
		} else {
			hex = s[:colon]
		}
		if !isHexHextet(hex) {
			return 0, false
		}
		count++
		if count > max {
			return 0, false
		}
		if colon < 0 {
			return count, true
		}
		s = s[colon+1:]
		if s == "" {
			return 0, false
		}
	}
}

// isHexHextet reports whether s is a 1-4 byte ASCII hexadecimal
// string.
func isHexHextet(s string) bool {
	n := len(s)
	if n == 0 || n > 4 {
		return false
	}
	for i := 0; i < n; i++ {
		if !isASCIIHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// ---------- mac_address ----------

// maskMAC preserves the first 3 octets (OUI) and masks the device
// portion. Accepts `:` or `-` as separator but NOT both mixed. The
// Cisco dotted form (`AABB.CCDD.EEFF`) is rejected per spec. Case
// is preserved verbatim on the kept octets.
func maskMAC(v string, c rune) string {
	if v == "" {
		return ""
	}
	sep, ok := validateMACShape(v)
	if !ok {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(8 + 3*(1+2*safeRuneLen(c)))
	b.WriteString(v[:8])
	for i := 0; i < 3; i++ {
		b.WriteByte(sep)
		b.WriteRune(c)
		b.WriteRune(c)
	}
	return b.String()
}

// validateMACShape reports whether v is a canonical MAC address
// `HH{sep}HH{sep}HH{sep}HH{sep}HH{sep}HH` where sep is `:` or `-`
// (uniform across all five). Returns the separator byte plus ok.
func validateMACShape(v string) (byte, bool) {
	if len(v) != 17 {
		return 0, false
	}
	sep := v[2]
	if sep != ':' && sep != '-' {
		return 0, false
	}
	for i := 0; i < 6; i++ {
		base := i * 3
		if i > 0 && v[base-1] != sep {
			return 0, false
		}
		if !isASCIIHexDigit(v[base]) || !isASCIIHexDigit(v[base+1]) {
			return 0, false
		}
	}
	return sep, true
}

// ---------- hostname ----------

// maskHostname preserves the first label and same-length-masks the
// remaining labels, preserving the `.` separators. Single-label
// inputs (no dot), leading/trailing/double dots all fail closed to
// same_length_mask over the whole input — the spec's literal echo
// of `db-master` is a spec error we've decided to reject in favour
// of the library-wide fail-closed contract.
//
// Note on label mask width: the spec example for
// `web-01.prod.example.com` is internally inconsistent — it shows
// 1 mask rune each for `prod` (4 chars) and `example` (7 chars),
// then 3 mask runes for `com` (3 chars). No single rule fits all
// three. We treat the `com → ***` case (same-length) as the
// authoritative signal and mask each remaining label at its
// original rune count. The resulting output does preserve label
// lengths, which is a minor information disclosure; consumers
// concerned about that should register a custom rule that replaces
// each label with a fixed-width marker.
func maskHostname(v string, c rune) string {
	if v == "" {
		return ""
	}
	firstDot := strings.IndexByte(v, '.')
	if firstDot <= 0 { // no dot, or leading dot
		return SameLengthMask(v, c)
	}
	// First label must be a valid DNS-style letter/digit/hyphen/
	// underscore label — spaces, tabs, control bytes, non-ASCII
	// would otherwise pass through to the output unmasked.
	if !isLDHLabel(v[:firstDot]) {
		return SameLengthMask(v, c)
	}
	// Walk remaining labels; any empty label (double-dot, trailing
	// dot) routes to same_length_mask.
	rest := v[firstDot+1:]
	// Any empty label (leading, trailing, or double dots) is malformed.
	if rest == "" || rest[0] == '.' || rest[len(rest)-1] == '.' || strings.Contains(rest, "..") {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(len(v))
	b.WriteString(v[:firstDot])
	// Emit '.' then each subsequent label masked by rune-length.
	b.WriteByte('.')
	labelStart := 0
	for i := 0; i < len(rest); i++ {
		if rest[i] == '.' {
			writeSameLengthMask(&b, rest[labelStart:i], c)
			b.WriteByte('.')
			labelStart = i + 1
		}
	}
	writeSameLengthMask(&b, rest[labelStart:], c)
	return b.String()
}

// writeSameLengthMask writes rune-count-of-s copies of c into b.
func writeSameLengthMask(b *strings.Builder, s string, c rune) {
	writeMaskRunes(b, c, utf8.RuneCountInString(s))
}

// isLDHLabel reports whether s is a non-empty DNS-style letter-digit-
// hyphen label plus underscore (LDH + `_`, which internal service
// names commonly use). We do NOT enforce the RFC 1035 63-byte limit
// or the no-leading/trailing-hyphen rule — the aim is to reject
// obviously-non-hostname inputs (spaces, control bytes, non-ASCII),
// not to validate DNS-resolvability.
func isLDHLabel(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isLDHByte(s[i]) {
			return false
		}
	}
	return true
}

// isLDHByte reports whether c is an ASCII letter, digit, hyphen, or
// underscore — the relaxed-LDH character class for hostname labels.
func isLDHByte(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}

// ---------- url ----------

// maskURL parses v with net/url, validates that the parse produced a
// well-formed authority-bearing URL, and emits the scheme and host
// verbatim alongside a masked path, masked query values, masked
// fragment, and (belt-and-braces) a redacted userinfo if one was
// present. If the URL carries no sensitive subcomponents — no
// userinfo, no path beyond `/`, no query, no fragment — it routes
// to same_length_mask to honour the fail-closed contract.
func maskURL(v string, c rune) string {
	if v == "" {
		return ""
	}
	u, ok := parseAuthorityURL(v)
	if !ok {
		return SameLengthMask(v, c)
	}
	path := urlEscapedPath(u)
	if !urlHasSensitive(u, path) {
		return SameLengthMask(v, c)
	}
	// RawQuery is the caller's raw bytes; net/url preserves non-ASCII
	// runes there verbatim. Writing invalid UTF-8 into the output
	// would break the library-wide "output is always valid UTF-8"
	// contract. Fail closed rather than emit a malformed string.
	if !utf8.ValidString(u.RawQuery) {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(len(v))
	writeURLMasked(&b, u, path, c)
	return b.String()
}

// urlHasSensitive reports whether the URL carries any of the
// subcomponents the `url` rule must mask. An input with no such
// component is effectively already safe; we fail closed rather
// than echoing it.
func urlHasSensitive(u *url.URL, path string) bool {
	if u.User != nil {
		return true
	}
	if path != "" && path != "/" {
		return true
	}
	return u.RawQuery != "" || u.Fragment != ""
}

// writeURLMasked emits the masked URL body (everything after the
// `scheme://`) into b. Assumes urlHasSensitive(u, path) is true.
func writeURLMasked(b *strings.Builder, u *url.URL, path string, c rune) {
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		writeUserinfoRedact(b, u.User, c)
	}
	b.WriteString(u.Host)
	if path != "" {
		writeMaskedURLPath(b, path, c)
	}
	if u.RawQuery != "" {
		b.WriteByte('?')
		writeMaskedURLQuery(b, u.RawQuery, c)
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		writeMaskRunes(b, c, fixedMaskWidth)
	}
}

// parseAuthorityURL parses v and returns (parsed, true) only when the
// result is a well-formed authority-bearing URL: non-empty scheme,
// non-empty validated host, and no opaque part. Shared by the three
// URL-based rules to keep validation centralised.
func parseAuthorityURL(v string) (*url.URL, bool) {
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return nil, false
	}
	if !isCleanAuthority(u.Host) {
		return nil, false
	}
	return u, true
}

// urlEscapedPath returns the path in its original percent-encoded
// form. u.EscapedPath() returns RawPath when it was set and is a
// valid encoding of Path; otherwise it re-encodes Path. Emitting a
// decoded u.Path directly would leak literal bytes (spaces, `/`, `%`)
// into the output and could change the number of path segments.
func urlEscapedPath(u *url.URL) string {
	return u.EscapedPath()
}

// isCleanAuthority validates u.Host does not contain stray authority
// delimiters that net/url may admit on pathological input. IPv6
// literals are allowed if bracketed exactly once.
func isCleanAuthority(h string) bool {
	if h == "" || hostHasStrayByte(h) {
		return false
	}
	if strings.ContainsAny(h, "[]") {
		return isBracketedIPv6Host(h)
	}
	return true
}

// hostHasStrayByte reports whether h contains bytes that should never
// appear in a clean authority (they signal that net/url has accepted
// a malformed URL whose host field is actually something else).
// Rejects any non-ASCII byte (emitting 0x80+ bytes would produce
// invalid UTF-8 in the output) and any ASCII control byte below 0x20
// or the delete byte 0x7F. Consumers that need IDN support should
// pre-punycode the host before calling.
func hostHasStrayByte(h string) bool {
	for i := 0; i < len(h); i++ {
		b := h[i]
		if b >= 0x80 || b < 0x20 || b == 0x7F {
			return true
		}
		switch b {
		case '@', '/', '?', '#', '%', ' ':
			return true
		}
	}
	return false
}

// isBracketedIPv6Host reports whether h is an `[ipv6]` literal with
// an optional trailing `:port` — exactly one `[` at the start, one
// `]`, and no other brackets.
func isBracketedIPv6Host(h string) bool {
	if !strings.HasPrefix(h, "[") {
		return false
	}
	closeIdx := strings.IndexByte(h, ']')
	if closeIdx < 0 {
		return false
	}
	if strings.Count(h, "[") != 1 || strings.Count(h, "]") != 1 {
		return false
	}
	rest := h[closeIdx+1:]
	return rest == "" || rest[0] == ':'
}

// writeUserinfoRedact emits `****:****@` when a password is present
// in the userinfo, `****@` when only a user is. Never emits the
// original userinfo bytes.
func writeUserinfoRedact(b *strings.Builder, u *url.Userinfo, c rune) {
	_, hasPass := u.Password()
	writeMaskRunes(b, c, 4)
	if hasPass {
		b.WriteByte(':')
		writeMaskRunes(b, c, 4)
	}
	b.WriteByte('@')
}

// writeMaskedURLPath same-length-masks each non-empty path segment,
// preserving `/` separators and empty segments (so `//a` stays `//*`).
func writeMaskedURLPath(b *strings.Builder, path string, c rune) {
	segStart := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if i > segStart {
				writeSameLengthMask(b, path[segStart:i], c)
			}
			b.WriteByte('/')
			segStart = i + 1
		}
	}
	if segStart < len(path) {
		writeSameLengthMask(b, path[segStart:], c)
	}
}

// writeMaskedURLQuery walks raw (u.RawQuery — bytes as transmitted),
// preserving key bytes and `&` / `=` structurally; each value
// becomes a fixed 4-rune mask. Pairs without a `=` (bare flags) and
// pairs with an empty key are same-length-masked so the rule cannot
// echo a secret that was written in the ambiguous half.
func writeMaskedURLQuery(b *strings.Builder, raw string, c rune) {
	pairStart := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '&' {
			writeMaskedQueryPair(b, raw[pairStart:i], c)
			if i < len(raw) {
				b.WriteByte('&')
			}
			pairStart = i + 1
		}
	}
}

// writeMaskedQueryPair emits `key=****` for `key=value` pairs and
// same-length-masks any bare flag (no `=`) or empty-key pair. Bare
// flags in particular are treated as potentially-sensitive because
// there is no structural separator signalling which half (name or
// value) the operator put the data in.
func writeMaskedQueryPair(b *strings.Builder, pair string, c rune) {
	eq := strings.IndexByte(pair, '=')
	if eq <= 0 {
		writeSameLengthMask(b, pair, c)
		return
	}
	b.WriteString(pair[:eq+1])
	writeMaskRunes(b, c, fixedMaskWidth)
}

// ---------- url_credentials ----------

// maskURLCredentials preserves scheme, host, port, path, query, and
// fragment verbatim and redacts userinfo only. Fails closed when no
// userinfo is present — echoing the input would violate the
// library-wide "never return original" contract.
func maskURLCredentials(v string, c rune) string {
	if v == "" {
		return ""
	}
	u, ok := parseAuthorityURL(v)
	if !ok || u.User == nil {
		return SameLengthMask(v, c)
	}
	// net/url admits non-ASCII bytes in RawQuery and percent-decodes
	// Fragment to the raw bytes, so an input like `...#%FF` yields an
	// invalid-UTF-8 Fragment. Emit the escaped form and validate the
	// RawQuery bytes to keep output always-valid-UTF-8.
	if !utf8.ValidString(u.RawQuery) {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(len(v))
	b.WriteString(u.Scheme)
	b.WriteString("://")
	writeUserinfoRedact(&b, u.User, c)
	b.WriteString(u.Host)
	b.WriteString(urlEscapedPath(u))
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		b.WriteString(u.EscapedFragment())
	}
	return b.String()
}

// ---------- api_key ----------

// maskAPIKey preserves the first 4 and last 4 runes and same-length-
// masks the middle. Input rune count < 9 falls back to
// same_length_mask. Length is measured in runes (UTF-8 aware) to
// avoid byte-length shortcuts masking multi-byte prefixes
// incorrectly.
func maskAPIKey(v string, c rune) string {
	if v == "" {
		return ""
	}
	if utf8.RuneCountInString(v) < apiKeyKeepEach*2+1 {
		return SameLengthMask(v, c)
	}
	return KeepFirstLast(v, apiKeyKeepEach, apiKeyKeepEach, c)
}

// ---------- jwt_token ----------

// maskJWT validates v is a 3-segment dot-separated base64url string
// with a header ≥ 4 chars, payload ≥ 1 char, signature ≥ 1 char
// (unsecured JWTs with empty signature are NOT accepted — the
// spec's illustrative shape is a signed token). Output is
// `<first4>****.****.****.` — the trailing dot is part of the
// spec output and intentional.
func maskJWT(v string, c rune) string {
	if v == "" {
		return ""
	}
	d1 := strings.IndexByte(v, '.')
	if d1 < jwtHeaderKeep {
		return SameLengthMask(v, c)
	}
	rest := v[d1+1:]
	d2 := strings.IndexByte(rest, '.')
	if d2 <= 0 {
		return SameLengthMask(v, c)
	}
	sig := rest[d2+1:]
	if sig == "" || strings.IndexByte(sig, '.') >= 0 {
		return SameLengthMask(v, c)
	}
	header := v[:d1]
	payload := rest[:d2]
	if !isBase64URLSeg(header) || !isBase64URLSeg(payload) || !isBase64URLSeg(sig) {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	// first4 of header + 4*mask + "." + 4*mask + "." + 4*mask + "."
	b.Grow(jwtHeaderKeep + 3*fixedMaskWidth*safeRuneLen(c) + 3)
	b.WriteString(header[:jwtHeaderKeep])
	writeMaskRunes(&b, c, fixedMaskWidth)
	b.WriteByte('.')
	writeMaskRunes(&b, c, fixedMaskWidth)
	b.WriteByte('.')
	writeMaskRunes(&b, c, fixedMaskWidth)
	b.WriteByte('.')
	return b.String()
}

// isBase64URLSeg reports whether s is a non-empty string of
// base64url bytes (no padding).
func isBase64URLSeg(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// ---------- bearer_token ----------

// maskBearerToken preserves the literal `Bearer ` scheme and the
// first 6 runes of the token, appending `****...` (four mask runes
// + three ASCII periods) as the elision marker. Case-sensitive
// scheme match — `bearer` and `BEARER` variants fail closed to
// avoid partial masking of a possibly-malformed header.
func maskBearerToken(v string, c rune) string {
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, bearerSchemePrefix) {
		return SameLengthMask(v, c)
	}
	token := v[len(bearerSchemePrefix):]
	tokenRunes := utf8.RuneCountInString(token)
	// `<` would admit a token of exactly 6 runes to pass through
	// unmasked (nothing left after the preserved prefix). Use `<=` so
	// a 6-rune token fails closed rather than echoing the whole secret.
	if tokenRunes <= bearerTokenKeep {
		return SameLengthMask(v, c)
	}
	// Byte offset at rune 6.
	cutByte := byteOffsetAtRune(token, bearerTokenKeep)
	var b strings.Builder
	b.Grow(len(bearerSchemePrefix) + cutByte + fixedMaskWidth*safeRuneLen(c) + len(bearerElisionDots))
	b.WriteString(bearerSchemePrefix)
	b.WriteString(token[:cutByte])
	writeMaskRunes(&b, c, fixedMaskWidth)
	b.WriteString(bearerElisionDots)
	return b.String()
}

// ---------- password ----------

// maskPassword returns 8 copies of the mask character for non-empty
// input. Empty in, empty out — preserves the library-wide
// empty-invariance convention; the "independent of source length"
// spec language is about masking length, not about manufacturing
// output from nothing.
func maskPassword(v string, c rune) string {
	if v == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(passwordMaskRunes * safeRuneLen(c))
	writeMaskRunes(&b, c, passwordMaskRunes)
	return b.String()
}

// ---------- connection_string ----------

// maskConnectionString parses a URL-shaped DSN and emits
// scheme+host+port+path verbatim, redacts userinfo, and
// same-length-masks secret query-parameter VALUES (keys in
// [secretQueryKeys], matched case-insensitively). Non-secret query
// params are preserved. Fragment is preserved.
func maskConnectionString(v string, c rune) string {
	if v == "" {
		return ""
	}
	u, ok := parseAuthorityURL(v)
	if !ok || (u.User == nil && !queryHasSecret(u.RawQuery)) {
		return SameLengthMask(v, c)
	}
	// RawQuery may contain raw non-UTF-8 bytes per net/url's lax
	// tokeniser. Fragment is masked to a fixed block so it's safe,
	// but the query is written through writeConnStringQuery which
	// passes pair bytes through. Fail closed on invalid UTF-8.
	if !utf8.ValidString(u.RawQuery) {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(len(v))
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		writeUserinfoRedact(&b, u.User, c)
	}
	b.WriteString(u.Host)
	b.WriteString(urlEscapedPath(u))
	if u.RawQuery != "" {
		b.WriteByte('?')
		writeConnStringQuery(&b, u.RawQuery, c)
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		writeMaskRunes(&b, c, fixedMaskWidth)
	}
	return b.String()
}

// queryHasSecret scans raw for any secret-key pair. Matches the key
// case-insensitively against [secretQueryKeys] AFTER percent-decoding
// the raw-byte key — without the decode, an attacker-crafted key like
// `password%3Dfoo` would bypass the lookup and the caller would echo
// the associated value verbatim.
func queryHasSecret(raw string) bool {
	if raw == "" {
		return false
	}
	pairStart := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '&' {
			pair := raw[pairStart:i]
			if eq := strings.IndexByte(pair, '='); eq > 0 {
				if isSecretKey(pair[:eq]) {
					return true
				}
			}
			pairStart = i + 1
		}
	}
	return false
}

// isSecretKey reports whether rawKey names one of the configured
// secret-query-parameter keys. Percent-decodes rawKey first so that
// encoded variants (for example `password%3Dfoo`) do not slip past
// the lookup. On decode failure the raw lowercased bytes are used —
// a malformed percent sequence is unusual in a key position and we
// prefer to fail closed toward matching.
func isSecretKey(rawKey string) bool {
	decoded, err := url.QueryUnescape(rawKey)
	if err != nil {
		decoded = rawKey
	}
	_, ok := secretQueryKeys[asciiLower(decoded)]
	return ok
}

// writeConnStringQuery walks raw and emits each pair with `key=****`
// for secret keys (matched case-insensitively) and the verbatim
// pair otherwise. Structure bytes `&`, `=` preserved.
func writeConnStringQuery(b *strings.Builder, raw string, c rune) {
	pairStart := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '&' {
			writeConnStringPair(b, raw[pairStart:i], c)
			if i < len(raw) {
				b.WriteByte('&')
			}
			pairStart = i + 1
		}
	}
}

func writeConnStringPair(b *strings.Builder, pair string, c rune) {
	eq := strings.IndexByte(pair, '=')
	// Bare flags (no `=`) and empty-key pairs (`=value`) carry no
	// key/value structure the rule can trust; mask them length-
	// preservingly rather than echoing bytes whose role is
	// ambiguous.
	if eq <= 0 {
		writeSameLengthMask(b, pair, c)
		return
	}
	key := pair[:eq]
	if isSecretKey(key) {
		b.WriteString(key)
		b.WriteByte('=')
		writeMaskRunes(b, c, fixedMaskWidth)
		return
	}
	b.WriteString(pair)
}

// asciiLower returns an ASCII-lowercased copy of s, allocating
// only when at least one byte in [A-Z] is present. Keeps the
// connection-string query walker zero-alloc on the common all-
// lowercase case while still correctly handling mixed-case keys.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			buf := []byte(s)
			for j := i; j < len(buf); j++ {
				if buf[j] >= 'A' && buf[j] <= 'Z' {
					buf[j] += 'a' - 'A'
				}
			}
			return string(buf)
		}
	}
	return s
}

// ---------- database_dsn ----------

// maskDatabaseDSN parses the Go MySQL DSN form
// `user:password@protocol(addr)/db?params` and redacts userinfo.
// The parser looks for an `@` immediately followed by a lowercase
// scheme identifier and `(` — this rules out unencoded `@`
// characters inside the password. Any ambiguity (no such `@`, or
// multiple candidates) fails closed.
func maskDatabaseDSN(v string, c rune) string {
	if v == "" {
		return ""
	}
	candidate, ok := findDSNProtocolAt(v)
	if !ok {
		return SameLengthMask(v, c)
	}
	userinfo := v[:candidate]
	rest := v[candidate+1:]
	if userinfo == "" || rest == "" || !utf8.ValidString(rest) {
		return SameLengthMask(v, c)
	}
	var b strings.Builder
	b.Grow(len(v))
	writeMaskRunes(&b, c, 4)
	if strings.IndexByte(userinfo, ':') >= 0 {
		b.WriteByte(':')
		writeMaskRunes(&b, c, 4)
	}
	b.WriteByte('@')
	b.WriteString(rest)
	return b.String()
}

// findDSNProtocolAt locates the single `@` whose following bytes
// match `[a-z]+\(`. Returns the `@` byte offset plus ok=true only
// when exactly one such `@` is present.
func findDSNProtocolAt(v string) (int, bool) {
	candidate := -1
	for i := 0; i < len(v); i++ {
		if v[i] != '@' || !looksLikeDSNProtocol(v[i+1:]) {
			continue
		}
		if candidate >= 0 {
			return 0, false
		}
		candidate = i
	}
	return candidate, candidate >= 0
}

// looksLikeDSNProtocol reports whether s starts with a well-formed
// `[a-z]+\([^)]*\)` protocol-and-address block, optionally followed
// by a `/` (path separator) or end-of-string. This prevents
// unterminated inputs like `u:p@tcp(abc` from being treated as a
// valid DSN shape and emitted as pseudo-masked output.
func looksLikeDSNProtocol(s string) bool {
	i := 0
	for i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
		i++
	}
	if i == 0 || i >= len(s) || s[i] != '(' {
		return false
	}
	closeIdx := strings.IndexByte(s[i+1:], ')')
	if closeIdx < 0 {
		return false
	}
	after := i + 1 + closeIdx + 1
	return after == len(s) || s[after] == '/'
}

// ---------- uuid ----------

// maskUUID preserves the first 8 hex runes and last 4 hex runes of
// a canonical 8-4-4-4-12 UUID. Hyphens must be at exactly bytes 8,
// 13, 18, 23; all other positions must be ASCII hex. Non-canonical
// forms (hyphenless, braced, URN-prefixed) fail closed.
//
// Hyphen positions are fixed by the format, so emission skips the
// generic [keepFirstLastNonSepCounted] walker in favour of direct
// byte-slice writes — roughly 2x faster for this shape.
func maskUUID(v string, c rune) string {
	if v == "" {
		return ""
	}
	if len(v) != 36 {
		return SameLengthMask(v, c)
	}
	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			if v[i] != '-' {
				return SameLengthMask(v, c)
			}
		default:
			if !isASCIIHexDigit(v[i]) {
				return SameLengthMask(v, c)
			}
		}
	}
	cl := safeRuneLen(c)
	var b strings.Builder
	b.Grow(8 + 4 + 20*cl + 4) // v[:8] + 4 hyphens + 20 masked runes + v[32:]
	b.WriteString(v[:8])
	b.WriteByte('-')
	writeMaskRunes(&b, c, 4)
	b.WriteByte('-')
	writeMaskRunes(&b, c, 4)
	b.WriteByte('-')
	writeMaskRunes(&b, c, 4)
	b.WriteByte('-')
	writeMaskRunes(&b, c, 8)
	b.WriteString(v[32:])
	return b.String()
}

// ---------- registration ----------

// registerTechnologyRules wires every rule in this file against m.
func registerTechnologyRules(m *Masker) {
	m.mustRegisterBuiltin("ipv4_address",
		func(v string) string { return maskIPv4(v, m.maskChar()) },
		RuleInfo{
			Name: "ipv4_address", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the first 2 octets and masks the last 2 as single mask runes; fails closed on malformed input. Example: 192.168.1.42 → 192.168.*.*.",
		})
	m.mustRegisterBuiltin("ipv6_address",
		func(v string) string { return maskIPv6(v, m.maskChar()) },
		RuleInfo{
			Name: "ipv6_address", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the first 4 hextets and masks the interface identifier; compressed form is preserved when `::` is in the tail. Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 → 2001:0db8:85a3:0000:****:****:****:****.",
		})
	m.mustRegisterBuiltin("mac_address",
		func(v string) string { return maskMAC(v, m.maskChar()) },
		RuleInfo{
			Name: "mac_address", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the OUI (first 3 octets) and masks the device identifier; accepts `:` and `-` separators. Example: AA:BB:CC:DD:EE:FF → AA:BB:CC:**:**:**.",
		})
	m.mustRegisterBuiltin("hostname",
		func(v string) string { return maskHostname(v, m.maskChar()) },
		RuleInfo{
			Name: "hostname", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the first label and same-length-masks the remaining labels; single-label inputs fail closed. Example: web-01.prod.example.com → web-01.****.*******.***.",
		})
	m.mustRegisterBuiltin("url",
		func(v string) string { return maskURL(v, m.maskChar()) },
		RuleInfo{
			Name: "url", Category: "technology", Jurisdiction: "global",
			Description: "Preserves scheme, host, and port; same-length-masks path segments; masks query values and fragment with fixed 4-rune blocks; redacts userinfo defensively. Example: https://example.com/users/42?token=abc → https://example.com/*****/**?token=****.",
		})
	m.mustRegisterBuiltin("url_credentials",
		func(v string) string { return maskURLCredentials(v, m.maskChar()) },
		RuleInfo{
			Name: "url_credentials", Category: "technology", Jurisdiction: "global",
			Description: "Preserves scheme, host, path, query and fragment; redacts userinfo only. Example: https://admin:s3cret@db.example.com/mydb → https://****:****@db.example.com/mydb.",
		})
	m.mustRegisterBuiltin("api_key",
		func(v string) string { return maskAPIKey(v, m.maskChar()) },
		RuleInfo{
			Name: "api_key", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the first 4 and last 4 runes and same-length-masks the middle; input shorter than 9 runes fails closed. Example: AKIAIOSFODNN7EXAMPLE → AKIA************MPLE.",
		})
	m.mustRegisterBuiltin("jwt_token",
		func(v string) string { return maskJWT(v, m.maskChar()) },
		RuleInfo{
			Name: "jwt_token", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the first 4 runes of the header segment and masks all three segments with fixed 4-rune blocks separated by literal dots; the output ends with a trailing dot. Example: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc → eyJh****.****.****.",
		})
	m.mustRegisterBuiltin("bearer_token",
		func(v string) string { return maskBearerToken(v, m.maskChar()) },
		RuleInfo{
			Name: "bearer_token", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the `Bearer ` scheme and the first 6 runes of the token, appending `****...` as the elision marker (four mask runes then three literal dots). Example: Bearer abc123def456 → Bearer abc123****...",
		})
	m.mustRegisterBuiltin("password",
		func(v string) string { return maskPassword(v, m.maskChar()) },
		RuleInfo{
			Name: "password", Category: "technology", Jurisdiction: "global",
			Description: "Emits a fixed 8-rune mask regardless of source length so password length is not leaked; empty input returns empty. Example: MyP@ssw0rd! → ********.",
		})
	m.mustRegisterBuiltin("private_key_pem",
		FullRedact,
		RuleInfo{
			Name: "private_key_pem", Category: "technology", Jurisdiction: "global",
			Description: "Full redact. Private key material must never be partially revealed. Example: -----BEGIN RSA PRIVATE KEY-----... → [REDACTED].",
		})
	m.mustRegisterBuiltin("connection_string",
		func(v string) string { return maskConnectionString(v, m.maskChar()) },
		RuleInfo{
			Name: "connection_string", Category: "technology", Jurisdiction: "global",
			Description: "Preserves scheme, host, port, path and non-secret query parameters; redacts userinfo and the values of known secret query parameters (password family, OAuth client/refresh/id-token family, AWS secret access key, Azure connection-string and SAS, signature/sig). Example: postgresql://admin:s3cret@db.example.com:5432/myapp → postgresql://****:****@db.example.com:5432/myapp.",
		})
	m.mustRegisterBuiltin("database_dsn",
		func(v string) string { return maskDatabaseDSN(v, m.maskChar()) },
		RuleInfo{
			Name: "database_dsn", Category: "technology", Jurisdiction: "global",
			Description: "Parses the Go MySQL DSN form `user:password@protocol(addr)/db` and redacts userinfo; preserves protocol, address, database and params. Example: user:password@tcp(localhost:3306)/dbname → ****:****@tcp(localhost:3306)/dbname.",
		})
	m.mustRegisterBuiltin("uuid",
		func(v string) string { return maskUUID(v, m.maskChar()) },
		RuleInfo{
			Name: "uuid", Category: "technology", Jurisdiction: "global",
			Description: "Preserves the first 8 and last 4 hex runes of a canonical 8-4-4-4-12 UUID; non-canonical forms fail closed. Example: 550e8400-e29b-41d4-a716-446655440000 → 550e8400-****-****-****-********0000.",
		})
}

func init() {
	builtinRegistrars = append(builtinRegistrars, registerTechnologyRules)
}
