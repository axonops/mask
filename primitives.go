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
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// safeRuneLen returns the UTF-8 byte width of c. For any invalid rune
// (negative value, lone surrogate, value above unicode.MaxRune) it returns
// the maximum valid rune width so downstream Builder.Grow calls never
// receive a negative argument. This keeps the library's "no panic on any
// input" contract intact even when a caller passes an obviously bad mask
// rune via WithMaskChar or SetMaskChar.
//
// The helper exists only to keep capacity calculations non-negative — it
// does not attempt to emit a valid rune. The subsequent Builder.WriteRune
// call uses strings.Builder's own fallback (utf8.RuneError) for invalid
// runes, so the output stays well-formed UTF-8.
func safeRuneLen(c rune) int {
	n := utf8.RuneLen(c)
	if n < 0 {
		return utf8.UTFMax
	}
	return n
}

// FullRedact replaces the value with the constant [FullRedactMarker], losing
// both length and contents. Use when the existence of a value is itself the
// only information that should survive.
//
// Example: FullRedact("anything") → "[REDACTED]".
func FullRedact(_ string) string {
	return FullRedactMarker
}

// Nullify replaces any value with the empty string. Prefer [FullRedact] when a
// downstream consumer must distinguish "field was present and redacted" from
// "field was absent".
//
// Example: Nullify("anything") → "".
func Nullify(_ string) string {
	return ""
}

// FixedReplacementFunc builds a [RuleFunc] that always returns replacement
// regardless of input. The replacement is captured at construction, so
// changes to the global or per-instance mask character do NOT affect it.
//
// Example:
//
//	r := mask.FixedReplacementFunc("N/A")
//	r("secret") // "N/A"
//	r("")      // "N/A"
func FixedReplacementFunc(replacement string) RuleFunc {
	return func(_ string) string {
		return replacement
	}
}

// SameLengthMask replaces every rune of v with the mask rune c while
// preserving the rune count of the input. Unicode aware — input `"Hello"`
// with c='*' yields `"*****"` regardless of the byte width of the mask rune.
//
// Example: SameLengthMask("Hello", '*') → "*****".
func SameLengthMask(v string, c rune) string {
	if v == "" {
		return ""
	}
	runeCount := utf8.RuneCountInString(v)
	var b strings.Builder
	b.Grow(runeCount * safeRuneLen(c))
	for i := 0; i < runeCount; i++ {
		b.WriteRune(c)
	}
	return b.String()
}

// KeepFirstN preserves the first n runes of v and replaces the remainder with
// the mask rune c. Negative n is treated as 0. n greater than or equal to the
// rune count of v returns v unchanged.
//
// Example: KeepFirstN("Sensitive", 4, '*') → "Sens*****".
func KeepFirstN(v string, n int, c rune) string {
	if v == "" {
		return ""
	}
	if n < 0 {
		n = 0
	}
	runeCount := utf8.RuneCountInString(v)
	if n >= runeCount {
		return v
	}
	cutByte := byteOffsetAtRune(v, n)
	tailRunes := runeCount - n
	var b strings.Builder
	b.Grow(cutByte + tailRunes*safeRuneLen(c))
	b.WriteString(v[:cutByte])
	for i := 0; i < tailRunes; i++ {
		b.WriteRune(c)
	}
	return b.String()
}

// KeepLastN preserves the last n runes of v and replaces the preceding runes
// with the mask rune c. Negative n is treated as 0. n greater than or equal to
// the rune count of v returns v unchanged.
//
// Example: KeepLastN("Sensitive", 4, '*') → "*****tive".
func KeepLastN(v string, n int, c rune) string {
	if v == "" {
		return ""
	}
	if n < 0 {
		n = 0
	}
	runeCount := utf8.RuneCountInString(v)
	if n >= runeCount {
		return v
	}
	tailByte := byteOffsetAtRune(v, runeCount-n)
	headRunes := runeCount - n
	var b strings.Builder
	b.Grow(headRunes*safeRuneLen(c) + (len(v) - tailByte))
	for i := 0; i < headRunes; i++ {
		b.WriteRune(c)
	}
	b.WriteString(v[tailByte:])
	return b.String()
}

// KeepFirstLast preserves the first and last runes of v and masks the middle
// with c. Negative values are clamped to 0. If first+last is greater than or
// equal to the rune count of v, v is returned unchanged — this is the safe
// degradation required by the spec and avoids ever producing output longer
// than the input.
//
// Example: KeepFirstLast("SensitiveData", 4, 4, '*') → "Sens*****Data".
func KeepFirstLast(v string, first, last int, c rune) string {
	if v == "" {
		return ""
	}
	if first < 0 {
		first = 0
	}
	if last < 0 {
		last = 0
	}
	runeCount := utf8.RuneCountInString(v)
	if first+last >= runeCount {
		return v
	}
	headByte := byteOffsetAtRune(v, first)
	tailByte := byteOffsetAtRune(v, runeCount-last)
	middleRunes := runeCount - first - last
	var b strings.Builder
	b.Grow(headByte + middleRunes*safeRuneLen(c) + (len(v) - tailByte))
	b.WriteString(v[:headByte])
	for i := 0; i < middleRunes; i++ {
		b.WriteRune(c)
	}
	b.WriteString(v[tailByte:])
	return b.String()
}

// TruncateVisible returns the first n runes of v with no mask characters
// appended. Values of n ≤ 0 produce the empty string; n ≥ the rune count of
// v returns v unchanged. Unicode aware.
//
// Example: TruncateVisible("Sensitive", 4) → "Sens".
//
// WARNING: TruncateVisible is a formatting helper, not a masking primitive.
// It does NOT fail closed — when n ≥ the rune count of v it returns v
// verbatim. Use it only in composition with an actual masking primitive
// (for example chained after [KeepFirstN] to clip a too-long visible
// prefix). Registering TruncateVisible directly as a masking rule will
// produce data leaks on short inputs.
func TruncateVisible(v string, n int) string {
	if n <= 0 || v == "" {
		return ""
	}
	seen := 0
	for i := range v {
		if seen == n {
			return v[:i]
		}
		seen++
	}
	return v
}

// PreserveDelimiters replaces every rune of v with c, except runes listed in
// delim, which are kept verbatim. Useful when a format's separators carry
// structural meaning (for example, the dashes in a payment card number).
//
// Example: PreserveDelimiters("ab-cd", "-", '*') → "**-**".
//
// The direct-call helper rebuilds the delimiter set on every invocation. For
// hot paths construct a factory once with [PreserveDelimitersFunc].
func PreserveDelimiters(v, delim string, c rune) string {
	if v == "" {
		return ""
	}
	return preserveDelimitersWithScan(v, delim, c)
}

// preserveDelimitersWithScan is the shared core. It uses a linear scan over
// the delimiter runes — optimal for the common 1–5 delimiter case.
func preserveDelimitersWithScan(v, delim string, c rune) string {
	delimRunes := []rune(delim)
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		if containsRune(delimRunes, r) {
			b.WriteRune(r)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func containsRune(rs []rune, needle rune) bool {
	for _, r := range rs {
		if r == needle {
			return true
		}
	}
	return false
}

// ReplaceRegex applies the regex pattern to v and replaces every match with
// replacement. Returns the original pattern compilation error if pattern is
// malformed; the value argument is never included in the error message.
//
// This function compiles pattern on every call. For hot-path use, call
// [ReplaceRegexFunc] once and reuse the returned [RuleFunc].
//
// Example: ReplaceRegex("id-42", `\d+`, "N") → ("id-N", nil).
func ReplaceRegex(v, pattern, replacement string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("mask: invalid regex pattern: %w", err)
	}
	return re.ReplaceAllString(v, replacement), nil
}

// ReplaceRegexFunc compiles pattern once and returns a [RuleFunc] that
// applies it on every call. An invalid pattern returns a wrapped error and a
// nil [RuleFunc] — never panics.
func ReplaceRegexFunc(pattern, replacement string) (RuleFunc, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("mask: invalid regex pattern: %w", err)
	}
	return func(v string) string {
		return re.ReplaceAllString(v, replacement)
	}, nil
}

// TruncateVisibleFunc builds a [RuleFunc] that truncates its input to the
// first n runes. See [TruncateVisible] for boundary behaviour.
func TruncateVisibleFunc(n int) RuleFunc {
	return func(v string) string {
		return TruncateVisible(v, n)
	}
}

// ReducePrecision reduces the decimal-place precision of a numeric string by
// preserving all characters up to and including decimals digits after the
// decimal point, and replacing every subsequent digit with c. Non-numeric
// input, scientific notation, multiple decimal points, NaN, and ±Infinity
// all fall back to [SameLengthMask] so the primitive never returns the
// original value.
//
// The primitive works on the original string byte by byte — it does not
// round-trip the value through a float, so leading zeros, trailing zeros,
// and signs are preserved exactly.
//
// Examples:
//
//	ReducePrecision("37.7749295", 2, '*') // "37.77*****"
//	ReducePrecision("-37.7749",   2, '*') // "-37.77**"
//	ReducePrecision("42",         2, '*') // "42" (no fractional part)
//	ReducePrecision("1.2e5",      2, '*') // "*****" (scientific not accepted)
func ReducePrecision(v string, decimals int, c rune) string {
	if v == "" {
		return ""
	}
	if decimals < 0 {
		decimals = 0
	}
	if !isPlainDecimal(v) {
		return SameLengthMask(v, c)
	}
	// A plain decimal has at most one '.'. Find it.
	dot := strings.IndexByte(v, '.')
	if dot < 0 {
		// No fractional part — nothing to mask.
		return v
	}
	// Position of the first digit to mask, measured in bytes from start of v.
	// decimals == 0 means "mask everything after the dot".
	// decimals == n means "preserve n digits after the dot".
	cut := dot + 1 + decimals
	if cut >= len(v) {
		return v
	}
	// Mask every digit after the cut. All trailing chars are guaranteed ASCII
	// digits by isPlainDecimal.
	tail := len(v) - cut
	var b strings.Builder
	b.Grow(cut + tail*safeRuneLen(c))
	b.WriteString(v[:cut])
	for i := 0; i < tail; i++ {
		b.WriteRune(c)
	}
	return b.String()
}

// ReducePrecisionFunc builds a [RuleFunc] that reduces decimal precision.
// See [ReducePrecision] for semantics.
func ReducePrecisionFunc(decimals int) RuleFunc {
	return func(v string) string {
		return ReducePrecision(v, decimals, DefaultMaskChar)
	}
}

// KeepFirstNFunc returns a [RuleFunc] that keeps the first n runes, masking
// the rest with [DefaultMaskChar]. See [KeepFirstN].
//
// Mask-character note: factories capture [DefaultMaskChar] at construction
// and ignore later per-Masker overrides configured via [WithMaskChar] or
// [SetMaskChar]. A caller who needs the instance mask character should use
// the direct-call helper inside a closure: for example
//
//	r := func(v string) string { return mask.KeepFirstN(v, 4, m.MaskChar()) }
//
// (where `m.MaskChar()` reads whatever state the caller tracks). The
// factory's stability is deliberate: registered parametric rules should not
// change output when a global knob is turned.
func KeepFirstNFunc(n int) RuleFunc {
	return func(v string) string {
		return KeepFirstN(v, n, DefaultMaskChar)
	}
}

// KeepLastNFunc returns a [RuleFunc] that keeps the last n runes, masking
// the rest with [DefaultMaskChar]. See [KeepLastN]. The same mask-character
// capture semantics as [KeepFirstNFunc] apply.
func KeepLastNFunc(n int) RuleFunc {
	return func(v string) string {
		return KeepLastN(v, n, DefaultMaskChar)
	}
}

// KeepFirstLastFunc returns a [RuleFunc] that keeps the first and last runes
// and masks the middle. See [KeepFirstLast]. The same mask-character capture
// semantics as [KeepFirstNFunc] apply.
func KeepFirstLastFunc(first, last int) RuleFunc {
	return func(v string) string {
		return KeepFirstLast(v, first, last, DefaultMaskChar)
	}
}

// PreserveDelimitersFunc returns a [RuleFunc] that masks v with
// [DefaultMaskChar] while preserving runes listed in delim. The delimiter
// set is captured once at construction and reused on every call. The same
// mask-character capture semantics as [KeepFirstNFunc] apply.
func PreserveDelimitersFunc(delim string) RuleFunc {
	delimSet := make(map[rune]struct{}, len(delim))
	for _, r := range delim {
		delimSet[r] = struct{}{}
	}
	return func(v string) string {
		if v == "" {
			return ""
		}
		var b strings.Builder
		b.Grow(len(v))
		for _, r := range v {
			if _, ok := delimSet[r]; ok {
				b.WriteRune(r)
			} else {
				b.WriteRune(DefaultMaskChar)
			}
		}
		return b.String()
	}
}

// keepFirstLastNonSep emits v with non-separator runes masked except the
// first `first` and last `last` non-separator runes. Separators (as
// determined by isSep) are emitted verbatim. Inputs whose non-separator
// count is less than or equal to first+last fall back to
// [SameLengthMask] — the rule fails closed rather than echoing the
// input when the keep window would span the whole value.
//
// One allocation: the output [strings.Builder] is grown to len(v).
// The helper is unexported and shared by the separator-preserving
// financial and identity rules.
func keepFirstLastNonSep(v string, first, last int, c rune, isSep func(rune) bool) string {
	if v == "" {
		return ""
	}
	first, last = clampNonNeg(first), clampNonNeg(last)
	nonsep := countNonSep(v, isSep)
	if nonsep <= first+last {
		return SameLengthMask(v, c)
	}
	return buildKeepFirstLastNonSep(v, first, nonsep-last, c, isSep)
}

// keepFirstLastNonSepCounted is a variant of keepFirstLastNonSep for
// callers that have already counted non-separator runes while doing their
// own validation (for example the IBAN validator). Skips the redundant
// second count pass. The caller MUST pass the correct count.
func keepFirstLastNonSepCounted(v string, first, last, nonsep int, c rune, isSep func(rune) bool) string {
	if v == "" {
		return ""
	}
	first, last = clampNonNeg(first), clampNonNeg(last)
	if nonsep <= first+last {
		return SameLengthMask(v, c)
	}
	return buildKeepFirstLastNonSep(v, first, nonsep-last, c, isSep)
}

// keepFirstLastNonSepWithPrefix is a third variant used by rules that want
// to preserve a leading format-literal prefix verbatim in the same output
// allocation. The prefix is written first, followed by the normal
// keep-first-last-over-body pass. Using this instead of concatenating
// `prefix + keepFirstLastNonSep(body, ...)` keeps the happy path at one
// allocation (the shared strings.Builder's backing array) rather than two.
//
// The caller MUST pass the non-separator count of body (NOT including the
// prefix). On fallback (nonsep of body ≤ first+last) the helper returns
// a same-length mask of the WHOLE prefix+body, preserving the fail-closed
// contract — the alphabetic prefix is not echoed on pathologically short
// bodies.
func keepFirstLastNonSepWithPrefix(prefix, body string, first, last, bodyNonsep int, c rune, isSep func(rune) bool) string {
	first, last = clampNonNeg(first), clampNonNeg(last)
	if bodyNonsep <= first+last {
		return SameLengthMask(prefix+body, c)
	}
	var b strings.Builder
	b.Grow(len(prefix) + len(body))
	b.WriteString(prefix)
	writeKeepFirstLastBody(&b, body, first, bodyNonsep-last, c, isSep)
	return b.String()
}

// clampNonNeg returns n or zero when n is negative.
func clampNonNeg(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// countNonSep returns the number of runes in v that do not satisfy isSep.
func countNonSep(v string, isSep func(rune) bool) int {
	n := 0
	for _, r := range v {
		if !isSep(r) {
			n++
		}
	}
	return n
}

// buildKeepFirstLastNonSep emits the masked string. tailStart is the
// non-separator index (inclusive) from which runes are preserved as the
// trailing keep window.
func buildKeepFirstLastNonSep(v string, first, tailStart int, c rune, isSep func(rune) bool) string {
	var b strings.Builder
	b.Grow(len(v))
	writeKeepFirstLastBody(&b, v, first, tailStart, c, isSep)
	return b.String()
}

// writeKeepFirstLastBody walks body once, emits separator runes
// verbatim, keeps non-separator runes whose non-separator index lies
// outside the [first, tailStart) masked window, and otherwise emits the
// mask rune c. Shared by [buildKeepFirstLastNonSep] and
// [keepFirstLastNonSepWithPrefix].
func writeKeepFirstLastBody(b *strings.Builder, body string, first, tailStart int, c rune, isSep func(rune) bool) {
	seen := 0
	for _, r := range body {
		if isSep(r) {
			b.WriteRune(r)
			continue
		}
		if seen < first || seen >= tailStart {
			b.WriteRune(r)
		} else {
			b.WriteRune(c)
		}
		seen++
	}
}

// byteOffsetAtRune returns the byte index in s where the rune at position idx
// begins. idx must be in the range [0, RuneCount(s)] — an idx equal to the
// rune count returns len(s). The caller is responsible for clamping.
func byteOffsetAtRune(s string, idx int) int {
	if idx <= 0 {
		return 0
	}
	seen := 0
	for i := range s {
		if seen == idx {
			return i
		}
		seen++
	}
	return len(s)
}

// isPlainDecimal reports whether s is a sign (optional) followed by ASCII
// digits, with at most one '.' and at least one digit. Scientific notation,
// NaN, Inf, commas, whitespace, and multiple dots all return false. Used by
// [ReducePrecision] to decide when to fall back to [SameLengthMask].
func isPlainDecimal(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i++
		if i == len(s) {
			return false
		}
	}
	sawDigit := false
	sawDot := false
	for ; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= '0' && ch <= '9':
			sawDigit = true
		case ch == '.':
			if sawDot {
				return false
			}
			sawDot = true
		default:
			return false
		}
	}
	return sawDigit
}

// registerPrimitives is appended to builtinRegistrars from init. It populates
// every Masker — zero-value, package-level default, and per-instance — with
// the primitives that have fixed semantics (no parameters from the caller).
//
// Parametric primitives (KeepFirstN, ReplaceRegex, etc.) are NOT registered
// as named rules here; consumers construct them via the `...Func` factories
// and call [Masker.Register] with a name of their choosing.
func registerPrimitives(m *Masker) {
	m.mustRegisterBuiltin("full_redact",
		func(_ string) string { return FullRedactMarker },
		RuleInfo{
			Name:         "full_redact",
			Category:     "utility",
			Jurisdiction: "global",
			Description:  "Replaces any value with the constant [REDACTED]. Example: anything → [REDACTED].",
		})

	m.mustRegisterBuiltin("same_length_mask",
		func(v string) string { return SameLengthMask(v, m.maskChar()) },
		RuleInfo{
			Name:         "same_length_mask",
			Category:     "utility",
			Jurisdiction: "global",
			Description:  "Replaces every character of the input with the configured mask character, preserving length. Example: Hello → *****.",
		})

	m.mustRegisterBuiltin("nullify",
		func(_ string) string { return "" },
		RuleInfo{
			Name:         "nullify",
			Category:     "utility",
			Jurisdiction: "global",
			Description:  "Replaces any value with the empty string. Example: anything → (empty string).",
		})

	m.mustRegisterBuiltin("deterministic_hash",
		DeterministicHashFunc(),
		RuleInfo{
			Name:         "deterministic_hash",
			Category:     "utility",
			Jurisdiction: "global",
			Description:  "Replaces the value with a truncated SHA-256 digest (sha256:<first-16-hex>); pseudonymisation only, not anonymisation. Example: alice@example.com → sha256:ff8d9819fc0e12bf.",
		})
}

func init() {
	builtinRegistrars = append(builtinRegistrars, registerPrimitives)
}
