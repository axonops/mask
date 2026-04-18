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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Internal tests that exercise defensive branches the black-box
// `package mask_test` suite cannot reach because they sit behind
// earlier guards. The goal is to pin the fallback behaviour so a
// future refactor cannot silently delete the branch.

// TestInternal_KeepFirstLastNonSep_DefensiveBranches covers the
// empty-input and window-too-big branches of the shared helper
// which the financial / identity callers never trigger because
// they pre-filter before calling.
func TestInternal_KeepFirstLastNonSep_DefensiveBranches(t *testing.T) {
	t.Parallel()
	noSep := func(rune) bool { return false }
	assert.Equal(t, "", keepFirstLastNonSep("", 2, 2, '*', noSep),
		"empty input must return empty")
	assert.Equal(t, "****", keepFirstLastNonSep("abcd", 2, 2, '*', noSep),
		"window exactly equal to non-separator count must fall back to same-length mask")
}

// TestInternal_ClampNonNeg_Negative pins the negative-input branch.
func TestInternal_ClampNonNeg_Negative(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 0, clampNonNeg(-1), "negative clamps to zero")
	assert.Equal(t, 0, clampNonNeg(-100), "large-negative clamps to zero")
	assert.Equal(t, 5, clampNonNeg(5), "positive passes through")
}

// TestInternal_ResolveAlgo_OutOfRange pins the resolveAlgo clamp
// for values below zero and at-or-above the maximum.
func TestInternal_ResolveAlgo_OutOfRange(t *testing.T) {
	t.Parallel()
	assert.Equal(t, SHA256, resolveAlgo(HashAlgorithm(-1)))
	assert.Equal(t, SHA256, resolveAlgo(maxHashAlgorithm))
	assert.Equal(t, SHA256, resolveAlgo(maxHashAlgorithm+1))
	assert.Equal(t, SHA256, resolveAlgo(SHA256))
	assert.Equal(t, SHA512, resolveAlgo(SHA512))
}

// TestInternal_Masker_ZeroValueLoadRules confirms that a zero-value
// Masker initialises on first access. Public callers normally use
// [New], but the type is exported so zero-value use is permitted.
func TestInternal_Masker_ZeroValueLoadRules(t *testing.T) {
	t.Parallel()
	var m Masker
	// Direct call to loadRules exercises the rm == nil branch.
	rm := m.loadRules()
	require.NotNil(t, rm, "zero-value Masker must lazily initialise")
	// Subsequent calls skip the initialisation branch.
	rm2 := m.loadRules()
	assert.Same(t, rm, rm2, "second call returns the same map pointer")
}

// TestInternal_MustRegisterBuiltin_PanicOnDuplicate covers the
// defensive panic when a duplicate name is registered at init
// time. The built-in registrar set cannot trigger this, so we
// test it directly on a fresh Masker.
func TestInternal_MustRegisterBuiltin_PanicOnDuplicate(t *testing.T) {
	t.Parallel()
	var m Masker
	m.ensureInit()
	// The name below is guaranteed not to collide with built-ins.
	const name = "internal_test_duplicate_rule"
	m.mustRegisterBuiltin(name, func(v string) string { return v }, RuleInfo{Name: name, Category: "test"})
	assert.PanicsWithValue(t,
		"mask: built-in registration failed: mask: rule already registered: name \""+name+"\"",
		func() {
			m.mustRegisterBuiltin(name, func(v string) string { return v }, RuleInfo{Name: name, Category: "test"})
		},
		"second registration with the same name MUST panic",
	)
}

// TestInternal_IsLDHLabel_EmptyAndInvalid covers the empty-string
// branch and each rejection path of the label validator that the
// hostname rule's own tests don't enumerate directly.
func TestInternal_IsLDHLabel_EmptyAndInvalid(t *testing.T) {
	t.Parallel()
	assert.False(t, isLDHLabel(""), "empty label is invalid")
	assert.False(t, isLDHLabel("foo bar"), "space is invalid")
	assert.False(t, isLDHLabel("foo.bar"), "dot is invalid inside a single label")
	assert.False(t, isLDHLabel("foo\x00bar"), "NUL is invalid")
	assert.True(t, isLDHLabel("foo-bar_baz-42"), "LDH with underscore and digit is valid")
}

// TestInternal_IsBracketedIPv6Host_Malformed covers the branches
// of the IPv6 bracket validator that the public URL tests exercise
// only tangentially.
func TestInternal_IsBracketedIPv6Host_Malformed(t *testing.T) {
	t.Parallel()
	assert.False(t, isBracketedIPv6Host("no-bracket"), "missing leading bracket is invalid")
	assert.False(t, isBracketedIPv6Host("[2001:db8::1"), "missing closing bracket is invalid")
	assert.False(t, isBracketedIPv6Host("[[2001:db8::1]"), "double opening bracket is invalid")
	assert.False(t, isBracketedIPv6Host("[2001:db8::1]abc"), "trailing non-colon is invalid")
	assert.True(t, isBracketedIPv6Host("[2001:db8::1]"), "canonical bracketed IPv6 is valid")
	assert.True(t, isBracketedIPv6Host("[2001:db8::1]:8080"), "bracketed IPv6 with port is valid")
}

// TestInternal_IsBase64URLSeg_EmptyAndInvalid covers the empty and
// disallowed-character branches.
func TestInternal_IsBase64URLSeg_EmptyAndInvalid(t *testing.T) {
	t.Parallel()
	assert.False(t, isBase64URLSeg(""), "empty segment rejected")
	assert.False(t, isBase64URLSeg("has+plus"), "`+` is base64 standard, not base64url")
	assert.False(t, isBase64URLSeg("has/slash"), "`/` is base64 standard, not base64url")
	assert.False(t, isBase64URLSeg("has=padding"), "`=` padding not accepted")
	assert.True(t, isBase64URLSeg("Abc123_-"), "canonical base64url accepted")
}

// TestInternal_IsPlainDecimal_EdgeCases covers sign-only, multi-dot,
// leading-sign-only, and NaN-like inputs.
func TestInternal_IsPlainDecimal_EdgeCases(t *testing.T) {
	t.Parallel()
	assert.False(t, isPlainDecimal(""))
	assert.False(t, isPlainDecimal("+"), "sign with no digits")
	assert.False(t, isPlainDecimal("-"), "sign with no digits")
	assert.False(t, isPlainDecimal("1.2.3"), "multiple dots")
	assert.False(t, isPlainDecimal("1e5"), "scientific rejected")
	assert.False(t, isPlainDecimal("."), "dot only")
	assert.True(t, isPlainDecimal("0"))
	assert.True(t, isPlainDecimal("42"))
	assert.True(t, isPlainDecimal("-42.5"))
	assert.True(t, isPlainDecimal("+0.0"))
}

// TestInternal_AllASCIIDigits_EmptyString covers the short-circuit
// that the public country / telecom rules never reach (empty input
// is filtered earlier in each rule's body).
func TestInternal_AllASCIIDigits_EmptyString(t *testing.T) {
	t.Parallel()
	assert.False(t, allASCIIDigits(""), "empty string is not all digits")
	assert.True(t, allASCIIDigits("0123456789"))
	assert.False(t, allASCIIDigits("012a456"))
}

// TestInternal_IsUKOutwardCode_EdgeCases covers the length and
// character-class rejection branches.
func TestInternal_IsUKOutwardCode_EdgeCases(t *testing.T) {
	t.Parallel()
	assert.False(t, isUKOutwardCode("A"), "1-byte too short")
	assert.False(t, isUKOutwardCode("ABCDE"), "5-byte too long")
	assert.False(t, isUKOutwardCode("1B"), "leading byte must be letter")
	assert.False(t, isUKOutwardCode("AB"), "outward code with no digit is rejected")
	assert.False(t, isUKOutwardCode("A!"), "non-LDH byte rejected")
	assert.True(t, isUKOutwardCode("M1"))
	assert.True(t, isUKOutwardCode("SW1A"))
}

// TestInternal_IsUKInwardCode_EdgeCases covers the shape-mismatch
// rejections.
func TestInternal_IsUKInwardCode_EdgeCases(t *testing.T) {
	t.Parallel()
	assert.False(t, isUKInwardCode(""))
	assert.False(t, isUKInwardCode("1AB"[:2]), "wrong length")
	assert.False(t, isUKInwardCode("ABC"), "first byte must be digit")
	assert.False(t, isUKInwardCode("12A"), "second byte must be letter")
	assert.True(t, isUKInwardCode("1AB"))
}

// TestInternal_IsGeoMaskable_EdgeCases covers the leading-plus
// rejection and the no-dot branch.
func TestInternal_IsGeoMaskable_EdgeCases(t *testing.T) {
	t.Parallel()
	assert.False(t, isGeoMaskable(""))
	assert.False(t, isGeoMaskable("+1.23"), "leading plus rejected for geo rules")
	assert.False(t, isGeoMaskable("123"), "integer rejected — no fractional part to mask")
	assert.False(t, isGeoMaskable("1.2"), "fractional too short to mask")
	assert.False(t, isGeoMaskable("1..2"), "double-dot rejected")
	assert.False(t, isGeoMaskable("abc"), "non-decimal rejected")
	assert.True(t, isGeoMaskable("1.234"))
	assert.True(t, isGeoMaskable("-122.4194155"))
}

// TestInternal_MonthNameRecognised_Boundaries pins the rejection
// branches that the public DOB tests exercise only partially.
func TestInternal_MonthNameRecognised_Boundaries(t *testing.T) {
	t.Parallel()
	assert.False(t, monthNameRecognised(""))
	assert.False(t, monthNameRecognised(strings.Repeat("x", 20)), "length > longest month name rejected")
	assert.False(t, monthNameRecognised("Xanuary"), "wrong letter rejected")
	assert.True(t, monthNameRecognised("January"))
	assert.True(t, monthNameRecognised("DECEMBER"), "upper-case accepted")
	assert.True(t, monthNameRecognised("May"))
}
