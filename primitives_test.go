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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/mask"
)

// ---------- FullRedact ----------

func TestFullRedact_AlwaysReturnsRedactedConstant(t *testing.T) {
	t.Parallel()
	cases := []string{"", "a", "secret", "佐藤太郎", strings.Repeat("x", 1000), "\xff\xfe"}
	for _, v := range cases {
		t.Run(short(v), func(t *testing.T) {
			assert.Equal(t, mask.FullRedactMarker, mask.FullRedact(v))
		})
	}
}

// ---------- Nullify ----------

func TestNullify_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"", "a", "secret", "佐藤太郎"} {
		assert.Equal(t, "", mask.Nullify(v))
	}
}

// ---------- FixedReplacement ----------

func TestFixedReplacementFunc_IgnoresInput(t *testing.T) {
	t.Parallel()
	r := mask.FixedReplacementFunc("N/A")
	for _, v := range []string{"", "anything", "佐藤", strings.Repeat("z", 200)} {
		assert.Equal(t, "N/A", r(v))
	}
}

func TestFixedReplacementFunc_EmptyEqualsNullify(t *testing.T) {
	t.Parallel()
	empty := mask.FixedReplacementFunc("")
	for _, v := range []string{"", "abc", "佐藤"} {
		assert.Equal(t, mask.Nullify(v), empty(v))
	}
}

func TestFixedReplacementFunc_UnaffectedByMaskCharChange(t *testing.T) {
	// Intentionally NOT t.Parallel — mutates global mask char.
	t.Cleanup(func() { mask.SetMaskChar(mask.DefaultMaskChar) })

	r := mask.FixedReplacementFunc("[[CAPTURED]]")
	mask.SetMaskChar('X')
	assert.Equal(t, "[[CAPTURED]]", r("secret"))
}

// ---------- SameLengthMask ----------

func TestSameLengthMask_PreservesLength_Unicode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		char  rune
		want  string
	}{
		{"empty", "", '*', ""},
		{"ascii", "Hello", '*', "*****"},
		{"cjk", "佐藤太郎", '*', "****"},
		{"combining", "e\u0301", '*', "**"}, // "é" decomposed → 2 runes
		{"emoji zwj", "\U0001F468\u200D\U0001F469\u200D\U0001F467", '*', "*****"},
		{"multibyte mask", "Hello", '※', "※※※※※"},
		{"already masked", "****", '*', "****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mask.SameLengthMask(tc.input, tc.char))
		})
	}
}

// ---------- KeepFirstN ----------

func TestKeepFirstN_Boundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		n     int
		char  rune
		want  string
	}{
		{"n zero", "abcdef", 0, '*', "******"},
		{"n one", "abcdef", 1, '*', "a*****"},
		{"n equals len", "abcdef", 6, '*', "abcdef"},
		{"n greater than len", "abcdef", 99, '*', "abcdef"},
		{"n negative", "abcdef", -1, '*', "******"},
		{"empty input", "", 3, '*', ""},
		{"unicode muller", "Müller", 3, '*', "Mül***"},
		{"cjk", "佐藤太郎", 2, '*', "佐藤**"},
		{"combining sequence", "e\u0301fg", 1, '*', "e***"}, // rune-level, documents split
		{"emoji zwj break", "\U0001F468\u200D\U0001F469abc", 1, '*', "\U0001F468*****"},
		{"already masked", "****", 2, '*', "****"},
		{"non default char", "abc", 0, '#', "###"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mask.KeepFirstN(tc.input, tc.n, tc.char))
		})
	}
}

// ---------- KeepLastN ----------

func TestKeepLastN_Boundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		n     int
		char  rune
		want  string
	}{
		{"n zero", "abcdef", 0, '*', "******"},
		{"n one", "abcdef", 1, '*', "*****f"},
		{"n equals len", "abcdef", 6, '*', "abcdef"},
		{"n greater than len", "abcdef", 99, '*', "abcdef"},
		{"n negative", "abcdef", -1, '*', "******"},
		{"empty input", "", 3, '*', ""},
		{"unicode muller", "Müller", 3, '*', "***ler"},
		{"cjk", "佐藤太郎", 2, '*', "**太郎"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mask.KeepLastN(tc.input, tc.n, tc.char))
		})
	}
}

// ---------- KeepFirstLast ----------

func TestKeepFirstLast_OverlappingRanges(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		input       string
		first, last int
		char        rune
		want        string
	}{
		{"first plus last equals len", "ABCD", 2, 2, '*', "ABCD"},
		{"first plus last exceeds len", "ABCD", 3, 2, '*', "ABCD"},
		{"first plus last is len minus one", "ABCDE", 2, 2, '*', "AB*DE"},
		{"both negative", "abcd", -1, -1, '*', "****"},
		{"both zero", "abcdef", 0, 0, '*', "******"},
		{"single rune", "A", 1, 1, '*', "A"},
		{"empty input", "", 2, 2, '*', ""},
		{"canonical", "SensitiveData", 4, 4, '*', "Sens*****Data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mask.KeepFirstLast(tc.input, tc.first, tc.last, tc.char))
		})
	}
}

func TestKeepFirstLast_Unicode(t *testing.T) {
	t.Parallel()
	// "María" is 5 runes: M, a, r, í, a.
	// first=2, last=1 → 2 middle runes masked.
	assert.Equal(t, "Ma**a", mask.KeepFirstLast("María", 2, 1, '*'))

	// "e\u0301fg" is 4 runes: e, combining acute, f, g.
	// first=2, last=1 → 1 middle rune masked.
	assert.Equal(t, "e\u0301*g", mask.KeepFirstLast("e\u0301fg", 2, 1, '*'))

	// "佐藤太郎" is 4 runes. first=1, last=1 → 2 middle runes masked.
	assert.Equal(t, "佐**郎", mask.KeepFirstLast("佐藤太郎", 1, 1, '*'))
}

// ---------- TruncateVisible ----------

// TestTruncateVisible_FailOpenBehaviourOnShortInput pins the documented
// WARNING: TruncateVisible is a formatting helper, not fail-closed. For
// n >= rune count the original value is returned. The warning in godoc is
// prose; this test makes it a contract.
func TestTruncateVisible_FailOpenBehaviourOnShortInput(t *testing.T) {
	t.Parallel()
	// n >= len: original returned verbatim (the fail-open property we document).
	assert.Equal(t, "abc", mask.TruncateVisible("abc", 99))
	assert.Equal(t, "abc", mask.TruncateVisible("abc", 3))
	// Invalid UTF-8 passes through without panic and remains non-empty.
	got := mask.TruncateVisible("\xff\xfe\xfd", 2)
	assert.NotEmpty(t, got)
	assert.NotEqual(t, "\xff\xfe\xfd", got)
}

func TestTruncateVisible_BasicAndUnicode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{"n zero", "abcdef", 0, ""},
		{"n negative", "abcdef", -1, ""},
		{"n equals len", "abcdef", 6, "abcdef"},
		{"n greater than len", "abcdef", 99, "abcdef"},
		{"n less than len", "abcdef", 3, "abc"},
		{"unicode muller", "Müller", 3, "Mül"},
		{"cjk", "佐藤太郎", 2, "佐藤"},
		{"empty input", "", 3, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mask.TruncateVisible(tc.input, tc.n))
		})
	}
}

// ---------- PreserveDelimiters ----------

func TestPreserveDelimiters_Email(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "*****@*******.***",
		mask.PreserveDelimiters("alice@example.com", "@.", '*'))
}

func TestPreserveDelimiters_EdgeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		delim string
		char  rune
		want  string
	}{
		{"empty input", "", "@.", '*', ""},
		{"empty delim equals same length mask", "abc", "", '*', "***"},
		{"delim contains mask char", "a*b", "*", '*', "***"},
		{"cjk delim", "佐藤・太郎。", "・。", '*', "**・**。"},
		{"delim superset of input", "abc", "abcdef", '*', "abc"},
		{"duplicate delim runes", "a@b@c", "@@", '*', "*@*@*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mask.PreserveDelimiters(tc.input, tc.delim, tc.char))
		})
	}
}

func TestPreserveDelimitersFunc_CapturesDelimOnce(t *testing.T) {
	t.Parallel()
	r := mask.PreserveDelimitersFunc("-_")
	assert.Equal(t, "***-***_***", r("abc-def_ghi"))
}

// TestFactory_CapturesDefaultMaskChar pins the documented behaviour that
// every `...Func` factory captures [DefaultMaskChar] at construction and is
// NOT affected by a later SetMaskChar call. A consumer who needs the
// instance mask character must close over the direct-call helper.
func TestFactory_CapturesDefaultMaskChar(t *testing.T) {
	// Intentionally NOT t.Parallel — mutates global mask char.
	t.Cleanup(func() { mask.SetMaskChar(mask.DefaultMaskChar) })

	keep := mask.KeepFirstNFunc(2)
	keepLast := mask.KeepLastNFunc(2)
	keepBoth := mask.KeepFirstLastFunc(1, 1)
	trunc := mask.TruncateVisibleFunc(2)
	pres := mask.PreserveDelimitersFunc("-")
	redprec := mask.ReducePrecisionFunc(1)

	mask.SetMaskChar('X')

	// All factories above were constructed BEFORE SetMaskChar. The mask
	// rune they emit must remain '*'. TruncateVisible emits no mask rune.
	assert.Equal(t, "se****", keep("secret"))
	assert.Equal(t, "****et", keepLast("secret"))
	assert.Equal(t, "s****t", keepBoth("secret"))
	assert.Equal(t, "se", trunc("secret"))
	assert.Equal(t, "*-*", pres("a-b"))
	assert.Equal(t, "37.7*", redprec("37.77"))

	// The direct-call helper sees the instance-level mask char when the
	// caller passes it explicitly — proves the escape hatch works.
	assert.Equal(t, "seXXXX", mask.KeepFirstN("secret", 2, 'X'))
}

// ---------- ReplaceRegex ----------

func TestReplaceRegex_InvalidPattern_ReturnsError(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"[a-", "(?P<name", "*"} {
		t.Run(p, func(t *testing.T) {
			_, err := mask.ReplaceRegex("irrelevant", p, "X")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "mask: invalid regex pattern")
			// Value must not be in the error.
			assert.NotContains(t, err.Error(), "irrelevant")
		})
	}
}

func TestReplaceRegex_HappyPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                                  string
		input, pattern, replacement, expected string
	}{
		{"no match", "abc", "z+", "X", "abc"},
		{"backreference", "abc", "(a)(b)", "$2$1", "bac"},
		{"digits to X", "id-42", `\d+`, "N", "id-N"},
		{"literal 1 stays literal", "abc", "(a)", `\1`, `\1bc`},
		{"empty replacement strips", "abc", "b", "", "ac"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mask.ReplaceRegex(tc.input, tc.pattern, tc.replacement)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestReplaceRegexFunc_CompiledOnce(t *testing.T) {
	t.Parallel()
	r, err := mask.ReplaceRegexFunc(`\d+`, "N")
	require.NoError(t, err)
	for i := 0; i < 1000; i++ {
		assert.Equal(t, "id-N", r("id-42"))
	}
}

func TestReplaceRegexFunc_InvalidPatternReturnsError(t *testing.T) {
	t.Parallel()
	r, err := mask.ReplaceRegexFunc("[a-", "X")
	require.Error(t, err)
	assert.Nil(t, r)
}

// ---------- ReducePrecision ----------

func TestReducePrecision_NumericAndNonNumeric(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		decimals int
		char     rune
		want     string
	}{
		{"canonical", "37.7749295", 2, '*', "37.77*****"},
		{"negative sign preserved", "-37.7749", 2, '*', "-37.77**"},
		{"positive sign preserved", "+37.77", 2, '*', "+37.77"},
		{"leading zeros preserved", "037.70", 1, '*', "037.7*"},
		{"integer no dot", "42", 2, '*', "42"},
		{"decimals greater than fraction", "37.7", 5, '*', "37.7"},
		{"scientific fallback", "1.2e5", 2, '*', "*****"},
		{"nan fallback", "NaN", 2, '*', "***"},
		{"inf fallback", "Inf", 2, '*', "***"},
		{"multiple dots fallback", "1.2.3", 2, '*', "*****"},
		{"comma fallback", "37,77", 2, '*', "*****"},
		{"trailing whitespace fallback", "37.77 ", 2, '*', "******"},
		{"empty", "", 2, '*', ""},
		{"decimals negative clamps to zero", "37.7749", -1, '*', "37.****"},
		{"dot only", ".", 2, '*', "*"},
		{"leading dot", ".5", 1, '*', ".5"},
		{"trailing dot", "5.", 1, '*', "5."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mask.ReducePrecision(tc.input, tc.decimals, tc.char))
		})
	}
}

func TestReducePrecisionFunc_UsesDefaultMaskChar(t *testing.T) {
	t.Parallel()
	r := mask.ReducePrecisionFunc(2)
	assert.Equal(t, "37.77*****", r("37.7749295"))
}

// ---------- Remaining parametric factories ----------

func TestKeepFirstNFunc_UsesDefaultMaskChar(t *testing.T) {
	t.Parallel()
	r := mask.KeepFirstNFunc(3)
	assert.Equal(t, "abc***", r("abcdef"))
}

func TestKeepLastNFunc_UsesDefaultMaskChar(t *testing.T) {
	t.Parallel()
	r := mask.KeepLastNFunc(3)
	assert.Equal(t, "***def", r("abcdef"))
}

func TestKeepFirstLastFunc_UsesDefaultMaskChar(t *testing.T) {
	t.Parallel()
	r := mask.KeepFirstLastFunc(2, 2)
	assert.Equal(t, "Se*********ta", r("SensitiveData"))
}

func TestTruncateVisibleFunc_TruncatesWithNoMark(t *testing.T) {
	t.Parallel()
	r := mask.TruncateVisibleFunc(3)
	assert.Equal(t, "abc", r("abcdef"))
	assert.Equal(t, "", r(""))
}

func TestPreserveDelimitersFunc_EmptyInput(t *testing.T) {
	t.Parallel()
	r := mask.PreserveDelimitersFunc("@.")
	assert.Equal(t, "", r(""))
}

// ---------- DeterministicHash ----------

func TestDeterministicHash_IsDeterministic(t *testing.T) {
	t.Parallel()
	const v = "alice@example.com"
	first := mask.DeterministicHash(v)
	for i := 0; i < 1000; i++ {
		assert.Equal(t, first, mask.DeterministicHash(v))
	}
}

func TestDeterministicHash_UsesSHA256_ByDefault(t *testing.T) {
	t.Parallel()
	out := mask.DeterministicHash("alice@example.com")
	assert.True(t, strings.HasPrefix(out, "sha256:"), "got %q", out)
	assert.Equal(t, len("sha256:")+16, len(out), "expected 23 bytes, got %d", len(out))
}

func TestDeterministicHash_WithAlgorithm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		algo   mask.HashAlgorithm
		prefix string
	}{
		{"sha256", mask.SHA256, "sha256"},
		{"sha512", mask.SHA512, "sha512"},
		{"sha3_256", mask.SHA3_256, "sha3-256"},
		{"sha3_512", mask.SHA3_512, "sha3-512"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := mask.DeterministicHashFunc(mask.WithAlgorithm(tc.algo))("alice@example.com")
			want := tc.prefix + ":"
			assert.True(t, strings.HasPrefix(out, want), "got %q, want prefix %q", out, want)
			assert.Equal(t, len(tc.prefix)+1+16, len(out))
		})
	}
}

func TestDeterministicHash_WithSalt_UsesHMAC(t *testing.T) {
	t.Parallel()
	const (
		val     = "alice@example.com"
		salt    = "k"
		version = "v1"
	)
	cases := []struct {
		name   string
		algo   mask.HashAlgorithm
		ctor   func() hash.Hash
		prefix string
	}{
		{"sha256", mask.SHA256, sha256.New, "sha256"},
		{"sha512", mask.SHA512, sha512.New, "sha512"},
		{"sha3_256", mask.SHA3_256, func() hash.Hash { return sha3.New256() }, "sha3-256"},
		{"sha3_512", mask.SHA3_512, func() hash.Hash { return sha3.New512() }, "sha3-512"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mask.DeterministicHashFunc(mask.WithAlgorithm(tc.algo), mask.WithSalt(salt), mask.WithSaltVersion(version))(val)
			h := hmac.New(tc.ctor, []byte(salt))
			h.Write([]byte(val))
			want := tc.prefix + ":" + version + ":" + hex.EncodeToString(h.Sum(nil)[:8])
			assert.Equal(t, want, got)
		})
	}
}

func TestDeterministicHashFunc_IncludesVersion(t *testing.T) {
	t.Parallel()
	out := mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion("v1"))("alice@example.com")
	// Must begin with the versioned prefix and be exactly 26 bytes long:
	// "sha256:" (7) + "v1:" (3) + 16 hex = 26.
	assert.True(t, strings.HasPrefix(out, "sha256:v1:"), "got %q", out)
	assert.Len(t, out, 26)
}

func TestDeterministicHash_WithSalt_IsDeterministic(t *testing.T) {
	t.Parallel()
	r := mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion("v1"))
	first := r("alice@example.com")
	for i := 0; i < 1000; i++ {
		assert.Equal(t, first, r("alice@example.com"))
	}
}

func TestDeterministicHash_DifferentSalt_DifferentOutput(t *testing.T) {
	t.Parallel()
	const v = "alice@example.com"
	a := mask.DeterministicHashFunc(mask.WithSalt("salt-a"), mask.WithSaltVersion("v1"))(v)
	b := mask.DeterministicHashFunc(mask.WithSalt("salt-b"), mask.WithSaltVersion("v1"))(v)
	assert.NotEqual(t, a, b)
}

func TestDeterministicHash_DifferentVersions_DifferentOutputs(t *testing.T) {
	t.Parallel()
	const (
		v    = "alice@example.com"
		salt = "k"
	)
	pairs := []struct{ left, right string }{
		{"v1", "v2"},
		{"v1", "V1"},
		{"v1", "v1.0"},
		{"2026-01", "2026-02"},
		{"a", "a."},
		{"rc1", "rc2"},
	}
	for _, p := range pairs {
		t.Run(p.left+"_vs_"+p.right, func(t *testing.T) {
			a := mask.DeterministicHashFunc(mask.WithSalt(salt), mask.WithSaltVersion(p.left))(v)
			b := mask.DeterministicHashFunc(mask.WithSalt(salt), mask.WithSaltVersion(p.right))(v)
			assert.NotEqual(t, a, b)
		})
	}
}

func TestDeterministicHash_EmptySaltCollapsesToUnsalted(t *testing.T) {
	t.Parallel()
	// WithSalt("", anything) is the unsalted path — version is ignored
	// when salt is empty. Output equals the plain DeterministicHash.
	const v = "alice@example.com"
	for _, ver := range []string{"", "v1", "2026-01", "anything goes here"} {
		t.Run("version="+ver, func(t *testing.T) {
			withEmpty := mask.DeterministicHashFunc(mask.WithSalt(""), mask.WithSaltVersion(ver))(v)
			unsalted := mask.DeterministicHash(v)
			assert.Equal(t, unsalted, withEmpty)
		})
	}
}

func TestDeterministicHash_EmptyVersionFailsClosed(t *testing.T) {
	t.Parallel()
	// Non-empty salt + empty version → every Apply returns the full-redact
	// marker verbatim. No prefix, no colon, no digest.
	salts := []string{"k", "SEKRET", "\x00", "佐藤", strings.Repeat("s", 1024)}
	values := []string{"", "x", "alice@example.com", "佐藤太郎", "\xff\xfe", strings.Repeat("x", 1000), mask.FullRedactMarker}
	for _, s := range salts {
		for _, v := range values {
			got := mask.DeterministicHashFunc(mask.WithSalt(s), mask.WithSaltVersion(""))(v)
			assert.Equal(t, mask.FullRedactMarker, got, "salt=%q value=%q", s, v)
		}
	}
	// Same via the factory.
	r := mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion(""))
	for _, v := range values {
		assert.Equal(t, mask.FullRedactMarker, r(v), "factory value=%q", v)
	}
}

func TestDeterministicHash_VersionRejectsColon(t *testing.T) {
	t.Parallel()
	cases := []string{"v:1", ":", ":v1", "v1:", "v::v", "a:b:c"}
	for _, ver := range cases {
		t.Run(ver, func(t *testing.T) {
			got := mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion(ver))("alice@example.com")
			assert.Equal(t, mask.FullRedactMarker, got)
		})
	}
}

func TestDeterministicHash_VersionCharsetEnforced(t *testing.T) {
	t.Parallel()

	bad := []string{
		" ", "v 1", "v\n", "v\r", "v\t1", "v\x00", "v\x7f",
		"v/1", "v=1", "v+1", "v#1", "v,1", "v;1", "v|1",
		"v*", "v?", "v(", "v)", "v[", "v]", "v{", "v}",
		"v@", "v!", "v~", "v'", "v\"", "v`", "v\\", "v$", "v%", "v^", "v&",
		"🎉", "v🎉", "café", "naïve", "Ω", "ß",
		strings.Repeat("a", 33),
		strings.Repeat("a", 64),
		strings.Repeat("a", 1024),
	}
	for _, ver := range bad {
		t.Run("bad_"+shortVersion(ver), func(t *testing.T) {
			got := mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion(ver))("alice@example.com")
			assert.Equal(t, mask.FullRedactMarker, got)
		})
	}

	good := []string{
		"v", "1", "v1", "V1", "v.1", "v-1", "v_1", "2026-01", "v_1.2-rc",
		strings.Repeat("a", 32),
		"0", "a.b-c_d", ".", "-", "_",
	}
	for _, ver := range good {
		t.Run("good_"+shortVersion(ver), func(t *testing.T) {
			got := mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion(ver))("alice@example.com")
			assert.NotEqual(t, mask.FullRedactMarker, got)
			assert.True(t, strings.HasPrefix(got, "sha256:"+ver+":"), "got %q", got)
		})
	}
}

// shortVersion produces a subtest-name-safe label for a version string.
func shortVersion(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) > 8 {
		return "len_" + strconv.Itoa(len(s))
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			out = append(out, b)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

func TestDeterministicHash_StickyMisconfiguration(t *testing.T) {
	t.Parallel()
	// Misconfigured option followed by a valid one must still produce
	// FullRedactMarker — the sticky flag cannot be cleared.
	got := mask.DeterministicHashFunc(
		mask.WithSalt("k"), mask.WithSaltVersion("bad:version"),
		mask.WithSalt("k"), mask.WithSaltVersion("v1"),
	)("alice@example.com")
	assert.Equal(t, mask.FullRedactMarker, got)
}

func TestDeterministicHash_BuiltInEqualsZeroOptionFactory(t *testing.T) {
	t.Parallel()
	factory := mask.DeterministicHashFunc()
	for _, v := range []string{"", "a", "alice@example.com", "佐藤太郎", "\xff\xfe", strings.Repeat("x", 1000), "a\x00b"} {
		assert.Equal(t, mask.DeterministicHash(v), factory(v), "input=%q", v)
		assert.Equal(t, mask.DeterministicHash(v), mask.Apply("deterministic_hash", v), "input=%q via Apply", v)
	}
}

func TestDeterministicHash_OptionLastWins(t *testing.T) {
	t.Parallel()
	// Algorithm: last-wins collapses to SHA-256.
	out := mask.DeterministicHashFunc(
		mask.WithAlgorithm(mask.SHA512),
		mask.WithAlgorithm(mask.SHA256),
	)("x")
	assert.True(t, strings.HasPrefix(out, "sha256:"))

	// Salt: setting salt+version then clearing salt to empty reverts
	// to the unsalted path; a later version without a salt is ignored.
	back := mask.DeterministicHashFunc(
		mask.WithSalt("k"), mask.WithSaltVersion("v1"),
		mask.WithSalt(""),
	)("x")
	unsalted := mask.DeterministicHash("x")
	assert.Equal(t, unsalted, back)
}

func TestDeterministicHash_UnknownAlgorithmClampsToSHA256(t *testing.T) {
	t.Parallel()
	out := mask.DeterministicHashFunc(mask.WithAlgorithm(mask.HashAlgorithm(99)))("x")
	assert.True(t, strings.HasPrefix(out, "sha256:"))

	out = mask.DeterministicHashFunc(mask.WithAlgorithm(mask.HashAlgorithm(-1)))("x")
	assert.True(t, strings.HasPrefix(out, "sha256:"))
}

func TestHashAlgorithm_StringMatchesPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		algo mask.HashAlgorithm
		want string
	}{
		{mask.SHA256, "sha256"},
		{mask.SHA512, "sha512"},
		{mask.SHA3_256, "sha3-256"},
		{mask.SHA3_512, "sha3-512"},
		{mask.HashAlgorithm(99), "sha256"},
		{mask.HashAlgorithm(-1), "sha256"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.algo.String())
	}
}

// TestDeterministicHash_SaltNotLeakedInOutputOrDescribe verifies acceptance
// criterion #10 (issue #3): salt values never appear in masked output, in
// Describe(), or in errors.
//
// Strategy: cover a corpus of inputs that deliberately includes values equal
// to the salt, values containing the salt as a substring, and encoded
// variants. Walk Describe()'s RuleInfo fields reflectively so this test
// keeps working if RuleInfo gains new string fields.
func TestDeterministicHash_SaltNotLeakedInOutputOrDescribe(t *testing.T) {
	t.Parallel()
	const salt = "SEKRET"

	m := mask.New()
	require.NoError(t, m.Register("salted_hash", mask.DeterministicHashFunc(mask.WithSalt(salt), mask.WithSaltVersion("v1"))))

	inputs := []string{
		"",
		"ascii",
		salt, // value == salt
		salt + "-with-suffix",
		"prefix-" + salt,
		"佐藤太郎",
		"\xff\xfe",                       // invalid UTF-8
		"\x00" + salt + "\x00",           // NUL-wrapped salt
		hex.EncodeToString([]byte(salt)), // hex-encoded form
		strings.Repeat("x", 1000),
	}
	for _, in := range inputs {
		out := m.Apply("salted_hash", in)
		assert.NotContains(t, out, salt, "salt leaked for input=%q", in)
		assert.NotContains(t, out, hex.EncodeToString([]byte(salt)), "salt-hex leaked for input=%q", in)
	}

	info, ok := m.Describe("salted_hash")
	require.True(t, ok)
	v := reflect.ValueOf(info)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.String {
			assert.NotContains(t, f.String(), salt,
				"salt leaked in RuleInfo.%s", v.Type().Field(i).Name)
		}
	}
}

// TestDeterministicHash_VersionDoesNotLeakSalt asserts the two-sided
// contract called out in issue #24: the salt never appears in any output
// surface, while the version — which is part of the public wire format —
// must appear in the output for every successful hash.
func TestDeterministicHash_VersionDoesNotLeakSalt(t *testing.T) {
	t.Parallel()
	const (
		salt    = "SEKRET"
		version = "v1"
	)

	m := mask.New()
	require.NoError(t, m.Register("salted_hash_v", mask.DeterministicHashFunc(mask.WithSalt(salt), mask.WithSaltVersion(version))))

	inputs := []string{
		"",
		"ascii",
		salt,
		salt + "-with-suffix",
		"prefix-" + salt,
		"佐藤太郎",
		"\xff\xfe",
		"\x00" + salt + "\x00",
		hex.EncodeToString([]byte(salt)),
		strings.Repeat("x", 1000),
	}
	for _, in := range inputs {
		out := m.Apply("salted_hash_v", in)
		assert.NotContains(t, out, salt, "salt leaked for input=%q", in)
		assert.NotContains(t, out, hex.EncodeToString([]byte(salt)), "salt-hex leaked for input=%q", in)
		// The positive half of the contract: the version IS part of the
		// wire format and must appear between the algo prefix and the
		// digest.
		assert.Contains(t, out, ":"+version+":", "version missing for input=%q; out=%q", in, out)
	}

	info, ok := m.Describe("salted_hash_v")
	require.True(t, ok)
	v := reflect.ValueOf(info)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.String {
			assert.NotContains(t, f.String(), salt,
				"salt leaked in RuleInfo.%s", v.Type().Field(i).Name)
		}
	}
}

func TestDeterministicHash_ConcurrentHashing(t *testing.T) {
	t.Parallel()
	r := mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion("v1"))
	want := r("alice@example.com")

	const goroutines = 50
	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-gate
			for j := 0; j < 200; j++ {
				got := r("alice@example.com")
				if got != want {
					errs <- errors.New("mismatch under concurrent use")
					return
				}
			}
		}()
	}
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// ---------- Registered primitive Apply paths ----------

func TestApply_RegisteredPrimitives(t *testing.T) {
	t.Parallel()
	m := mask.New()
	assert.Equal(t, mask.FullRedactMarker, m.Apply("full_redact", "secret"))
	assert.Equal(t, "*****", m.Apply("same_length_mask", "hello"))
	assert.Equal(t, "", m.Apply("nullify", "secret"))

	h := m.Apply("deterministic_hash", "alice@example.com")
	assert.True(t, strings.HasPrefix(h, "sha256:"))
	assert.Equal(t, len("sha256:")+16, len(h))
}

func TestApply_SameLengthMask_HonoursInstanceMaskChar(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.Equal(t, "XXXXX", m.Apply("same_length_mask", "hello"))
}

func TestApply_SameLengthMask_ReflectsLateMaskCharChange(t *testing.T) {
	// Intentionally NOT t.Parallel — mutates global mask char.
	t.Cleanup(func() { mask.SetMaskChar(mask.DefaultMaskChar) })

	mask.SetMaskChar('#')
	assert.Equal(t, "#####", mask.Apply("same_length_mask", "hello"))
}

// TestPrimitives_NoPanicOnInvalidMaskRune guards the B1 fix: an invalid
// mask rune (negative value, lone surrogate, above unicode.MaxRune) used
// to panic the Builder.Grow path via a negative capacity argument. Every
// primitive that writes the mask rune must survive without panic AND must
// still produce a masked output — returning the original value would let
// a rune-validation regression silently leak data.
func TestPrimitives_NoPanicOnInvalidMaskRune(t *testing.T) {
	t.Parallel()
	badRunes := []rune{-1, 0xD800, 0x110000} // negative, lone surrogate, above MaxRune

	for _, bad := range badRunes {
		t.Run("", func(t *testing.T) {
			// SameLengthMask: output MUST have the same rune count as the
			// input (here 6) and MUST NOT be the original value.
			out := mask.SameLengthMask("secret", bad)
			assert.NotPanics(t, func() { _ = out })
			assert.NotEqual(t, "secret", out)
			assert.NotEmpty(t, out)

			// KeepFirstN: prefix preserved, tail masked and non-empty.
			out = mask.KeepFirstN("secret", 2, bad)
			assert.True(t, strings.HasPrefix(out, "se"), "got %q", out)
			assert.NotEqual(t, "secret", out)

			// KeepLastN: suffix preserved.
			out = mask.KeepLastN("secret", 2, bad)
			assert.True(t, strings.HasSuffix(out, "et"), "got %q", out)
			assert.NotEqual(t, "secret", out)

			// KeepFirstLast: both ends preserved, middle masked.
			out = mask.KeepFirstLast("hello world", 2, 2, bad)
			assert.True(t, strings.HasPrefix(out, "he"), "got %q", out)
			assert.True(t, strings.HasSuffix(out, "ld"), "got %q", out)
			assert.NotEqual(t, "hello world", out)

			// PreserveDelimiters: delimiter rune kept verbatim.
			out = mask.PreserveDelimiters("a-b", "-", bad)
			assert.Contains(t, out, "-", "delimiter lost; got %q", out)
			assert.NotEqual(t, "a-b", out)

			// ReducePrecision: numeric prefix preserved up to the dot+1 digit.
			out = mask.ReducePrecision("37.77", 1, bad)
			assert.True(t, strings.HasPrefix(out, "37.7"), "got %q", out)
		})
	}

	// Masker-level check: construct a Masker with an invalid mask rune and
	// run the same_length_mask registered rule. Output must still be masked.
	t.Run("masker level", func(t *testing.T) {
		m := mask.New(mask.WithMaskChar(-1))
		out := m.Apply("same_length_mask", "hello")
		assert.NotEqual(t, "hello", out)
		assert.NotEmpty(t, out)
	})
}

// TestPrimitives_InvalidUTF8NoPanic exercises every primitive that processes
// string contents with a deliberately malformed UTF-8 input. The library's
// "no panic on any input" contract is easy to break with a future refactor
// that drops rune-aware handling, so this test pins the behaviour down for
// the rune-iterating primitives.
func TestPrimitives_InvalidUTF8NoPanic(t *testing.T) {
	t.Parallel()
	const bad = "\xff\xfe\xfd"

	// None of these should panic; we do not assert on output shape because
	// invalid-UTF-8 semantics are explicitly rune-level (RuneError per bad
	// byte) and not part of the public contract.
	assert.NotPanics(t, func() { _ = mask.SameLengthMask(bad, '*') })
	assert.NotPanics(t, func() { _ = mask.KeepFirstN(bad, 1, '*') })
	assert.NotPanics(t, func() { _ = mask.KeepLastN(bad, 1, '*') })
	assert.NotPanics(t, func() { _ = mask.KeepFirstLast(bad, 1, 1, '*') })
	assert.NotPanics(t, func() { _ = mask.TruncateVisible(bad, 2) })
	assert.NotPanics(t, func() { _ = mask.PreserveDelimiters(bad, "@", '*') })
	assert.NotPanics(t, func() { _ = mask.ReducePrecision(bad, 2, '*') })
	assert.NotPanics(t, func() { _ = mask.DeterministicHash(bad) })
	assert.NotPanics(t, func() {
		_ = mask.DeterministicHashFunc(mask.WithSalt("k"), mask.WithSaltVersion("v1"), mask.WithAlgorithm(mask.SHA3_512))(bad)
	})
}

// ---------- Helpers ----------

// short renders s as a short printable identifier suitable for use as a
// subtest name.
func short(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) > 16 {
		return "len_" + strings.ReplaceAll(strings.ReplaceAll(s[:8], " ", "_"), "\n", "n") + "_trunc"
	}
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, " ", "_"), "\n", "n"), "\t", "t")
}
