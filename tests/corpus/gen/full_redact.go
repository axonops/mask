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

//go:build corpusgen

package main

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// fullRedactGen emits a wide variety of inputs — every one collapses
// to [REDACTED]. The point is not to exercise the rule (it has no
// branches) but to lock the invariant that no input shape, however
// adversarial, can leak even one character.
type fullRedactGen struct{}

func (fullRedactGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedFullRedact))

	var inputs []string

	// Realistic-looking sensitive value shapes.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d-%02d-%04d",
			r.IntN(1000), r.IntN(100), r.IntN(10000)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomCardLikeDigits(r))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("user%d@example.com", r.IntN(1_000_000)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("https://example.com/path/%d?token=%s",
			r.IntN(10_000), randomHex(r, 16)))
	}

	// Edge: ASCII printable strings of varying length.
	for i := 0; i < 40; i++ {
		inputs = append(inputs, randomASCII(r, 1+r.IntN(60)))
	}

	// Edge: very long inputs (well below the 64 KiB line cap).
	for i := 0; i < 5; i++ {
		inputs = append(inputs, strings.Repeat("X", 1024*(1+i)))
	}

	// Edge: unicode of varying scripts.
	scripts := []string{"日本語テスト", "안녕하세요", "Привет мир", "مرحبا بالعالم", "שלום עולם", "Ελληνικά"}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, scripts[i%len(scripts)]+fmt.Sprintf("-%d", i))
	}

	// Edge: emoji and combining marks.
	emoji := []string{"😀", "👨‍👩‍👧‍👦", "🇬🇧", "🏳️‍🌈", "👋🏽"}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, emoji[i%len(emoji)]+fmt.Sprintf("%d", i))
	}

	// Edge: already-redacted values.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, strings.Repeat("[REDACTED]", 1+r.IntN(5)))
	}

	// Edge: whitespace-only inputs.
	for n := 1; n <= 8; n++ {
		inputs = append(inputs, strings.Repeat(" ", n))
	}

	// Edge: numeric edge values.
	inputs = append(inputs, "0", "-0", "1e10", "3.14159", "NaN", "Inf", "-Inf",
		"9223372036854775807", "18446744073709551615")

	inputs = uniqueLines(inputs)
	out := make([]Pair, len(inputs))
	for i, s := range inputs {
		out[i] = Pair{Input: s}
	}
	return out
}

// randomCardLikeDigits returns a 13–19 digit run with hyphens at the
// common 4-4-4-4 boundary — close to a card PAN shape.
func randomCardLikeDigits(r *rand.Rand) string {
	groups := []int{4, 4, 4, 4}
	if r.IntN(3) == 0 {
		groups = append(groups, 1+r.IntN(3))
	}
	parts := make([]string, len(groups))
	for i, n := range groups {
		parts[i] = randomDigits(r, n)
	}
	return strings.Join(parts, "-")
}

// randomHex returns n lower-case hex characters.
func randomHex(r *rand.Rand, n int) string {
	const alphabet = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(16)]
	}
	return string(b)
}

// randomASCII returns n printable ASCII characters in [0x20, 0x7E],
// excluding the tab character (would be confused for a fixture
// separator), the comment-line leader '#' as the first character (the
// harness would swallow the line as a comment), and the backslash
// (which would be re-interpreted as an escape sequence in any file
// carrying the `# corpus: escaped` pragma).
func randomASCII(r *rand.Rand, n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		c := byte(0x20 + r.IntN(0x7E-0x20+1))
		switch {
		case c == '\t' || c == '\\':
			c = ' '
		case i == 0 && c == '#':
			c = 'A'
		}
		b[i] = c
	}
	return string(b)
}

const seedFullRedact uint64 = 0xDEC0DE02

func init() {
	register("full_redact", fullRedactGen{})
}
