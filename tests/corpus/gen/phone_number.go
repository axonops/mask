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
)

// phoneNumberGen produces a mix of international (`+CC...`), ITU-T
// (`00CC...`), and domestic phone-number shapes plus a stream of
// malformed inputs that exercise the fail-closed fallback. The
// underlying maskPhoneNumber preserves a leading +NN or 00NN country
// code, masks the middle digits, keeps the last 4 digits, and keeps
// structural separators (spaces, hyphens, dots, parentheses) verbatim.
type phoneNumberGen struct{}

func (phoneNumberGen) Generate(seed uint64) []Pair {
	// Deterministic per-rule seed — same output across machines.
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	// Country codes covering 1-, 2-, and 3-digit forms.
	ccs := []string{"1", "44", "33", "49", "61", "234", "255", "353", "420", "971"}
	// Separators that the rule treats as structure-only.
	seps := []string{" ", "-", ".", "  ", " - ", " ", "-"}

	var inputs []string

	// + prefix, separator after CC, varied middle/tail widths.
	for i := 0; i < 60; i++ {
		cc := ccs[r.IntN(len(ccs))]
		sep := seps[r.IntN(len(seps))]
		mid := randomDigits(r, 4+r.IntN(6))
		tail := randomDigits(r, 4)
		inputs = append(inputs, fmt.Sprintf("+%s%s%s %s", cc, sep, mid, tail))
	}

	// + prefix with single inner separator instead of two.
	for i := 0; i < 40; i++ {
		cc := ccs[r.IntN(len(ccs))]
		mid := randomDigits(r, 7+r.IntN(4))
		inputs = append(inputs, fmt.Sprintf("+%s %s", cc, mid))
	}

	// 00 prefix compact form — no separator between CC and body.
	for i := 0; i < 40; i++ {
		cc := ccs[r.IntN(len(ccs))]
		body := randomDigits(r, 8+r.IntN(4))
		inputs = append(inputs, fmt.Sprintf("00%s%s", cc, body))
	}

	// 00 prefix with separator after CC.
	for i := 0; i < 40; i++ {
		cc := ccs[r.IntN(len(ccs))]
		sep := seps[r.IntN(len(seps))]
		body := randomDigits(r, 8+r.IntN(4))
		inputs = append(inputs, fmt.Sprintf("00%s%s%s", cc, sep, body))
	}

	// Domestic — no prefix, just digits with separators.
	for i := 0; i < 40; i++ {
		body := randomDigits(r, 9+r.IntN(3))
		inputs = append(inputs, body)
	}

	// Parenthesised area-code shapes (US/CA/Latin America style).
	for i := 0; i < 30; i++ {
		area := randomDigits(r, 3)
		mid := randomDigits(r, 3)
		tail := randomDigits(r, 4)
		inputs = append(inputs, fmt.Sprintf("(%s) %s-%s", area, mid, tail))
	}

	// Hyphen-rich shapes — common formatting.
	for i := 0; i < 30; i++ {
		a := randomDigits(r, 3)
		b := randomDigits(r, 3)
		c := randomDigits(r, 4)
		inputs = append(inputs, fmt.Sprintf("%s-%s-%s", a, b, c))
	}

	// Dotted forms — Continental European convention.
	for i := 0; i < 30; i++ {
		a := randomDigits(r, 3)
		b := randomDigits(r, 3)
		c := randomDigits(r, 4)
		inputs = append(inputs, fmt.Sprintf("%s.%s.%s", a, b, c))
	}

	// Edge: short bodies that should fall back to SameLengthMask.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomDigits(r, 3+r.IntN(4)))
	}

	// Edge: invalid shapes — letters mixed in, leading zeros that
	// don't form a recognised prefix. These must fail closed.
	letters := []string{"abc", "tel:", "TEL", "phone", "x123", "ext.567"}
	for _, lp := range letters {
		for i := 0; i < 5; i++ {
			inputs = append(inputs, lp+randomDigits(r, 6+r.IntN(4)))
		}
	}

	// Edge: + with no separator after CC (rejected for + per spec).
	for i := 0; i < 15; i++ {
		cc := ccs[r.IntN(len(ccs))]
		body := randomDigits(r, 7+r.IntN(4))
		inputs = append(inputs, fmt.Sprintf("+%s%s", cc, body))
	}

	// Edge: 00 prefix with leading zero CC (must fail per
	// split00Prefix's `v[2] != '0'` rule).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "000"+randomDigits(r, 7+r.IntN(3)))
	}

	// Dedup — randomDigits can collide for short widths.
	inputs = uniqueLines(inputs)

	out := make([]Pair, len(inputs))
	for i, s := range inputs {
		out[i] = Pair{Input: s}
	}
	return out
}

// randomDigits draws n ASCII decimal digits from r.
func randomDigits(r *rand.Rand, n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + r.IntN(10))
	}
	return string(b)
}

// seedPhoneNumber is a per-generator seed constant. Mixing it with a
// shared base spreads PCG sequences across generators while keeping
// each one deterministic across machines and re-runs.

func init() {
	register("phone_number", phoneNumberGen{})
}
