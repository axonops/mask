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

// postalCodeGen exercises the shape-aware postal_code masker — UK
// (keep outward code, mask inward), US (keep first 3, mask last 2 of
// a 5-digit ZIP), Canada (keep FSA). Anything else falls back to
// same-length mask.
//
// NOTE: BUG? candidate per the harness plan — the UK validator
// accepts shapes that aren't real UK outward codes (e.g. A1AA).
// Fixtures here will lock current behaviour; if a generated case
// looks wrong on review, leave a `# BUG?` comment in the canonical
// section and file a follow-up.
type postalCodeGen struct{}

func (postalCodeGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedPostalCode))

	var inputs []string

	// UK — outward + inward shapes, spaced and unspaced.
	ukOutwards := []string{"SW1A", "EC1A", "W1A", "M1", "B33", "CR2", "DN55", "L1", "EH1", "BT1", "GL51", "OX1", "CB2"}
	for i := 0; i < 60; i++ {
		out := ukOutwards[r.IntN(len(ukOutwards))]
		inward := fmt.Sprintf("%d%s%s", r.IntN(10), randomUpper(r, 1), randomUpper(r, 1))
		spaced := r.IntN(2) == 0
		if spaced {
			inputs = append(inputs, out+" "+inward)
		} else {
			inputs = append(inputs, out+inward)
		}
	}

	// US — 5-digit ZIP and ZIP+4 (ZIP+4 should fall back since
	// rule only knows the bare 5-digit form).
	for i := 0; i < 60; i++ {
		inputs = append(inputs, randomDigits(r, 5))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 5)+"-"+randomDigits(r, 4))
	}

	// Canada — A1A 1A1 (FSA + LDU).
	for i := 0; i < 40; i++ {
		fsa := randomUpper(r, 1) + fmt.Sprintf("%d", r.IntN(10)) + randomUpper(r, 1)
		ldu := fmt.Sprintf("%d", r.IntN(10)) + randomUpper(r, 1) + fmt.Sprintf("%d", r.IntN(10))
		spaced := r.IntN(2) == 0
		if spaced {
			inputs = append(inputs, fsa+" "+ldu)
		} else {
			inputs = append(inputs, fsa+ldu)
		}
	}

	// Other countries — fail closed.
	// German 5-digit (looks like US ZIP but no way to disambiguate)
	// French 5-digit
	// Australian 4-digit
	// Japanese 7-digit with hyphen 123-4567
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomDigits(r, 3)+"-"+randomDigits(r, 4))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomDigits(r, 4))
	}
	// Brazilian 8-digit 12345-678.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 5)+"-"+randomDigits(r, 3))
	}

	// Edge: lower-case UK outward (rule case sensitivity).
	for i := 0; i < 15; i++ {
		out := strings.ToLower(ukOutwards[r.IntN(len(ukOutwards))])
		inward := fmt.Sprintf("%d%s%s",
			r.IntN(10),
			strings.ToLower(randomUpper(r, 1)),
			strings.ToLower(randomUpper(r, 1)))
		inputs = append(inputs, out+" "+inward)
	}

	// Edge: trailing whitespace, leading whitespace.
	for i := 0; i < 10; i++ {
		out := ukOutwards[r.IntN(len(ukOutwards))]
		inward := fmt.Sprintf("%d%s%s", r.IntN(10), randomUpper(r, 1), randomUpper(r, 1))
		inputs = append(inputs, " "+out+" "+inward)
		inputs = append(inputs, out+" "+inward+" ")
	}

	// Edge: too short / too long.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 2))
		inputs = append(inputs, randomDigits(r, 8))
	}

	return uniqueLinesToPairs(inputs)
}

// randomUpper emits n upper-case ASCII letters.
func randomUpper(r *rand.Rand, n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('A' + r.IntN(26))
	}
	return string(b)
}

const seedPostalCode uint64 = 0xDEC0DE09

func init() {
	register("postal_code", postalCodeGen{})
}
