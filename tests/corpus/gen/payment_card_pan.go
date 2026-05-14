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
	"math/rand/v2"
)

// panInputs builds the shared input set for the three payment_card_pan
// variants. All three rules use maskPANWindow with the same separator
// and digit-count validation; only the keep window differs. Sharing
// the input set lets reviewers verify that the rule family is
// internally consistent (an input that fails closed for one variant
// fails closed for all three).
func panInputs(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	var inputs []string

	// Well-formed PANs at the common lengths: 16 (Visa/MC), 15 (Amex),
	// 19 (Maestro/UnionPay extended).
	for i := 0; i < 60; i++ {
		inputs = append(inputs, randomDigits(r, 16))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 15))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 19))
	}
	// Edge lengths: 13 (legacy Visa) and 14.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 13))
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 14))
	}

	// Hyphen-grouped 4-4-4-4.
	for i := 0; i < 40; i++ {
		inputs = append(inputs, groupBy(randomDigits(r, 16), 4, "-"))
	}
	// Space-grouped 4-4-4-4.
	for i := 0; i < 40; i++ {
		inputs = append(inputs, groupBy(randomDigits(r, 16), 4, " "))
	}
	// 4-6-5 grouping common for Amex.
	for i := 0; i < 20; i++ {
		d := randomDigits(r, 15)
		inputs = append(inputs, d[:4]+"-"+d[4:10]+"-"+d[10:])
	}

	// Edge: too short (< 13 digits) — fail closed.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 6+r.IntN(6)))
	}
	// Edge: too long (> 19 digits) — fail closed.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 20+r.IntN(6)))
	}

	// Edge: letters mixed in — fail closed.
	for i := 0; i < 20; i++ {
		d := []byte(randomDigits(r, 16))
		d[r.IntN(len(d))] = byte('A' + r.IntN(26))
		inputs = append(inputs, string(d))
	}

	// Edge: unicode digit (e.g. Devanagari १) — must fail closed
	// because the rule requires ASCII digits.
	for i := 0; i < 5; i++ {
		d := randomDigits(r, 15)
		// Insert a non-ASCII digit at a random position.
		pos := r.IntN(len(d))
		inputs = append(inputs, d[:pos]+"१"+d[pos:])
	}

	// Edge: separators other than space/hyphen.
	for _, sep := range []string{".", "/", "_"} {
		for i := 0; i < 10; i++ {
			inputs = append(inputs, groupBy(randomDigits(r, 16), 4, sep))
		}
	}

	return uniqueLinesToPairs(inputs)
}

type paymentCardPANGen struct{}

func (paymentCardPANGen) Generate(seed uint64) []Pair { return panInputs(seed) }

type paymentCardPANFirst6Gen struct{}

func (paymentCardPANFirst6Gen) Generate(seed uint64) []Pair { return panInputs(seed) }

type paymentCardPANLast4Gen struct{}

func (paymentCardPANLast4Gen) Generate(seed uint64) []Pair { return panInputs(seed) }

// uniqueLinesToPairs dedups and wraps a slice of inputs as Pair values.
func uniqueLinesToPairs(in []string) []Pair {
	in = uniqueLines(in)
	out := make([]Pair, len(in))
	for i, s := range in {
		out[i] = Pair{Input: s}
	}
	return out
}

func init() {
	register("payment_card_pan", paymentCardPANGen{})
	register("payment_card_pan_first6", paymentCardPANFirst6Gen{})
	register("payment_card_pan_last4", paymentCardPANLast4Gen{})
}
