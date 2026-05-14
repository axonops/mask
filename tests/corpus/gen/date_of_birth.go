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

// dateOfBirthGen exercises the date_of_birth masker. Recognised
// shapes: YYYY-MM-DD (ISO), YYYY/MM/DD, DD/MM/YYYY, MM/DD/YYYY.
// Year is preserved; month and day are masked. Slash form has a
// deliberate quirk: emits exactly 4 mask runes regardless of
// month-digit width (rules_identity.go:404-408). The corpus locks
// that as current behaviour.
type dateOfBirthGen struct{}

func (dateOfBirthGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	var inputs []string

	// ISO YYYY-MM-DD across a wide year span.
	for i := 0; i < 80; i++ {
		y := 1900 + r.IntN(150)
		m := 1 + r.IntN(12)
		d := 1 + r.IntN(28)
		inputs = append(inputs, fmt.Sprintf("%04d-%02d-%02d", y, m, d))
	}

	// YYYY/MM/DD.
	for i := 0; i < 50; i++ {
		y := 1900 + r.IntN(150)
		m := 1 + r.IntN(12)
		d := 1 + r.IntN(28)
		inputs = append(inputs, fmt.Sprintf("%04d/%02d/%02d", y, m, d))
	}

	// DD/MM/YYYY (European).
	for i := 0; i < 50; i++ {
		y := 1900 + r.IntN(150)
		m := 1 + r.IntN(12)
		d := 1 + r.IntN(28)
		inputs = append(inputs, fmt.Sprintf("%02d/%02d/%04d", d, m, y))
	}

	// MM/DD/YYYY (US) — same shape as DD/MM but different semantics;
	// the rule can't distinguish, so it treats both as "slash form".
	for i := 0; i < 50; i++ {
		y := 1900 + r.IntN(150)
		m := 1 + r.IntN(12)
		d := 1 + r.IntN(28)
		inputs = append(inputs, fmt.Sprintf("%02d/%02d/%04d", m, d, y))
	}

	// Edge: zero-padded vs not — rule expects 2-digit month/day.
	for i := 0; i < 15; i++ {
		y := 1900 + r.IntN(150)
		m := 1 + r.IntN(9) // single-digit month
		d := 1 + r.IntN(9)
		inputs = append(inputs, fmt.Sprintf("%d-%d-%d", y, m, d))
	}

	// Edge: 29th, 30th, 31st boundary days.
	for d := 28; d <= 31; d++ {
		for m := 1; m <= 12; m++ {
			inputs = append(inputs, fmt.Sprintf("2000-%02d-%02d", m, d))
		}
	}

	// Edge: month-13, day-32 (invalid but rule probably still masks).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("2000-%02d-%02d", 13+r.IntN(5), 1))
		inputs = append(inputs, fmt.Sprintf("2000-%02d-%02d", 1, 32+r.IntN(5)))
	}

	// Edge: ambiguous numeric without separators — fails closed.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomDigits(r, 8))
	}

	// Edge: time-bearing — fails closed.
	for i := 0; i < 10; i++ {
		y := 1900 + r.IntN(150)
		m := 1 + r.IntN(12)
		d := 1 + r.IntN(28)
		inputs = append(inputs, fmt.Sprintf("%04d-%02d-%02dT12:34:56Z", y, m, d))
	}

	// Edge: short year (2 digits) — fails closed.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%02d-%02d-%02d", r.IntN(100), r.IntN(13), r.IntN(31)))
	}

	// Edge: text date — fails closed.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "March 15, 1985")
		inputs = append(inputs, "15 March 1985")
	}

	return uniqueLinesToPairs(inputs)
}

func init() {
	register("date_of_birth", dateOfBirthGen{})
}
