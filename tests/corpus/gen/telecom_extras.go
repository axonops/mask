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

// imeiGen — 15 digits, no separators.
type imeiGen struct{}

func (imeiGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 100; i++ {
		inputs = append(inputs, randomDigits(r, 15))
	}
	// Common TAC prefixes (first 8 digits identify model).
	for _, tac := range []string{"35355109", "35325207", "01193300", "86755603"} {
		for i := 0; i < 8; i++ {
			inputs = append(inputs, tac+randomDigits(r, 7))
		}
	}
	// Edge: 16-digit IMEISV form (likely fails closed).
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 16))
	}
	// Edge: hyphenated 8-6-1.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%s-%s-%s",
			randomDigits(r, 8), randomDigits(r, 6), randomDigits(r, 1)))
	}
	// Edge: too short.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 12+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

// imsiGen — 14 or 15 digits, MCC+MNC+MSIN.
type imsiGen struct{}

func (imsiGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, randomDigits(r, 15))
	}
	for i := 0; i < 40; i++ {
		inputs = append(inputs, randomDigits(r, 14))
	}
	// Edge: wrong length.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 13))
		inputs = append(inputs, randomDigits(r, 16))
	}
	return uniqueLinesToPairs(inputs)
}

// msisdnGen — phone number for mobile lines, 8-15 digits with
// optional + prefix.
type msisdnGen struct{}

func (msisdnGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, "+"+randomDigits(r, 10+r.IntN(5)))
	}
	for i := 0; i < 40; i++ {
		inputs = append(inputs, randomDigits(r, 10+r.IntN(5)))
	}
	// Edge: too short.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "+"+randomDigits(r, 5+r.IntN(3)))
	}
	// Edge: too long.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "+"+randomDigits(r, 16+r.IntN(3)))
	}
	// Edge: contains separators (likely fails closed).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("+%s-%s-%s",
			randomDigits(r, 2), randomDigits(r, 4), randomDigits(r, 6)))
	}
	return uniqueLinesToPairs(inputs)
}

func init() {
	register("imei", imeiGen{})
	register("imsi", imsiGen{})
	register("msisdn", msisdnGen{})
}
