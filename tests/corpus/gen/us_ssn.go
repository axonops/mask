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

// usSSNGen — preserves the last 4 digits of a 9-digit US SSN. Accepts
// `AAA-GG-SSSS` and `AAAGGSSSS`.
type usSSNGen struct{}

func (usSSNGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedUSSSN))
	var inputs []string

	// Canonical hyphenated.
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d-%02d-%04d",
			r.IntN(1000), r.IntN(100), r.IntN(10000)))
	}
	// Compact.
	for i := 0; i < 50; i++ {
		inputs = append(inputs, randomDigits(r, 9))
	}
	// Space-separated.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d %02d %04d",
			r.IntN(1000), r.IntN(100), r.IntN(10000)))
	}
	// Edge: too short.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 6+r.IntN(2)))
	}
	// Edge: too long.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 10+r.IntN(3)))
	}
	// Edge: letters in body.
	for i := 0; i < 10; i++ {
		d := []byte(randomDigits(r, 9))
		d[r.IntN(9)] = byte('A' + r.IntN(26))
		inputs = append(inputs, string(d))
	}
	// Edge: wrong separator.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d.%02d.%04d",
			r.IntN(1000), r.IntN(100), r.IntN(10000)))
	}
	return uniqueLinesToPairs(inputs)
}

const seedUSSSN uint64 = 0xDEC0DE12

func init() { register("us_ssn", usSSNGen{}) }
