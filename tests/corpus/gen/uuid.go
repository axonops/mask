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

// uuidGen — 8-4-4-4-12 hex digits.
type uuidGen struct{}

func (uuidGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string

	// Canonical lower-case.
	for i := 0; i < 100; i++ {
		inputs = append(inputs, fmt.Sprintf("%s-%s-%s-%s-%s",
			randomHextet(r, 8), randomHextet(r, 4),
			randomHextet(r, 4), randomHextet(r, 4),
			randomHextet(r, 12)))
	}
	// Upper-case.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, strings.ToUpper(fmt.Sprintf("%s-%s-%s-%s-%s",
			randomHextet(r, 8), randomHextet(r, 4),
			randomHextet(r, 4), randomHextet(r, 4),
			randomHextet(r, 12))))
	}
	// Mixed case.
	for i := 0; i < 20; i++ {
		s := fmt.Sprintf("%s-%s-%s-%s-%s",
			randomHextet(r, 8), randomHextet(r, 4),
			randomHextet(r, 4), randomHextet(r, 4),
			randomHextet(r, 12))
		b := []byte(s)
		for j := range b {
			if r.IntN(2) == 0 && b[j] >= 'a' && b[j] <= 'f' {
				b[j] = b[j] - 'a' + 'A'
			}
		}
		inputs = append(inputs, string(b))
	}
	// Brace-wrapped (Microsoft GUID style).
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("{%s-%s-%s-%s-%s}",
			randomHextet(r, 8), randomHextet(r, 4),
			randomHextet(r, 4), randomHextet(r, 4),
			randomHextet(r, 12)))
	}
	// No-dash form.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomHextet(r, 32))
	}
	// Edge: wrong group widths.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, fmt.Sprintf("%s-%s-%s-%s-%s",
			randomHextet(r, 9), randomHextet(r, 4),
			randomHextet(r, 4), randomHextet(r, 4),
			randomHextet(r, 11)))
	}
	// Edge: non-hex characters.
	for i := 0; i < 10; i++ {
		base := fmt.Sprintf("%s-%s-%s-%s-%s",
			randomHextet(r, 8), randomHextet(r, 4),
			randomHextet(r, 4), randomHextet(r, 4),
			randomHextet(r, 12))
		b := []byte(base)
		b[r.IntN(len(b))] = byte('g' + r.IntN(8))
		inputs = append(inputs, string(b))
	}
	return uniqueLinesToPairs(inputs)
}

func init() { register("uuid", uuidGen{}) }
