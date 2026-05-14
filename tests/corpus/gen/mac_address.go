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
	"strings"
)

// macAddressGen — 12 hex digits in 6 groups of 2.
type macAddressGen struct{}

func (macAddressGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string

	// Colon-separated lowercase.
	for i := 0; i < 60; i++ {
		parts := make([]string, 6)
		for j := range parts {
			parts[j] = randomHextet(r, 2)
		}
		inputs = append(inputs, strings.Join(parts, ":"))
	}
	// Colon-separated uppercase.
	for i := 0; i < 30; i++ {
		parts := make([]string, 6)
		for j := range parts {
			parts[j] = strings.ToUpper(randomHextet(r, 2))
		}
		inputs = append(inputs, strings.Join(parts, ":"))
	}
	// Hyphen-separated.
	for i := 0; i < 30; i++ {
		parts := make([]string, 6)
		for j := range parts {
			parts[j] = randomHextet(r, 2)
		}
		inputs = append(inputs, strings.Join(parts, "-"))
	}
	// Dot-separated 3-group (Cisco).
	for i := 0; i < 20; i++ {
		parts := make([]string, 3)
		for j := range parts {
			parts[j] = randomHextet(r, 4)
		}
		inputs = append(inputs, strings.Join(parts, "."))
	}
	// No separators.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomHextet(r, 12))
	}
	// Edge: wrong length.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomHextet(r, 8))
		inputs = append(inputs, randomHextet(r, 14))
	}
	// Edge: non-hex character.
	for i := 0; i < 10; i++ {
		parts := make([]string, 6)
		for j := range parts {
			parts[j] = randomHextet(r, 2)
		}
		parts[r.IntN(6)] = "gg"
		inputs = append(inputs, strings.Join(parts, ":"))
	}
	return uniqueLinesToPairs(inputs)
}

func init() { register("mac_address", macAddressGen{}) }
