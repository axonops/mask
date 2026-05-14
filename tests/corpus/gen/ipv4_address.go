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

// ipv4AddressGen — four 0-255 octets separated by dots.
type ipv4AddressGen struct{}

func (ipv4AddressGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedIPv4Address))
	var inputs []string

	for i := 0; i < 120; i++ {
		inputs = append(inputs, fmt.Sprintf("%d.%d.%d.%d",
			r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	// Common well-known addresses.
	inputs = append(inputs,
		"0.0.0.0", "127.0.0.1", "255.255.255.255",
		"192.168.1.1", "10.0.0.1", "172.16.0.1",
		"8.8.8.8", "1.1.1.1", "169.254.1.1",
	)
	// Boundary octet values.
	for o := 0; o < 4; o++ {
		for _, v := range []int{0, 1, 127, 128, 254, 255} {
			parts := []int{r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256)}
			parts[o] = v
			inputs = append(inputs, fmt.Sprintf("%d.%d.%d.%d", parts[0], parts[1], parts[2], parts[3]))
		}
	}
	// Edge: octet > 255.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, fmt.Sprintf("%d.%d.%d.%d",
			256+r.IntN(100), r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	// Edge: too few octets.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%d.%d.%d",
			r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	// Edge: too many octets.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%d.%d.%d.%d.%d",
			r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	// Edge: letters in octet.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%da.%d.%d.%d",
			r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	// Edge: leading zeros (some parsers interpret as octal).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d.%03d.%03d.%03d",
			r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	// Edge: trailing dot.
	for i := 0; i < 5; i++ {
		inputs = append(inputs, fmt.Sprintf("%d.%d.%d.%d.",
			r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256)))
	}
	return uniqueLinesToPairs(inputs)
}

const seedIPv4Address uint64 = 0xDEC0DE15

func init() { register("ipv4_address", ipv4AddressGen{}) }
