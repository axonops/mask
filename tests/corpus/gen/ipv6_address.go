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

// ipv6AddressGen exercises the IPv6 masker. Inputs cover:
//   - full 8-hextet addresses (lower- and upper-case)
//   - compressed `::` forms (left, right, middle, all-zero)
//   - boundary hextet widths (1, 2, 3, 4)
//   - rejected shapes: IPv4-embedded (contains '.'), zone IDs ('%'),
//     too many colons, non-hex characters
type ipv6AddressGen struct{}

func (ipv6AddressGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedIPv6Address))

	var inputs []string

	// Full 8-hextet addresses with varying digit widths.
	for i := 0; i < 80; i++ {
		parts := make([]string, 8)
		for j := range parts {
			parts[j] = randomHextet(r, 1+r.IntN(4))
		}
		inputs = append(inputs, strings.Join(parts, ":"))
	}

	// Mixed case full addresses.
	for i := 0; i < 30; i++ {
		parts := make([]string, 8)
		for j := range parts {
			parts[j] = randomHextet(r, 4)
		}
		s := strings.Join(parts, ":")
		if r.IntN(2) == 0 {
			s = strings.ToUpper(s)
		}
		inputs = append(inputs, s)
	}

	// Compressed `::` forms — leading zeros.
	for i := 0; i < 40; i++ {
		left := r.IntN(3) // 0..2 leading groups
		right := 1 + r.IntN(5)
		var leftParts, rightParts []string
		for j := 0; j < left; j++ {
			leftParts = append(leftParts, randomHextet(r, 1+r.IntN(4)))
		}
		for j := 0; j < right; j++ {
			rightParts = append(rightParts, randomHextet(r, 1+r.IntN(4)))
		}
		s := strings.Join(leftParts, ":") + "::" + strings.Join(rightParts, ":")
		inputs = append(inputs, s)
	}

	// Common literals — loopback, link-local, all-zeros.
	inputs = append(inputs,
		"::1",
		"::",
		"::ffff",
		"fe80::1",
		"fe80::200:5eff:fe00:5318",
		"2001:db8::",
		"2001:db8::1",
		"2001:db8:85a3::8a2e:370:7334",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"FE80:0000:0000:0000:0202:B3FF:FE1E:8329",
	)

	// Trailing compressed.
	for i := 0; i < 20; i++ {
		groups := 1 + r.IntN(5)
		parts := make([]string, groups)
		for j := range parts {
			parts[j] = randomHextet(r, 1+r.IntN(4))
		}
		inputs = append(inputs, strings.Join(parts, ":")+"::")
	}

	// Leading compressed.
	for i := 0; i < 20; i++ {
		groups := 1 + r.IntN(5)
		parts := make([]string, groups)
		for j := range parts {
			parts[j] = randomHextet(r, 1+r.IntN(4))
		}
		inputs = append(inputs, "::"+strings.Join(parts, ":"))
	}

	// Edge: IPv4-embedded forms (must fail closed — rule rejects '.').
	for i := 0; i < 20; i++ {
		ipv4 := fmt.Sprintf("%d.%d.%d.%d", r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256))
		inputs = append(inputs, "::ffff:"+ipv4)
		inputs = append(inputs, "2001:db8::"+ipv4)
	}

	// Edge: zone identifiers (must fail closed — rule rejects '%').
	for i := 0; i < 10; i++ {
		zone := []string{"eth0", "en0", "lo", "wlan0"}[r.IntN(4)]
		inputs = append(inputs, "fe80::1%"+zone)
	}

	// Edge: hextet too long (5 hex digits) — fail closed.
	for i := 0; i < 15; i++ {
		parts := make([]string, 8)
		for j := range parts {
			parts[j] = randomHextet(r, 4)
		}
		parts[r.IntN(8)] = randomHextet(r, 5)
		inputs = append(inputs, strings.Join(parts, ":"))
	}

	// Edge: non-hex characters in a hextet — fail closed.
	for i := 0; i < 15; i++ {
		parts := make([]string, 8)
		for j := range parts {
			parts[j] = randomHextet(r, 4)
		}
		junk := []string{"g", "z", "@", "_"}[r.IntN(4)]
		parts[r.IntN(8)] = randomHextet(r, 3) + junk
		inputs = append(inputs, strings.Join(parts, ":"))
	}

	// Edge: too many colons — fail closed.
	for i := 0; i < 10; i++ {
		parts := make([]string, 9)
		for j := range parts {
			parts[j] = randomHextet(r, 4)
		}
		inputs = append(inputs, strings.Join(parts, ":"))
	}

	// Edge: too few colons (no `::`).
	for i := 0; i < 10; i++ {
		parts := make([]string, 5+r.IntN(3))
		for j := range parts {
			parts[j] = randomHextet(r, 4)
		}
		inputs = append(inputs, strings.Join(parts, ":"))
	}

	return uniqueLinesToPairs(inputs)
}

// randomHextet emits n lower-case hex digits.
func randomHextet(r *rand.Rand, n int) string {
	const alpha = "0123456789abcdef"
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return string(b)
}

const seedIPv6Address uint64 = 0xDEC0DE08

func init() {
	register("ipv6_address", ipv6AddressGen{})
}
