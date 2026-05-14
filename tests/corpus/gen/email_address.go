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

// emailAddressGen produces well-formed and malformed email shapes.
// The rule keeps the first character of the local part verbatim,
// masks the rest of the local part, and preserves the @domain part
// in full. Malformed shapes (no @, multiple @, empty local part,
// etc.) fail closed to same-length mask.
type emailAddressGen struct{}

func (emailAddressGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedEmailAddress))

	localChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+"
	domains := []string{
		"example.com", "example.org", "test.io", "company.co.uk",
		"sub.example.com", "deep.sub.example.com", "localhost",
		"university.edu", "mail.tld", "tld",
	}

	var inputs []string

	// Well-formed mailboxes of varied local-part length.
	for i := 0; i < 80; i++ {
		n := 1 + r.IntN(18)
		local := make([]byte, n)
		for j := range local {
			local[j] = localChars[r.IntN(len(localChars))]
		}
		inputs = append(inputs, string(local)+"@"+domains[r.IntN(len(domains))])
	}

	// Single-character local parts — minimum-information case.
	for _, c := range "abcde0123" {
		for _, d := range domains[:5] {
			inputs = append(inputs, string(c)+"@"+d)
		}
	}

	// Subaddress (+tag) and dot-separated locals.
	for i := 0; i < 30; i++ {
		base := fmt.Sprintf("user%d", r.IntN(1_000_000))
		tag := fmt.Sprintf("tag%d", r.IntN(100))
		inputs = append(inputs, base+"+"+tag+"@"+domains[r.IntN(len(domains))])
	}
	for i := 0; i < 30; i++ {
		first := []string{"alice", "bob", "carol", "dan", "erin"}[r.IntN(5)]
		last := []string{"smith", "jones", "patel", "khan", "garcia"}[r.IntN(5)]
		inputs = append(inputs, first+"."+last+"@"+domains[r.IntN(len(domains))])
	}

	// Uppercase, mixed-case locals.
	for i := 0; i < 30; i++ {
		s := []byte{}
		for j := 0; j < 6+r.IntN(6); j++ {
			c := localChars[r.IntN(26)] // a-z
			if r.IntN(2) == 0 {
				c = c - 'a' + 'A'
			}
			s = append(s, c)
		}
		inputs = append(inputs, string(s)+"@"+domains[r.IntN(len(domains))])
	}

	// Numeric-only locals.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomDigits(r, 1+r.IntN(8))+"@"+domains[r.IntN(len(domains))])
	}

	// Edge: deep subdomains.
	for i := 0; i < 10; i++ {
		parts := []string{}
		for j := 0; j < 2+r.IntN(4); j++ {
			parts = append(parts, fmt.Sprintf("sub%d", r.IntN(100)))
		}
		inputs = append(inputs, fmt.Sprintf("user%d@%s.example.com", r.IntN(100), strings.Join(parts, ".")))
	}

	// Malformed: no '@'.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("noatsign%d", r.IntN(10000)))
	}

	// Malformed: empty local part.
	for _, d := range domains[:5] {
		inputs = append(inputs, "@"+d)
	}

	// Malformed: empty domain part.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("user%d@", r.IntN(10000)))
	}

	// Malformed: multiple @ characters.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("user@%d@example.com", r.IntN(100)))
	}

	// Edge: whitespace inside email (must fail closed).
	for i := 0; i < 5; i++ {
		inputs = append(inputs, fmt.Sprintf("user %d@example.com", r.IntN(100)))
	}

	inputs = uniqueLines(inputs)
	out := make([]Pair, len(inputs))
	for i, s := range inputs {
		out[i] = Pair{Input: s}
	}
	return out
}

const seedEmailAddress uint64 = 0xDEC0DE03

func init() {
	register("email_address", emailAddressGen{})
}
