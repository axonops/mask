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

// caSINGen — 9-digit Canadian SIN, AAA-BBB-CCC and AAABBBCCC.
type caSINGen struct{}

func (caSINGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedCASIN))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d-%03d-%03d", r.IntN(1000), r.IntN(1000), r.IntN(1000)))
	}
	for i := 0; i < 50; i++ {
		inputs = append(inputs, randomDigits(r, 9))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d %03d %03d", r.IntN(1000), r.IntN(1000), r.IntN(1000)))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 6+r.IntN(2)))  // too short
		inputs = append(inputs, randomDigits(r, 10+r.IntN(3))) // too long
	}
	return uniqueLinesToPairs(inputs)
}

// ukNINOGen — AB123456C and AB 12 34 56 C.
type ukNINOGen struct{}

func (ukNINOGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedUKNINO))
	var inputs []string
	for i := 0; i < 60; i++ {
		inputs = append(inputs, fmt.Sprintf("%s%s%06d%s",
			randomUpper(r, 1), randomUpper(r, 1),
			r.IntN(1_000_000), randomUpper(r, 1)))
	}
	for i := 0; i < 40; i++ {
		inputs = append(inputs, fmt.Sprintf("%s%s %02d %02d %02d %s",
			randomUpper(r, 1), randomUpper(r, 1),
			r.IntN(100), r.IntN(100), r.IntN(100),
			randomUpper(r, 1)))
	}
	// Lower-case (likely fails closed).
	for i := 0; i < 15; i++ {
		s := fmt.Sprintf("%s%s%06d%s",
			randomUpper(r, 1), randomUpper(r, 1),
			r.IntN(1_000_000), randomUpper(r, 1))
		inputs = append(inputs, strings.ToLower(s))
	}
	// Edge: wrong shape.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 9))
	}
	return uniqueLinesToPairs(inputs)
}

// inAadhaarGen — 12 digits, 4-4-4 spaced or compact.
type inAadhaarGen struct{}

func (inAadhaarGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedINAadhaar))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, randomDigits(r, 12))
	}
	for i := 0; i < 50; i++ {
		inputs = append(inputs, fmt.Sprintf("%s %s %s",
			randomDigits(r, 4), randomDigits(r, 4), randomDigits(r, 4)))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%s-%s-%s",
			randomDigits(r, 4), randomDigits(r, 4), randomDigits(r, 4)))
	}
	// Edge.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 11+r.IntN(3)))
	}
	return uniqueLinesToPairs(inputs)
}

// inPANGen — 10 characters, alphanumeric.
type inPANGen struct{}

func (inPANGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedINPAN))
	var inputs []string
	for i := 0; i < 80; i++ {
		// AAAAA9999A format.
		inputs = append(inputs, fmt.Sprintf("%s%04d%s",
			randomUpper(r, 5), r.IntN(10000), randomUpper(r, 1)))
	}
	// Mixed case.
	for i := 0; i < 20; i++ {
		s := fmt.Sprintf("%s%04d%s",
			randomUpper(r, 5), r.IntN(10000), randomUpper(r, 1))
		inputs = append(inputs, strings.ToLower(s))
	}
	// Wrong length.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomUpper(r, 8+r.IntN(5)))
	}
	return uniqueLinesToPairs(inputs)
}

// brCPFGen — 11 digits, AAA.BBB.CCC-DD or AAABBBCCCDD.
type brCPFGen struct{}

func (brCPFGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedBRCPF))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d.%03d.%03d-%02d",
			r.IntN(1000), r.IntN(1000), r.IntN(1000), r.IntN(100)))
	}
	for i := 0; i < 50; i++ {
		inputs = append(inputs, randomDigits(r, 11))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d %03d %03d %02d",
			r.IntN(1000), r.IntN(1000), r.IntN(1000), r.IntN(100)))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 9+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

// brCNPJGen — 14 digits, AA.BBB.CCC/DDDD-EE or compact.
type brCNPJGen struct{}

func (brCNPJGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedBRCNPJ))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%02d.%03d.%03d/%04d-%02d",
			r.IntN(100), r.IntN(1000), r.IntN(1000), r.IntN(10000), r.IntN(100)))
	}
	for i := 0; i < 50; i++ {
		inputs = append(inputs, randomDigits(r, 14))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 13))
	}
	return uniqueLinesToPairs(inputs)
}

const (
	seedCASIN     uint64 = 0xDEC0DE20
	seedUKNINO    uint64 = 0xDEC0DE21
	seedINAadhaar uint64 = 0xDEC0DE22
	seedINPAN     uint64 = 0xDEC0DE23
	seedBRCPF     uint64 = 0xDEC0DE24
	seedBRCNPJ    uint64 = 0xDEC0DE25
)

func init() {
	register("ca_sin", caSINGen{})
	register("uk_nino", ukNINOGen{})
	register("in_aadhaar", inAadhaarGen{})
	register("in_pan", inPANGen{})
	register("br_cpf", brCPFGen{})
	register("br_cnpj", brCNPJGen{})
}
