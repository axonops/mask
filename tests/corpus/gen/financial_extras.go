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

// bankAccountNumberGen — keeps the last 4 digits; preserves dashes
// and spaces.
type bankAccountNumberGen struct{}

func (bankAccountNumberGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		// 8-12 digit accounts.
		inputs = append(inputs, randomDigits(r, 8+r.IntN(5)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, groupBy(randomDigits(r, 12), 4, "-"))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, groupBy(randomDigits(r, 12), 4, " "))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 4+r.IntN(3))) // very short
	}
	// Edge: letters present.
	for i := 0; i < 10; i++ {
		d := []byte(randomDigits(r, 10))
		d[r.IntN(10)] = byte('A' + r.IntN(26))
		inputs = append(inputs, string(d))
	}
	return uniqueLinesToPairs(inputs)
}

// ukSortCodeGen — 6 digits, NN-NN-NN.
type ukSortCodeGen struct{}

func (ukSortCodeGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%02d-%02d-%02d",
			r.IntN(100), r.IntN(100), r.IntN(100)))
	}
	for i := 0; i < 40; i++ {
		inputs = append(inputs, randomDigits(r, 6))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%02d %02d %02d",
			r.IntN(100), r.IntN(100), r.IntN(100)))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 4+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

// usABARoutingNumberGen — 9 digits, no separators.
type usABARoutingNumberGen struct{}

func (usABARoutingNumberGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 100; i++ {
		inputs = append(inputs, randomDigits(r, 9))
	}
	// Edge: hyphenated (likely fails closed).
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d-%03d-%03d",
			r.IntN(1000), r.IntN(1000), r.IntN(1000)))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 8+r.IntN(3)))
	}
	return uniqueLinesToPairs(inputs)
}

// swiftBICGen — 8 or 11 upper-case alphanumeric characters.
type swiftBICGen struct{}

func (swiftBICGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	// 8-character form.
	for i := 0; i < 60; i++ {
		inputs = append(inputs, randomBICChars(r, 8))
	}
	// 11-character form (with branch code).
	for i := 0; i < 60; i++ {
		inputs = append(inputs, randomBICChars(r, 11))
	}
	// Real-looking BICs.
	commonBanks := []string{"BARC", "HSBC", "DEUT", "CHAS", "CITI", "BOFA", "WFBI", "SBIN"}
	for _, bank := range commonBanks {
		for i := 0; i < 4; i++ {
			cc := randomUpper(r, 2)
			inputs = append(inputs, bank+cc+randomBICChars(r, 2))
			inputs = append(inputs, bank+cc+randomBICChars(r, 5))
		}
	}
	// Edge: lower-case.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, strings.ToLower(randomBICChars(r, 8)))
	}
	// Edge: wrong length.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomBICChars(r, 7))
		inputs = append(inputs, randomBICChars(r, 10))
		inputs = append(inputs, randomBICChars(r, 12))
	}
	return uniqueLinesToPairs(inputs)
}

func randomBICChars(r *rand.Rand, n int) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return string(b)
}

// monetaryAmountGen — replaces with [REDACTED]. Same shape as
// full_redact but for currency values.
type monetaryAmountGen struct{}

func (monetaryAmountGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	currencies := []string{"$", "£", "€", "¥", "₹", "₩", "USD", "GBP", "EUR"}
	for i := 0; i < 80; i++ {
		cur := currencies[r.IntN(len(currencies))]
		amt := r.IntN(1_000_000)
		dec := r.IntN(100)
		inputs = append(inputs, fmt.Sprintf("%s%d.%02d", cur, amt, dec))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("%d,%03d.%02d",
			r.IntN(1000), r.IntN(1000), r.IntN(100)))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%d %s",
			r.IntN(1_000_000), currencies[r.IntN(3)+6])) // last 3 = ISO codes
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, "-"+fmt.Sprintf("$%d.%02d", r.IntN(10000), r.IntN(100)))
	}
	inputs = append(inputs, "$0.00", "$0", "free", "-$1,234.56")
	return uniqueLinesToPairs(inputs)
}

func init() {
	register("bank_account_number", bankAccountNumberGen{})
	register("uk_sort_code", ukSortCodeGen{})
	register("us_aba_routing_number", usABARoutingNumberGen{})
	register("swift_bic", swiftBICGen{})
	register("monetary_amount", monetaryAmountGen{})
}
