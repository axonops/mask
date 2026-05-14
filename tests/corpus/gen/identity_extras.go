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

// givenNameGen — keeps first character; masks rest.
type givenNameGen struct{}

func (givenNameGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedGivenName))
	pool := []string{"Alice", "Bob", "Carol", "Dan", "Erin", "Fadi",
		"Greta", "Hugo", "Ines", "John", "Kara", "Liam", "Mia", "Noah",
		"Olga", "Pedro", "Qiang", "Rosa", "Saanvi", "Tomás", "Ulla",
		"Václav", "Wei", "Xenia", "Yusuf", "Zoe", "Áine", "Çetin",
		"Élise", "İsmail", "Jürgen", "François", "Müller"}
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, pool[r.IntN(len(pool))])
	}
	// All-upper.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, strings.ToUpper(pool[r.IntN(len(pool))]))
	}
	// All-lower.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, strings.ToLower(pool[r.IntN(len(pool))]))
	}
	// Hyphenated.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, pool[r.IntN(len(pool))]+"-"+pool[r.IntN(len(pool))])
	}
	// Single-letter.
	for i := 0; i < 5; i++ {
		inputs = append(inputs, string(rune('A'+i)))
	}
	return uniqueLinesToPairs(inputs)
}

// familyNameGen — same shape as given_name; preserves first character.
type familyNameGen struct{}

func (familyNameGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedFamilyName))
	pool := []string{"Smith", "Jones", "Patel", "Khan", "Garcia",
		"Müller", "Schmidt", "Rodríguez", "Tanaka", "Yamada", "Lee",
		"Park", "O'Brien", "MacDonald", "Smith-Jones",
		"van der Berg", "de la Cruz", "Saint-Pierre", "D'Angelo",
		"Le Roux", "Andersen", "Nakamura", "Ng", "Wong"}
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, pool[r.IntN(len(pool))])
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, strings.ToUpper(pool[r.IntN(len(pool))]))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, strings.ToLower(pool[r.IntN(len(pool))]))
	}
	return uniqueLinesToPairs(inputs)
}

// usernameGen — varied login shapes.
type usernameGen struct{}

func (usernameGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedUsername))
	var inputs []string
	// alpha-numeric.
	for i := 0; i < 80; i++ {
		n := 4 + r.IntN(16)
		b := make([]byte, n)
		const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
		for j := range b {
			b[j] = alpha[r.IntN(len(alpha))]
		}
		inputs = append(inputs, string(b))
	}
	// dot-separated.
	for i := 0; i < 30; i++ {
		first := []string{"john", "jane", "alice", "bob", "carol"}[r.IntN(5)]
		last := []string{"smith", "jones", "doe", "patel"}[r.IntN(4)]
		inputs = append(inputs, first+"."+last)
	}
	// Underscore.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("user_%d", r.IntN(100000)))
	}
	// Hyphen.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, fmt.Sprintf("svc-%d", r.IntN(10000)))
	}
	// At-prefix.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "@user"+fmt.Sprint(r.IntN(10000)))
	}
	// Numeric.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprint(r.IntN(1_000_000)))
	}
	// Single letter.
	for i := 0; i < 5; i++ {
		inputs = append(inputs, string(rune('a'+i)))
	}
	return uniqueLinesToPairs(inputs)
}

// passportNumberGen — alphanumeric, varied lengths by country.
type passportNumberGen struct{}

func (passportNumberGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedPassportNumber))
	var inputs []string
	// Common shapes: 1-2 letters + 6-9 digits.
	for i := 0; i < 80; i++ {
		prefix := randomUpper(r, r.IntN(3))
		digits := randomDigits(r, 6+r.IntN(4))
		inputs = append(inputs, prefix+digits)
	}
	// All digits (e.g. US 9-digit).
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 9))
	}
	// 8-digit.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 8))
	}
	// Edge: lower-case prefix.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, strings.ToLower(randomUpper(r, 2))+randomDigits(r, 7))
	}
	// Edge: too short.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 4+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

const (
	seedGivenName      uint64 = 0xDEC0DE50
	seedFamilyName     uint64 = 0xDEC0DE51
	seedUsername       uint64 = 0xDEC0DE52
	seedPassportNumber uint64 = 0xDEC0DE53
)

func init() {
	register("given_name", givenNameGen{})
	register("family_name", familyNameGen{})
	register("username", usernameGen{})
	register("passport_number", passportNumberGen{})
}
