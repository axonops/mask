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

// personNameGen exercises the person_name masker. The rule keeps the
// first character of each whitespace/hyphen/apostrophe-delimited
// token and masks the rest. Separators (space, hyphen, apostrophe)
// are preserved.
type personNameGen struct{}

func (personNameGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	givens := []string{
		"Alice", "Bob", "Carol", "Dan", "Erin", "Fadi", "Greta",
		"Hugo", "Ines", "John", "Kara", "Liam", "Mia", "Noah", "Olga",
		"Pedro", "Qiang", "Rosa", "Saanvi", "Tomás", "Ulla", "Václav",
		"Wei", "Xenia", "Yusuf", "Zoe", "Áine", "Çetin", "Élise",
	}
	surnames := []string{
		"Smith", "Jones", "Patel", "Khan", "Garcia", "Müller",
		"Schmidt", "Rodríguez", "Tanaka", "Yamada", "Lee", "Park",
		"O'Brien", "MacDonald", "Smith-Jones", "van der Berg",
		"de la Cruz", "Saint-Pierre", "D'Angelo", "Le Roux",
	}

	var inputs []string

	// First + last.
	for i := 0; i < 80; i++ {
		inputs = append(inputs, givens[r.IntN(len(givens))]+" "+surnames[r.IntN(len(surnames))])
	}

	// First + middle + last.
	for i := 0; i < 40; i++ {
		inputs = append(inputs, givens[r.IntN(len(givens))]+" "+
			givens[r.IntN(len(givens))]+" "+
			surnames[r.IntN(len(surnames))])
	}

	// Hyphenated double surname.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, givens[r.IntN(len(givens))]+" "+
			surnames[r.IntN(len(surnames))]+"-"+surnames[r.IntN(len(surnames))])
	}

	// Apostrophe-bearing.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, givens[r.IntN(len(givens))]+" O'"+
			surnames[r.IntN(len(surnames))])
	}

	// Single-token names — short and long.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, givens[r.IntN(len(givens))])
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, surnames[r.IntN(len(surnames))])
	}

	// All-upper and all-lower variants.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, strings.ToUpper(givens[r.IntN(len(givens))])+" "+
			strings.ToUpper(surnames[r.IntN(len(surnames))]))
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, strings.ToLower(givens[r.IntN(len(givens))])+" "+
			strings.ToLower(surnames[r.IntN(len(surnames))]))
	}

	// Unicode-heavy names — multi-byte rune handling.
	uni := []string{"日本太郎", "Müller-Lüdenscheidt", "Łukasz Łazarski", "Иван Иванович", "محمد علي"}
	for _, n := range uni {
		inputs = append(inputs, n)
	}

	// Edge: extra whitespace.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, givens[r.IntN(len(givens))]+"  "+surnames[r.IntN(len(surnames))])
	}

	// Edge: single-letter tokens (initials).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "J. "+surnames[r.IntN(len(surnames))])
	}

	// Edge: title-bearing — rule treats title as a name token.
	for _, t := range []string{"Dr", "Mr", "Mrs", "Ms", "Prof"} {
		for i := 0; i < 5; i++ {
			inputs = append(inputs, t+" "+givens[r.IntN(len(givens))]+" "+surnames[r.IntN(len(surnames))])
		}
	}

	return uniqueLinesToPairs(inputs)
}

func init() {
	register("person_name", personNameGen{})
}
