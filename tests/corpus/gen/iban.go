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

// ibanGen exercises maskIBAN: keeps the 4 leading characters (country
// + check digits) and the trailing 4 alphanumeric characters; masks
// the body. Length range 15–34 non-separator characters. Lower-case
// letters and non-alphanumerics fail closed to SameLengthMask.
type ibanGen struct{}

func (ibanGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	// Sample country prefixes drawn from real ISO 13616 lengths.
	countries := []struct {
		cc     string
		length int // total non-separator length per ISO 13616
	}{
		{"GB", 22}, {"DE", 22}, {"FR", 27}, {"IT", 27}, {"ES", 24},
		{"NL", 18}, {"BE", 16}, {"AT", 20}, {"IE", 22}, {"PT", 25},
		{"CH", 21}, {"SE", 24}, {"NO", 15}, {"FI", 18}, {"DK", 18},
		{"PL", 28}, {"GR", 27}, {"LU", 20}, {"MT", 31}, {"CY", 28},
		{"BR", 29}, {"SA", 24}, {"AE", 23}, {"MU", 30}, {"LB", 28},
	}

	var inputs []string

	// Well-formed compact (no spaces) IBANs of valid lengths.
	for i := 0; i < 80; i++ {
		c := countries[r.IntN(len(countries))]
		body := randomIBANBody(r, c.length-2-2)
		check := randomDigits(r, 2)
		inputs = append(inputs, c.cc+check+body)
	}

	// Well-formed grouped (4-char groups separated by space) — the
	// rule preserves spaces verbatim.
	for i := 0; i < 60; i++ {
		c := countries[r.IntN(len(countries))]
		body := randomIBANBody(r, c.length-2-2)
		full := c.cc + randomDigits(r, 2) + body
		inputs = append(inputs, groupBy(full, 4, " "))
	}

	// Hyphen-grouped — also accepted as a separator.
	for i := 0; i < 30; i++ {
		c := countries[r.IntN(len(countries))]
		body := randomIBANBody(r, c.length-2-2)
		full := c.cc + randomDigits(r, 2) + body
		inputs = append(inputs, groupBy(full, 4, "-"))
	}

	// Minimum-length (15) and maximum-length (34) — boundary checks.
	for i := 0; i < 10; i++ {
		body := randomIBANBody(r, 15-2-2)
		inputs = append(inputs, "NO"+randomDigits(r, 2)+body)
	}
	for i := 0; i < 10; i++ {
		body := randomIBANBody(r, 34-2-2)
		inputs = append(inputs, "MT"+randomDigits(r, 2)+body)
	}

	// Edge: lower-case letters — fail closed because !isUpperAlphanumeric.
	for i := 0; i < 20; i++ {
		c := countries[r.IntN(len(countries))]
		body := strings.ToLower(randomIBANBody(r, c.length-4))
		inputs = append(inputs, strings.ToLower(c.cc)+randomDigits(r, 2)+body)
	}

	// Edge: too short — fail closed (nonsep < 15).
	for i := 0; i < 15; i++ {
		c := countries[r.IntN(len(countries))]
		body := randomIBANBody(r, 8+r.IntN(5))
		inputs = append(inputs, c.cc+randomDigits(r, 2)+body)
	}

	// Edge: too long — fail closed (nonsep > 34).
	for i := 0; i < 10; i++ {
		body := randomIBANBody(r, 35+r.IntN(10))
		inputs = append(inputs, "GB"+randomDigits(r, 2)+body)
	}

	// Edge: non-alphanumeric characters in the body — fail closed.
	junk := []string{"@", "$", "#", "!", "/", ".", ","}
	for i := 0; i < 15; i++ {
		c := countries[r.IntN(len(countries))]
		body := []byte(randomIBANBody(r, c.length-4))
		body[r.IntN(len(body))] = junk[r.IntN(len(junk))][0]
		inputs = append(inputs, c.cc+randomDigits(r, 2)+string(body))
	}

	inputs = uniqueLines(inputs)
	out := make([]Pair, len(inputs))
	for i, s := range inputs {
		out[i] = Pair{Input: s}
	}
	return out
}

// randomIBANBody emits n upper-case alphanumeric characters — the
// allowed IBAN body alphabet.
func randomIBANBody(r *rand.Rand, n int) string {
	if n <= 0 {
		return ""
	}
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return string(b)
}

// groupBy inserts sep every n characters, classic IBAN grouping.
func groupBy(s string, n int, sep string) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%n == 0 {
			b.WriteString(sep)
		}
		b.WriteRune(c)
	}
	return b.String()
}

func init() {
	register("iban", ibanGen{})
}
