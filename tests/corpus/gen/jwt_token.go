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

// jwtTokenGen exercises the JWT masker. Three base64url-ish segments
// separated by dots. Output preserves the first 4 runes of the
// header, masks each segment with 4-rune blocks, and trails with a
// final dot per the spec example.
type jwtTokenGen struct{}

func (jwtTokenGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedJWTToken))

	var inputs []string

	// Well-formed JWT-shaped inputs of varying segment widths.
	for i := 0; i < 120; i++ {
		header := randomB64URL(r, 10+r.IntN(40))
		payload := randomB64URL(r, 20+r.IntN(60))
		sig := randomB64URL(r, 20+r.IntN(50))
		inputs = append(inputs, header+"."+payload+"."+sig)
	}

	// Realistic header prefix (eyJ... is what `{"alg":"...` base64s to).
	for i := 0; i < 30; i++ {
		header := "eyJ" + randomB64URL(r, 30+r.IntN(20))
		payload := "eyJ" + randomB64URL(r, 40+r.IntN(40))
		sig := randomB64URL(r, 30+r.IntN(30))
		inputs = append(inputs, header+"."+payload+"."+sig)
	}

	// Minimum-shape: very short segments.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomB64URL(r, 4+r.IntN(3))+"."+
			randomB64URL(r, 4+r.IntN(3))+"."+
			randomB64URL(r, 4+r.IntN(3)))
	}

	// Maximum reasonable size — long tokens.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomB64URL(r, 100)+"."+
			randomB64URL(r, 300)+"."+
			randomB64URL(r, 100))
	}

	// Empty middle segment (unsigned JWT shape — no payload).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomB64URL(r, 20)+"."+
			""+"."+
			randomB64URL(r, 20))
	}

	// Edge: only two segments — fail closed.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomB64URL(r, 20)+"."+randomB64URL(r, 20))
	}

	// Edge: four segments — fail closed.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomB64URL(r, 20)+"."+randomB64URL(r, 20)+"."+
			randomB64URL(r, 20)+"."+randomB64URL(r, 20))
	}

	// Edge: no separator at all.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomB64URL(r, 60+r.IntN(40)))
	}

	// Edge: contains invalid base64url character.
	for i := 0; i < 10; i++ {
		base := randomB64URL(r, 30)
		bad := []string{"$", "@", "/", "+"}[r.IntN(4)] // / and + are base64 not base64url
		inputs = append(inputs, base+bad+"."+randomB64URL(r, 30)+"."+randomB64URL(r, 30))
	}

	return uniqueLinesToPairs(inputs)
}

// randomB64URL emits n base64url-safe characters (A–Z, a–z, 0–9, '-', '_').
func randomB64URL(r *rand.Rand, n int) string {
	if n <= 0 {
		return ""
	}
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return string(b)
}

// silence unused-import warning if strings drops from active use.
var _ = strings.Repeat

const seedJWTToken uint64 = 0xDEC0DE0E

func init() {
	register("jwt_token", jwtTokenGen{})
}
