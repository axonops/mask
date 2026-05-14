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

// mobilePhoneNumberGen reuses the same input distribution as
// phone_number (they share the underlying mask function via
// registerTelecomRules). Mobile-specific shapes (UK 07xxx, US
// area codes that aren't traditional mobile vs landline) blend in
// naturally with the general phone distribution.
type mobilePhoneNumberGen struct{}

func (mobilePhoneNumberGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedMobilePhoneNumber))

	ccs := []string{"1", "44", "33", "49", "61", "353", "971", "39", "34"}
	seps := []string{" ", "-", ".", "  ", " - "}

	var inputs []string

	// +CC mobile-looking shapes (UK +44 7xxx).
	for i := 0; i < 60; i++ {
		body := "7" + randomDigits(r, 9)
		sep := seps[r.IntN(len(seps))]
		inputs = append(inputs, fmt.Sprintf("+44%s%s", sep, body))
	}

	// +CC with various country codes.
	for i := 0; i < 60; i++ {
		cc := ccs[r.IntN(len(ccs))]
		sep := seps[r.IntN(len(seps))]
		body := randomDigits(r, 8+r.IntN(4))
		inputs = append(inputs, fmt.Sprintf("+%s%s%s", cc, sep, body))
	}

	// 00CC compact form.
	for i := 0; i < 40; i++ {
		cc := ccs[r.IntN(len(ccs))]
		body := randomDigits(r, 8+r.IntN(4))
		inputs = append(inputs, fmt.Sprintf("00%s%s", cc, body))
	}

	// Domestic mobile shapes — UK 07xxxxxxxxx, US (xxx) xxx-xxxx.
	for i := 0; i < 40; i++ {
		inputs = append(inputs, "07"+randomDigits(r, 9))
	}
	for i := 0; i < 40; i++ {
		area := randomDigits(r, 3)
		mid := randomDigits(r, 3)
		tail := randomDigits(r, 4)
		inputs = append(inputs, fmt.Sprintf("(%s) %s-%s", area, mid, tail))
	}

	// Hyphen-grouped 3-3-4.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("%s-%s-%s", randomDigits(r, 3), randomDigits(r, 3), randomDigits(r, 4)))
	}

	// Dotted form.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("%s.%s.%s", randomDigits(r, 3), randomDigits(r, 3), randomDigits(r, 4)))
	}

	// Edge: too short — fail closed.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, randomDigits(r, 3+r.IntN(4)))
	}

	// Edge: letters in body.
	for i := 0; i < 15; i++ {
		body := randomDigits(r, 8)
		inputs = append(inputs, "+44 7"+string(rune('A'+r.IntN(26)))+body)
	}

	// Edge: extension suffix.
	for i := 0; i < 10; i++ {
		base := "+44 7" + randomDigits(r, 9)
		inputs = append(inputs, base+" x"+randomDigits(r, 4))
	}

	return uniqueLinesToPairs(inputs)
}

const seedMobilePhoneNumber uint64 = 0xDEC0DE11

func init() {
	register("mobile_phone_number", mobilePhoneNumberGen{})
}
