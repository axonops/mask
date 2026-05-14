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

// streetAddressGen exercises maskStreet — keeps the leading house
// number and the recognised trailing street type; masks the name
// body. Falls back to same-length mask when neither signal is
// present.
type streetAddressGen struct{}

func (streetAddressGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	streetTypes := []string{"Street", "Road", "Avenue", "Lane", "Way",
		"Drive", "Court", "Boulevard", "Place", "Square", "Terrace",
		"Crescent", "Close", "Walk", "Mews", "Parade",
		"St", "Rd", "Ave", "Ln", "Dr", "Ct", "Blvd", "Pl", "Sq", "Cres",
	}
	bodies := []string{
		"Wallaby", "Privet", "Maple", "Oak", "High", "Church",
		"Main", "Park", "Station", "Mill", "Bridge", "King",
		"Queen", "Victoria", "Albert", "Castle", "Mountain", "River",
		"Lakeview", "Sunset", "Eagle Pass", "Crystal Bay",
	}

	var inputs []string

	// Canonical "<n> <body> <type>" shape.
	for i := 0; i < 80; i++ {
		n := 1 + r.IntN(9999)
		body := bodies[r.IntN(len(bodies))]
		st := streetTypes[r.IntN(len(streetTypes))]
		inputs = append(inputs, fmt.Sprintf("%d %s %s", n, body, st))
	}

	// Multi-word body.
	for i := 0; i < 40; i++ {
		n := 1 + r.IntN(9999)
		b1 := bodies[r.IntN(len(bodies))]
		b2 := bodies[r.IntN(len(bodies))]
		st := streetTypes[r.IntN(len(streetTypes))]
		inputs = append(inputs, fmt.Sprintf("%d %s %s %s", n, b1, b2, st))
	}

	// House-number-only (no street type) — current behaviour.
	for i := 0; i < 20; i++ {
		n := 1 + r.IntN(9999)
		body := bodies[r.IntN(len(bodies))]
		inputs = append(inputs, fmt.Sprintf("%d %s", n, body))
	}

	// Street type only (no number).
	for i := 0; i < 20; i++ {
		body := bodies[r.IntN(len(bodies))]
		st := streetTypes[r.IntN(len(streetTypes))]
		inputs = append(inputs, fmt.Sprintf("%s %s", body, st))
	}

	// Apartment / unit suffix.
	for i := 0; i < 30; i++ {
		n := 1 + r.IntN(9999)
		body := bodies[r.IntN(len(bodies))]
		st := streetTypes[r.IntN(len(streetTypes))]
		unit := []string{"Apt", "Unit", "Suite", "Flat"}[r.IntN(4)]
		inputs = append(inputs, fmt.Sprintf("%d %s %s, %s %d", n, body, st, unit, 1+r.IntN(99)))
	}

	// Number-with-letter suffix (UK common).
	for i := 0; i < 20; i++ {
		n := 1 + r.IntN(99)
		suffix := string(rune('A' + r.IntN(6)))
		body := bodies[r.IntN(len(bodies))]
		st := streetTypes[r.IntN(len(streetTypes))]
		inputs = append(inputs, fmt.Sprintf("%d%s %s %s", n, suffix, body, st))
	}

	// PO Box.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("PO Box %d", 1+r.IntN(99999)))
	}

	// Edge: no number, no street type — fail closed.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, bodies[r.IntN(len(bodies))])
	}

	// Edge: unicode street names.
	for _, s := range []string{
		"42 Champs-Élysées Avenue",
		"10 Königsallee Strasse",
		"5 Calle Mayor Street",
	} {
		inputs = append(inputs, s)
	}

	// Edge: very long street body.
	for i := 0; i < 5; i++ {
		bodies := make([]string, 6)
		for j := range bodies {
			bodies[j] = "Word"
		}
		inputs = append(inputs, fmt.Sprintf("%d %s %s",
			r.IntN(1000), strings.Join(bodies, " "), streetTypes[r.IntN(len(streetTypes))]))
	}

	return uniqueLinesToPairs(inputs)
}

func init() {
	register("street_address", streetAddressGen{})
}
