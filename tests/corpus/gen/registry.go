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

// Pair is a single (input, _) fixture. The generator computes the
// expected value from mask.Apply at write time, so generators only
// need to author inputs — keeping each strategy short.
type Pair struct {
	Input string
}

// Generator produces a deterministic sequence of fixture inputs for
// one rule. Implementations MUST be pure functions of the rule name
// (no math/rand without a fixed seed, no time-dependent values, no
// map iteration without sort) so the output is byte-stable.
type Generator interface {
	Generate() []Pair
}

// generators is the per-rule registry. A missing rule yields an empty
// generated section — perfectly valid; the harness still runs the
// canonical fixtures. Adding a rule means writing a new generator in
// its own file and registering it in init().
var generators = map[string]Generator{}

// register is the helper every per-rule file calls from its init().
// It panics on duplicate registration so programmer error surfaces at
// `make corpus-regen` time rather than producing silently dropped
// generators.
func register(rule string, g Generator) {
	if _, exists := generators[rule]; exists {
		panic("corpus generator: duplicate registration for " + rule)
	}
	generators[rule] = g
}
