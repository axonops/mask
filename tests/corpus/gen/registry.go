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
// one rule. Implementations receive a 64-bit seed derived from the
// rule name and MUST be pure functions of that seed (no math/rand
// without it, no time-dependent values, no map iteration without
// sort) so the output is byte-stable across machines and re-runs.
type Generator interface {
	Generate(seed uint64) []Pair
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

// seedFor derives a deterministic 64-bit seed from a rule name via
// FNV-1a. Two generators registered for distinct rules get distinct
// seeds without contributors having to pick an unused magic number —
// a manual collision was a high-severity API ergonomics concern in
// the earlier seed design (per-generator `seedXxx` constants).
//
// The high bit is forced to keep the seed away from the all-zero
// state PCG handles specially; the value is otherwise stable as long
// as the rule name itself doesn't change.
func seedFor(rule string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(rule); i++ {
		h ^= uint64(rule[i])
		h *= prime64
	}
	return h | (1 << 63)
}
