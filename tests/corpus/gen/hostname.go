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

// hostnameGen — domain names of varying depth.
type hostnameGen struct{}

func (hostnameGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedHostname))
	tlds := []string{"com", "org", "net", "io", "co.uk", "edu", "gov",
		"local", "internal", "dev", "test", "info"}
	labels := []string{"example", "api", "web", "auth", "db", "cache",
		"queue", "primary", "replica", "prod", "staging", "qa",
		"east", "west", "us", "eu", "ap", "service", "node", "pod",
		"app", "monitoring", "metrics", "logs"}

	var inputs []string

	// Two-label (apex).
	for i := 0; i < 60; i++ {
		inputs = append(inputs, labels[r.IntN(len(labels))]+"."+tlds[r.IntN(len(tlds))])
	}
	// Three-label.
	for i := 0; i < 60; i++ {
		inputs = append(inputs, fmt.Sprintf("%s.%s.%s",
			labels[r.IntN(len(labels))], labels[r.IntN(len(labels))], tlds[r.IntN(len(tlds))]))
	}
	// Deep subdomains.
	for i := 0; i < 30; i++ {
		depth := 3 + r.IntN(4)
		parts := make([]string, depth)
		for j := range parts[:depth-1] {
			parts[j] = labels[r.IntN(len(labels))]
		}
		parts[depth-1] = tlds[r.IntN(len(tlds))]
		inputs = append(inputs, strings.Join(parts, "."))
	}
	// Numeric labels (legal in DNS).
	for i := 0; i < 15; i++ {
		inputs = append(inputs, fmt.Sprintf("node-%d.%s.%s",
			r.IntN(1000), labels[r.IntN(len(labels))], tlds[r.IntN(len(tlds))]))
	}
	// Hyphenated.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%s-%s.%s",
			labels[r.IntN(len(labels))], labels[r.IntN(len(labels))],
			tlds[r.IntN(len(tlds))]))
	}
	// Single-label.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, labels[r.IntN(len(labels))])
	}
	// Localhost / well-known.
	inputs = append(inputs, "localhost", "host.docker.internal",
		"kubernetes.default.svc.cluster.local")

	// Edge: trailing dot (FQDN).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, labels[r.IntN(len(labels))]+"."+tlds[r.IntN(len(tlds))]+".")
	}
	// Edge: leading hyphen in label.
	for i := 0; i < 5; i++ {
		inputs = append(inputs, "-"+labels[r.IntN(len(labels))]+"."+tlds[r.IntN(len(tlds))])
	}
	// Edge: empty label (double dot).
	for i := 0; i < 5; i++ {
		inputs = append(inputs, labels[r.IntN(len(labels))]+".."+tlds[r.IntN(len(tlds))])
	}
	// Edge: IDN (punycode).
	inputs = append(inputs, "xn--80akhbyknj4f.com", "xn--ls8h.la")

	return uniqueLinesToPairs(inputs)
}

const seedHostname uint64 = 0xDEC0DE16

func init() { register("hostname", hostnameGen{}) }
