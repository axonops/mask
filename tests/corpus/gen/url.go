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

// urlGen exercises the URL masker: preserves scheme, host, and port
// verbatim; same-length-masks each path segment; replaces query
// values and fragments with fixed-width mask blocks; redacts userinfo
// defensively.
type urlGen struct{}

func (urlGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	schemes := []string{"https", "http", "ws", "wss", "ftp", "ftps"}
	hosts := []string{
		"example.com", "api.example.com", "service.internal",
		"localhost", "192.168.1.1", "deep.sub.example.org",
		"docs.go.dev", "[::1]", "[2001:db8::1]",
	}
	pathSegs := []string{"users", "v1", "v2", "api", "orders", "products",
		"reports", "admin", "static", "blog", "posts", "comments"}
	queryKeys := []string{"id", "page", "limit", "filter", "sort",
		"token", "session", "user", "ref", "utm_source"}

	var inputs []string

	// Plain authority-only.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("%s://%s", s, h))
	}

	// With explicit port.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		port := []int{80, 443, 8080, 3000, 8443, 5432, 27017}[r.IntN(7)]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%d", s, h, port))
	}

	// Single path segment.
	for i := 0; i < 40; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(5)]
		seg := pathSegs[r.IntN(len(pathSegs))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s", s, h, seg))
	}

	// Multi-segment path with numeric ID.
	for i := 0; i < 60; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(5)]
		seg := pathSegs[r.IntN(len(pathSegs))]
		id := r.IntN(1_000_000)
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s/%d", s, h, seg, id))
	}

	// Path + single query parameter.
	for i := 0; i < 50; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(5)]
		seg := pathSegs[r.IntN(len(pathSegs))]
		key := queryKeys[r.IntN(len(queryKeys))]
		val := fmt.Sprintf("value%d", r.IntN(10000))
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=%s", s, h, seg, key, val))
	}

	// Multi-parameter query.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(5)]
		seg := pathSegs[r.IntN(len(pathSegs))]
		k1 := queryKeys[r.IntN(len(queryKeys))]
		k2 := queryKeys[r.IntN(len(queryKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=%d&%s=%s",
			s, h, seg, k1, r.IntN(1000), k2, randomHex(r, 8)))
	}

	// Fragment.
	for i := 0; i < 20; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(5)]
		frag := fmt.Sprintf("section-%d", r.IntN(50))
		inputs = append(inputs, fmt.Sprintf("%s://%s/page#%s", s, h, frag))
	}

	// With userinfo — must be redacted.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(5)]
		user := fmt.Sprintf("user%d", r.IntN(1000))
		pass := randomHex(r, 12)
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s/", s, user, pass, h))
	}

	// IPv6 literal host.
	for i := 0; i < 10; i++ {
		s := schemes[r.IntN(2)]
		seg := pathSegs[r.IntN(len(pathSegs))]
		inputs = append(inputs, fmt.Sprintf("%s://[2001:db8::%d]/%s", s, r.IntN(100), seg))
	}

	// Edge: no scheme — fail closed.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, hosts[r.IntN(5)]+"/"+pathSegs[r.IntN(len(pathSegs))])
	}

	// Edge: scheme-only.
	for i := 0; i < 5; i++ {
		inputs = append(inputs, schemes[r.IntN(len(schemes))]+"://")
	}

	// Edge: unicode in path (must remain valid UTF-8 in output).
	for i := 0; i < 10; i++ {
		s := schemes[r.IntN(2)]
		h := hosts[r.IntN(5)]
		uni := []string{"café", "日本語", "Ελληνικά", "файл"}[r.IntN(4)]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s", s, h, uni))
	}

	// Edge: whitespace inside (likely fails closed).
	for i := 0; i < 5; i++ {
		inputs = append(inputs, "https://example.com/with space/path")
	}

	return uniqueLinesToPairs(inputs)
}

func init() {
	register("url", urlGen{})
}
