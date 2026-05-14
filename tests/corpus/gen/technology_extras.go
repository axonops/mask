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

// urlCredentialsGen — URLs with userinfo.
type urlCredentialsGen struct{}

func (urlCredentialsGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedURLCredentials))
	schemes := []string{"https", "http", "ftp", "ftps", "ssh"}
	hosts := []string{"example.com", "internal.svc", "git.repo.org",
		"server.example.org", "10.0.0.1"}
	var inputs []string
	for i := 0; i < 80; i++ {
		s := schemes[r.IntN(len(schemes))]
		u := fmt.Sprintf("user%d", r.IntN(10000))
		p := randomHex(r, 16+r.IntN(16))
		h := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s/", s, u, p, h))
	}
	// User only, no password.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(len(schemes))]
		u := fmt.Sprintf("user%d", r.IntN(10000))
		h := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("%s://%s@%s/", s, u, h))
	}
	// With path/query.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(len(schemes))]
		u := fmt.Sprintf("user%d", r.IntN(10000))
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s/path?q=value", s, u, p, h))
	}
	// No credentials — should pass through as-is or be flagged.
	for i := 0; i < 20; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/", s, h))
	}
	return uniqueLinesToPairs(inputs)
}

// passwordGen — diverse strings; rule masks all.
type passwordGen struct{}

func (passwordGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedPassword))
	var inputs []string
	// Hex passwords.
	for i := 0; i < 40; i++ {
		inputs = append(inputs, randomHex(r, 8+r.IntN(24)))
	}
	// Alphanumeric.
	for i := 0; i < 40; i++ {
		const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		n := 8 + r.IntN(20)
		b := make([]byte, n)
		for j := range b {
			b[j] = alpha[r.IntN(len(alpha))]
		}
		inputs = append(inputs, string(b))
	}
	// Symbolic — common passwords.
	for _, p := range []string{
		"password", "12345678", "P@ssw0rd!", "letmein",
		"correct horse battery staple", "qwertyuiop",
	} {
		inputs = append(inputs, p)
	}
	// Empty / very short / very long.
	for n := 1; n <= 6; n++ {
		inputs = append(inputs, randomHex(r, n))
	}
	for i := 0; i < 5; i++ {
		inputs = append(inputs, randomHex(r, 64+r.IntN(64)))
	}
	return uniqueLinesToPairs(inputs)
}

// apiKeyGen — common API key shapes (prefix + hex/base32).
type apiKeyGen struct{}

func (apiKeyGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedAPIKey))
	var inputs []string
	// Generic — avoid real provider patterns that trip GitHub
	// push protection (sk_test_<24-hex> for Stripe, ghp_, etc.).
	prefixes := []string{"key_", "akey_", "internal_", "svc_", "api_"}
	for i := 0; i < 80; i++ {
		p := prefixes[r.IntN(len(prefixes))]
		inputs = append(inputs, p+randomHex(r, 24+r.IntN(16)))
	}
	// Random bare strings.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomHex(r, 32))
	}
	// UUID-like keys.
	for i := 0; i < 20; i++ {
		inputs = append(inputs, fmt.Sprintf("%s-%s-%s-%s-%s",
			randomHextet(r, 8), randomHextet(r, 4),
			randomHextet(r, 4), randomHextet(r, 4),
			randomHextet(r, 12)))
	}
	return uniqueLinesToPairs(inputs)
}

// bearerTokenGen — "Bearer ..." prefixed tokens.
type bearerTokenGen struct{}

func (bearerTokenGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedBearerToken))
	var inputs []string
	for i := 0; i < 60; i++ {
		inputs = append(inputs, "Bearer "+randomB64URL(r, 30+r.IntN(60)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, "bearer "+randomB64URL(r, 30+r.IntN(60)))
	}
	// Token without prefix.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomB64URL(r, 40+r.IntN(40)))
	}
	// JWT-shaped bearer.
	for i := 0; i < 15; i++ {
		jwt := randomB64URL(r, 30) + "." + randomB64URL(r, 80) + "." + randomB64URL(r, 40)
		inputs = append(inputs, "Bearer "+jwt)
	}
	return uniqueLinesToPairs(inputs)
}

const (
	seedURLCredentials uint64 = 0xDEC0DE60
	seedPassword       uint64 = 0xDEC0DE61
	seedAPIKey         uint64 = 0xDEC0DE62
	seedBearerToken    uint64 = 0xDEC0DE63
)

func init() {
	register("url_credentials", urlCredentialsGen{})
	register("password", passwordGen{})
	register("api_key", apiKeyGen{})
	register("bearer_token", bearerTokenGen{})
}
