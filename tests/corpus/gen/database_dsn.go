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

// databaseDSNGen exercises maskDatabaseDSN — parses the Go MySQL
// driver DSN form `user:password@protocol(addr)/db` and redacts
// userinfo. Protocol, address, database, and params are preserved.
//
// NOTE: the current parser rejects `tcp6(...)` IPv6 protocol form
// (rules_technology.go:1058-1063). Fixtures here lock that as
// current behaviour — reviewers should leave a `# BUG?` marker in
// canonical and open a follow-up if appropriate.
type databaseDSNGen struct{}

func (databaseDSNGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	users := []string{"root", "admin", "app", "service", "etl",
		"replicator", "monitor", "ops"}
	protocols := []string{"tcp", "unix", "tcp6"} // tcp6 likely fails closed
	hosts := []string{"localhost:3306", "db.internal:3306",
		"127.0.0.1:3306", "primary.cluster.local:3306",
		"[::1]:3306", "[2001:db8::1]:3306",
		"/var/run/mysqld/mysqld.sock"}
	dbnames := []string{"app", "users", "orders", "products",
		"analytics", "audit", "staging"}

	var inputs []string

	// Canonical user:password@tcp(host:port)/db.
	for i := 0; i < 80; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		proto := protocols[0] // tcp
		h := hosts[r.IntN(4)] // pick TCP-ish hosts
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s:%s@%s(%s)/%s", u, p, proto, h, db))
	}

	// Unix socket form.
	for i := 0; i < 30; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s:%s@unix(/var/run/mysqld/mysqld.sock)/%s", u, p, db))
	}

	// tcp6 form — BUG? path. Lock current behaviour.
	for i := 0; i < 20; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s:%s@tcp6([2001:db8::%d]:3306)/%s",
			u, p, r.IntN(100), db))
	}

	// With multiple non-secret params.
	for i := 0; i < 40; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(4)]
		db := dbnames[r.IntN(len(dbnames))]
		params := []string{
			"charset=utf8mb4",
			"parseTime=true",
			"loc=UTC",
			"tls=true",
			"timeout=30s",
			"interpolateParams=true",
			"multiStatements=true",
			"readTimeout=10s",
			"writeTimeout=10s",
		}
		// Build 1-4 params.
		n := 1 + r.IntN(4)
		var ps string
		for j := 0; j < n; j++ {
			if j > 0 {
				ps += "&"
			}
			ps += params[r.IntN(len(params))]
		}
		inputs = append(inputs, fmt.Sprintf("%s:%s@tcp(%s)/%s?%s", u, p, h, db, ps))
	}

	// Multi-param DSN with a SECRET keyword in the query. The
	// current parser only redacts userinfo, so the query passes
	// through verbatim — a behaviour gap tracked in #72. These
	// fixtures pin the current behaviour so a future fix surfaces
	// as a deliberate corpus diff.
	secretQueryKeys := []string{"password", "client_secret", "token",
		"refresh_token", "private_key"}
	for i := 0; i < 25; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(4)]
		db := dbnames[r.IntN(len(dbnames))]
		sk := secretQueryKeys[r.IntN(len(secretQueryKeys))]
		inputs = append(inputs, fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&%s=%s&parseTime=true",
			u, p, h, db, sk, randomHex(r, 16)))
	}

	// Empty password.
	for i := 0; i < 15; i++ {
		u := users[r.IntN(len(users))]
		h := hosts[r.IntN(4)]
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s:@tcp(%s)/%s", u, h, db))
	}

	// No password (single-colon-free user form).
	for i := 0; i < 15; i++ {
		u := users[r.IntN(len(users))]
		h := hosts[r.IntN(4)]
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s@tcp(%s)/%s", u, h, db))
	}

	// No database.
	for i := 0; i < 10; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(4)]
		inputs = append(inputs, fmt.Sprintf("%s:%s@tcp(%s)/", u, p, h))
	}

	// Edge: no protocol parens — fail closed.
	for i := 0; i < 15; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s:%s@tcp:%s", u, p, db))
	}

	// Edge: URL-style (postgres://...) — different rule's domain.
	for i := 0; i < 10; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("postgres://%s:%s@host/%s", u, p, db))
	}

	// Edge: special characters in password.
	specials := []string{"P@ss!w0rd", "p#ass$word", "pass:word", "p&a&s&s"}
	for _, sp := range specials {
		inputs = append(inputs, fmt.Sprintf("root:%s@tcp(localhost:3306)/app", sp))
	}

	return uniqueLinesToPairs(inputs)
}

func init() {
	register("database_dsn", databaseDSNGen{})
}
