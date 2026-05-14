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

// connectionStringGen exercises the connection_string masker.
// Inputs are well-formed authority-style URIs (postgres://, mongodb://,
// redis://, mysql://, jdbc:, kafka://, https-with-secret-params) plus
// malformed shapes.
//
// NOTE: the current secret-keyword set is incomplete — `client_secret`,
// `private_key`, `bearer`, `authorization`, `aws_secret_access_key`,
// and `connectionstring` are missing per the test-analyst findings.
// Fixtures here will lock current behaviour; reviewers should flag
// any obvious leak in canonical via a `# BUG?` comment + follow-up
// issue rather than fixing it inline (per the locked decision).
type connectionStringGen struct{}

func (connectionStringGen) Generate() []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seedConnectionString))

	schemes := []string{"postgres", "postgresql", "mysql", "mariadb",
		"mongodb", "mongodb+srv", "redis", "rediss",
		"kafka", "amqp", "amqps", "memcached"}
	users := []string{"admin", "appuser", "ops", "root", "service",
		"developer", "readonly", "writer", "etl", "monitor"}
	hosts := []string{"db.example.com", "primary.cluster.local",
		"replica-1.internal", "127.0.0.1", "[::1]",
		"cluster-east.example.org", "rds.aws.example.com",
		"shard0.mongodb.example.net"}
	dbnames := []string{"app", "users", "orders", "products",
		"analytics", "audit", "reporting", "staging"}
	knownSecretKeys := []string{"password", "passwd", "pass", "pwd",
		"secret", "apikey", "api_key", "auth_token", "token", "key"}
	innocuousKeys := []string{"sslmode", "connectTimeout", "ssl",
		"readPreference", "replicaSet", "appname", "schema"}

	var inputs []string

	// Authority with explicit userinfo.
	for i := 0; i < 80; i++ {
		s := schemes[r.IntN(len(schemes))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		port := []int{5432, 3306, 27017, 6379, 9092}[r.IntN(5)]
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s:%d/%s", s, u, p, h, port, db))
	}

	// Authority with query parameters carrying known secrets.
	for i := 0; i < 40; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		k := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		v := randomHex(r, 20)
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=%s", s, h, db, k, v))
	}

	// Mixed: innocuous + secret query parameters.
	for i := 0; i < 40; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		k1 := innocuousKeys[r.IntN(len(innocuousKeys))]
		k2 := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=verify-full&%s=%s",
			s, h, db, k1, k2, randomHex(r, 18)))
	}

	// JDBC-style.
	for i := 0; i < 20; i++ {
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		inputs = append(inputs, fmt.Sprintf("jdbc:postgresql://%s/%s?user=%s&password=%s", h, db, u, p))
	}

	// Authority with no userinfo, no params.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s", s, h, db))
	}

	// mongodb+srv-style (no port).
	for i := 0; i < 20; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 20)
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("mongodb+srv://%s:%s@%s/%s?retryWrites=true&w=majority", u, p, h, db))
	}

	// kafka-style (broker list).
	for i := 0; i < 15; i++ {
		h1 := hosts[r.IntN(len(hosts))]
		h2 := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("kafka://%s:9092,%s:9092", h1, h2))
	}

	// Edge: no scheme — likely fails closed.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, fmt.Sprintf("%s:%s@%s/%s",
			users[r.IntN(len(users))], randomHex(r, 16),
			hosts[r.IntN(len(hosts))], dbnames[r.IntN(len(dbnames))]))
	}

	// Edge: empty password (e.g. user::@host).
	for i := 0; i < 10; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s://%s:@%s/%s",
			s, users[r.IntN(len(users))], h, db))
	}

	// Edge: key-value pair format common to ADO.NET / SQL Server.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, fmt.Sprintf("Server=%s;Database=%s;User=%s;Password=%s;",
			hosts[r.IntN(len(hosts))], dbnames[r.IntN(len(dbnames))],
			users[r.IntN(len(users))], randomHex(r, 16)))
	}

	return uniqueLinesToPairs(inputs)
}

const seedConnectionString uint64 = 0xDEC0DE0F

func init() {
	register("connection_string", connectionStringGen{})
}
