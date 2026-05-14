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
// redis://, mysql://, jdbc:, kafka://) with userinfo, query parameters
// in every position relative to a secret, multiple secret keywords,
// repeated keys, and substring-only false-positive bait
// (`secretsauce`, `my_token_id`).
//
// The curated secret-keyword set now covers OAuth, AWS, and Azure
// families (per #70); the generator mixes those liberally with
// non-secret structural params so reviewers can verify that only
// the secret values redact and only on whole-key matches.
type connectionStringGen struct{}

func (connectionStringGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))

	// Authority-style schemes drawn from the popular database and
	// messaging ecosystems. Each is widely deployed with a
	// `scheme://user:pass@host[:port]/path?params` shape.
	schemes := []string{
		// Relational.
		"postgres", "postgresql",
		"mysql", "mariadb",
		"sqlserver", "mssql",
		"oracle",
		"cockroachdb",
		"vertica",
		"db2",
		"firebird",
		// Document / key-value / wide-column.
		"mongodb", "mongodb+srv",
		"couchbase", "couchbases",
		"cassandra", "scylla",
		"redis", "rediss",
		"dynamodb",
		"etcd",
		// Time-series and analytics.
		"clickhouse", "tcp", // ClickHouse native protocol is `tcp://`.
		"influxdb",
		"snowflake",
		"timescaledb",
		// Search and graph.
		"elasticsearch", "elastic",
		"neo4j", "bolt",
		// Messaging.
		"kafka",
		"amqp", "amqps",
		"pulsar", "pulsar+ssl",
		"nats", "tls",
		"mqtt", "mqtts",
		// Object storage.
		"s3",
		"gs",
		// Memcached and others.
		"memcached",
	}
	users := []string{"admin", "appuser", "ops", "root", "service",
		"developer", "readonly", "writer", "etl", "monitor"}
	hosts := []string{"db.example.com", "primary.cluster.local",
		"replica-1.internal", "127.0.0.1", "[::1]",
		"cluster-east.example.org", "rds.aws.example.com",
		"shard0.mongodb.example.net"}
	dbnames := []string{"app", "users", "orders", "products",
		"analytics", "audit", "reporting", "staging"}
	// Full OAuth+cloud+password set — must each redact.
	knownSecretKeys := []string{
		"password", "passwd", "pass", "pwd",
		"secret", "apikey", "api_key", "auth_token", "access_token", "token",
		"client_secret", "client_credentials", "refresh_token", "id_token",
		"aws_secret_access_key", "private_key", "sas", "sastoken",
		"signature", "sig", "connectionstring", "bearer", "authorization",
	}
	// Non-secret structural params — must pass through verbatim.
	innocuousKeys := []string{"sslmode", "connectTimeout", "ssl",
		"readPreference", "replicaSet", "authSource", "appname",
		"application_name", "schema", "w", "retryWrites", "tlsCAFile",
		"loadBalanceHosts", "targetServerType", "compression"}
	// Substring-bait keys — they contain a secret keyword as a
	// substring but must NOT be matched on the whole-key lookup.
	substringBait := []string{"secretsauce", "my_token_id",
		"application_name", "passcode_label", "key_metric",
		"signedurl_handler"}

	var inputs []string

	// Per-database canonical port + path conventions so the
	// generated fixtures look like real connection strings rather
	// than random scheme-host pairs. Falling back to a default
	// generic port set for schemes not in this map.
	schemePort := map[string]int{
		"postgres": 5432, "postgresql": 5432, "cockroachdb": 26257, "timescaledb": 5432,
		"mysql": 3306, "mariadb": 3306, "vertica": 5433,
		"sqlserver": 1433, "mssql": 1433,
		"oracle": 1521, "db2": 50000, "firebird": 3050,
		"mongodb": 27017, "mongodb+srv": 27017,
		"redis": 6379, "rediss": 6379,
		"cassandra": 9042, "scylla": 9042,
		"couchbase": 8091, "couchbases": 18091,
		"clickhouse": 8123, "tcp": 9000,
		"influxdb": 8086, "snowflake": 443,
		"elasticsearch": 9200, "elastic": 9200,
		"neo4j": 7687, "bolt": 7687,
		"kafka": 9092, "amqp": 5672, "amqps": 5671,
		"pulsar": 6650, "pulsar+ssl": 6651,
		"nats": 4222, "tls": 4443,
		"mqtt": 1883, "mqtts": 8883,
		"etcd": 2379, "memcached": 11211,
		"dynamodb": 8000, "s3": 443, "gs": 443,
	}
	portFor := func(s string) int {
		if p, ok := schemePort[s]; ok {
			return p
		}
		return []int{5432, 3306, 27017, 6379, 9092}[r.IntN(5)]
	}

	// Authority with explicit userinfo across every scheme.
	for i := 0; i < 100; i++ {
		s := schemes[r.IntN(len(schemes))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s:%d/%s", s, u, p, h, portFor(s), db))
	}

	// Authority + userinfo + a single non-secret structural param —
	// realistic for every scheme. Pins per-scheme behaviour without
	// the noise of secrets in the query.
	for i := 0; i < 60; i++ {
		s := schemes[r.IntN(len(schemes))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		nk := innocuousKeys[r.IntN(len(innocuousKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s:%d/%s?%s=true",
			s, u, p, h, portFor(s), db, nk))
	}

	// Single secret query parameter — every keyword covered.
	for i := 0; i < 60; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		k := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		v := randomHex(r, 16+r.IntN(16))
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=%s", s, h, db, k, v))
	}

	// Secret BEFORE non-secret.
	for i := 0; i < 40; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		sk := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		nk := innocuousKeys[r.IntN(len(innocuousKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=%s&%s=verify-full",
			s, h, db, sk, randomHex(r, 16), nk))
	}

	// Secret AFTER non-secret.
	for i := 0; i < 40; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		nk := innocuousKeys[r.IntN(len(innocuousKeys))]
		sk := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=verify-full&%s=%s",
			s, h, db, nk, sk, randomHex(r, 16)))
	}

	// Secret in the MIDDLE of three+ params.
	for i := 0; i < 40; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		nk1 := innocuousKeys[r.IntN(len(innocuousKeys))]
		sk := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		nk2 := innocuousKeys[r.IntN(len(innocuousKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=verify-full&%s=%s&%s=myapp",
			s, h, db, nk1, sk, randomHex(r, 16), nk2))
	}

	// Multiple distinct secrets in the same query.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		// Pick 2-4 distinct secret keys.
		count := 2 + r.IntN(3)
		seen := make(map[string]bool, count)
		var parts []string
		for len(seen) < count {
			k := knownSecretKeys[r.IntN(len(knownSecretKeys))]
			if seen[k] {
				continue
			}
			seen[k] = true
			parts = append(parts, fmt.Sprintf("%s=%s", k, randomHex(r, 12)))
		}
		query := ""
		for j, p := range parts {
			if j > 0 {
				query += "&"
			}
			query += p
		}
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s", s, h, db, query))
	}

	// Repeated same secret key — both occurrences must redact.
	for i := 0; i < 15; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		k := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=%s&%s=%s",
			s, h, db, k, randomHex(r, 12), k, randomHex(r, 12)))
	}

	// Empty-value secret — must still redact to ****.
	for i := 0; i < 10; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		k := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		nk := innocuousKeys[r.IntN(len(innocuousKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=&%s=require", s, h, db, k, nk))
	}

	// Substring-bait next to a real secret — the bait must NOT
	// match, the real key MUST. Critical regression surface for
	// a future "lax substring" refactor.
	for i := 0; i < 30; i++ {
		s := schemes[r.IntN(len(schemes))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		bait := substringBait[r.IntN(len(substringBait))]
		sk := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s/%s?%s=ok&%s=%s",
			s, h, db, bait, sk, randomHex(r, 12)))
	}

	// Realistic PostgreSQL connection string with 3-4 structural
	// params and one secret.
	for i := 0; i < 25; i++ {
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		sk := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		inputs = append(inputs, fmt.Sprintf(
			"postgres://%s/%s?sslmode=verify-full&application_name=svc&%s=%s&connect_timeout=10",
			h, db, sk, randomHex(r, 16)))
	}

	// Realistic MongoDB connection string mixing replicaSet,
	// authSource, and a credential.
	for i := 0; i < 25; i++ {
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		sk := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		inputs = append(inputs, fmt.Sprintf(
			"mongodb://%s/%s?replicaSet=rs0&authSource=admin&%s=%s&w=majority",
			h, db, sk, randomHex(r, 16)))
	}

	// Userinfo + multi-param query — every leak surface combined.
	for i := 0; i < 25; i++ {
		s := schemes[r.IntN(len(schemes))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		sk := knownSecretKeys[r.IntN(len(knownSecretKeys))]
		nk := innocuousKeys[r.IntN(len(innocuousKeys))]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s/%s?%s=verify-full&%s=%s",
			s, u, p, h, db, nk, sk, randomHex(r, 16)))
	}

	// JDBC URLs across the major drivers. The current parser does
	// not understand the `jdbc:driver://` double-scheme so the rule
	// fails closed — the fixtures pin that contract so a future
	// JDBC-aware enhancement surfaces as a deliberate diff.
	jdbcDrivers := []string{
		"postgresql", "mysql", "mariadb", "sqlserver", "oracle:thin",
		"db2", "firebirdsql", "vertica", "snowflake", "clickhouse",
		"redshift", "cassandra",
	}
	for i := 0; i < 30; i++ {
		d := jdbcDrivers[r.IntN(len(jdbcDrivers))]
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		inputs = append(inputs, fmt.Sprintf("jdbc:%s://%s/%s?user=%s&password=%s", d, h, db, u, p))
	}

	// SQL Server JDBC with semicolon-separated property list — the
	// dominant SQL Server connection-string shape in Java
	// ecosystems.
	for i := 0; i < 15; i++ {
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		inputs = append(inputs, fmt.Sprintf(
			"jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s;encrypt=true",
			h, db, u, p))
	}

	// Oracle SQLPlus EZ-connect form: user/password@//host:port/service.
	for i := 0; i < 15; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		svc := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf("%s/%s@//%s:1521/%s", u, p, h, svc))
	}

	// Oracle TNS descriptor — never URL-shaped, always fail-closed
	// territory. Pin the contract.
	for i := 0; i < 10; i++ {
		h := hosts[r.IntN(len(hosts))]
		svc := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf(
			"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=%s)))",
			h, svc))
	}

	// libpq / psql key-value form — same shape as a Postgres
	// connection string but with space-separated `key=value` pairs.
	for i := 0; i < 15; i++ {
		h := hosts[r.IntN(len(hosts))]
		db := dbnames[r.IntN(len(dbnames))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		inputs = append(inputs, fmt.Sprintf(
			"host=%s port=5432 dbname=%s user=%s password=%s sslmode=verify-full",
			h, db, u, p))
	}

	// ADO.NET / SQL Server semicolon key=value blob. The parser
	// won't recognise this as a URL — fail-closed pinned.
	adoFields := []struct{ k, vfn string }{
		{"Server", "host"}, {"Database", "db"}, {"User Id", "user"},
		{"Password", "secret"}, {"Encrypt", "true"},
		{"TrustServerCertificate", "false"}, {"Integrated Security", "SSPI"},
	}
	for i := 0; i < 20; i++ {
		// Build 4-7 semicolon pairs.
		count := 4 + r.IntN(4)
		parts := make([]string, count)
		for j := 0; j < count; j++ {
			f := adoFields[r.IntN(len(adoFields))]
			var v string
			switch f.vfn {
			case "host":
				v = hosts[r.IntN(len(hosts))]
			case "db":
				v = dbnames[r.IntN(len(dbnames))]
			case "user":
				v = users[r.IntN(len(users))]
			case "secret":
				v = randomHex(r, 16)
			default:
				v = f.vfn
			}
			parts[j] = f.k + "=" + v
		}
		out := ""
		for j, p := range parts {
			if j > 0 {
				out += ";"
			}
			out += p
		}
		out += ";"
		inputs = append(inputs, out)
	}

	// Snowflake account URI shape.
	for i := 0; i < 10; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 24)
		acct := fmt.Sprintf("acct%d.region", r.IntN(1000))
		db := dbnames[r.IntN(len(dbnames))]
		inputs = append(inputs, fmt.Sprintf(
			"snowflake://%s:%s@%s.snowflakecomputing.com/%s?warehouse=WH&role=ROLE",
			u, p, acct, db))
	}

	// Elasticsearch HTTPS with basic auth.
	for i := 0; i < 10; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("https://%s:%s@%s:9200/_search", u, p, h))
	}

	// Neo4j bolt and bolt+s URIs.
	for i := 0; i < 10; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		scheme := []string{"bolt", "neo4j", "neo4j+s", "bolt+s"}[r.IntN(4)]
		inputs = append(inputs, fmt.Sprintf("%s://%s:%s@%s:7687", scheme, u, p, h))
	}

	// AMQP / RabbitMQ with vhost in path.
	for i := 0; i < 10; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		vhost := []string{"prod", "staging", "%2F"}[r.IntN(3)]
		inputs = append(inputs, fmt.Sprintf("amqp://%s:%s@%s:5672/%s", u, p, h, vhost))
	}

	// Cassandra/Scylla with contact-points and credentials in query.
	for i := 0; i < 10; i++ {
		h1 := hosts[r.IntN(len(hosts))]
		h2 := hosts[r.IntN(len(hosts))]
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		inputs = append(inputs, fmt.Sprintf(
			"cassandra://%s:9042,%s:9042/keyspace?username=%s&password=%s",
			h1, h2, u, p))
	}

	// DataStax-style with secure-connect-bundle path.
	for i := 0; i < 5; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 32)
		inputs = append(inputs, fmt.Sprintf(
			"cassandra://%s:%s@cloud.datastax.com/?secure_connect_bundle=/etc/scb.zip",
			u, p))
	}

	// MQTT with TLS userinfo.
	for i := 0; i < 5; i++ {
		u := users[r.IntN(len(users))]
		p := randomHex(r, 16)
		h := hosts[r.IntN(len(hosts))]
		inputs = append(inputs, fmt.Sprintf("mqtts://%s:%s@%s:8883/topic", u, p, h))
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

func init() {
	register("connection_string", connectionStringGen{})
}
