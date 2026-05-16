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

package mask_test

import (
	"strings"
	"testing"

	"github.com/axonops/mask"
)

var techSink string

// runBench is a tiny helper that centralises the b.ReportAllocs + loop
// boilerplate so per-rule benchmarks stay single-line.
func runBench(b *testing.B, rule, in string) {
	b.Helper()
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply(rule, in)
	}
	techSink = s
}

// ---------- ipv4_address ----------

func BenchmarkApply_ipv4_address(b *testing.B)         { runBench(b, "ipv4_address", "192.168.1.42") }
func BenchmarkApply_ipv4_address_invalid(b *testing.B) { runBench(b, "ipv4_address", "not.an.ip.here") }

// ---------- ipv6_address ----------

func BenchmarkApply_ipv6_address_full(b *testing.B) {
	runBench(b, "ipv6_address", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
}
func BenchmarkApply_ipv6_address_compressed(b *testing.B) { runBench(b, "ipv6_address", "fe80::1") }
func BenchmarkApply_ipv6_address_invalid(b *testing.B) {
	runBench(b, "ipv6_address", "2001:db8:gggg::1")
}

// ---------- mac_address ----------

func BenchmarkApply_mac_address(b *testing.B) { runBench(b, "mac_address", "AA:BB:CC:DD:EE:FF") }
func BenchmarkApply_mac_address_invalid(b *testing.B) {
	runBench(b, "mac_address", "AA.BB.CC.DD.EE.FF")
}

// ---------- hostname ----------

func BenchmarkApply_hostname(b *testing.B) { runBench(b, "hostname", "web-01.prod.example.com") }
func BenchmarkApply_hostname_single_label(b *testing.B) {
	runBench(b, "hostname", "db-master")
}

// ---------- url ----------

func BenchmarkApply_url(b *testing.B) {
	runBench(b, "url", "https://example.com/users/42?token=abc")
}
func BenchmarkApply_url_long(b *testing.B) {
	long := "https://example.com/" + strings.Repeat("seg/", 50) + "?" + strings.Repeat("k=v&", 20) + "end=1"
	runBench(b, "url", long)
}
func BenchmarkApply_url_invalid(b *testing.B) { runBench(b, "url", "not a url") }

// ---------- url_credentials ----------

func BenchmarkApply_url_credentials(b *testing.B) {
	runBench(b, "url_credentials", "https://admin:s3cret@db.example.com/mydb")
}
func BenchmarkApply_url_credentials_invalid(b *testing.B) {
	runBench(b, "url_credentials", "not-a-url-at-all")
}

// ---------- api_key ----------

func BenchmarkApply_api_key(b *testing.B) { runBench(b, "api_key", "AKIAIOSFODNN7EXAMPLE") }
func BenchmarkApply_api_key_long(b *testing.B) {
	runBench(b, "api_key", "sk_live_"+strings.Repeat("x", 500))
}
func BenchmarkApply_api_key_short(b *testing.B) { runBench(b, "api_key", "abc") }

// ---------- jwt_token ----------

func BenchmarkApply_jwt_token(b *testing.B) {
	runBench(b, "jwt_token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
}
func BenchmarkApply_jwt_token_invalid(b *testing.B) { runBench(b, "jwt_token", "not.a.jwt.extra") }

// ---------- bearer_token ----------

func BenchmarkApply_bearer_token(b *testing.B) {
	runBench(b, "bearer_token", "Bearer abc123def456")
}
func BenchmarkApply_bearer_token_unknown_scheme(b *testing.B) {
	runBench(b, "bearer_token", "Basic dXNlcjpwYXNz")
}

// ---------- password ----------

func BenchmarkApply_password(b *testing.B)       { runBench(b, "password", "MyP@ssw0rd!") }
func BenchmarkApply_password_empty(b *testing.B) { runBench(b, "password", "") }

// ---------- private_key_pem ----------

func BenchmarkApply_private_key_pem(b *testing.B) {
	runBench(b, "private_key_pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
}

// ---------- connection_string ----------

func BenchmarkApply_connection_string(b *testing.B) {
	runBench(b, "connection_string", "postgresql://admin:s3cret@db.example.com:5432/myapp")
}
func BenchmarkApply_connection_string_secret_query(b *testing.B) {
	runBench(b, "connection_string", "postgresql://db.example.com/d?user=u&password=p&sslmode=require")
}

// ---------- database_dsn ----------

func BenchmarkApply_database_dsn(b *testing.B) {
	runBench(b, "database_dsn", "user:password@tcp(localhost:3306)/dbname")
}
func BenchmarkApply_database_dsn_invalid(b *testing.B) {
	runBench(b, "database_dsn", "nothing at all like a dsn")
}

// BenchmarkApply_database_dsn_tcp6 pins the IPv6 path's hot-loop
// overhead under the closed-allowlist matcher introduced in #83.
func BenchmarkApply_database_dsn_tcp6(b *testing.B) {
	runBench(b, "database_dsn", "user:password@tcp6([2001:db8::1]:3306)/dbname")
}

// BenchmarkApply_database_dsn_unlisted_protocol exercises the
// fail-closed path for a protocol that lexes as `[a-z]+\(` but
// is outside the closed allowlist (#83). Confirms the rejection
// path stays cheap and allocation-free.
func BenchmarkApply_database_dsn_unlisted_protocol(b *testing.B) {
	runBench(b, "database_dsn", "user:password@quic(localhost:3306)/dbname")
}

// ---------- uuid ----------

func BenchmarkApply_uuid(b *testing.B) {
	runBench(b, "uuid", "550e8400-e29b-41d4-a716-446655440000")
}
func BenchmarkApply_uuid_invalid(b *testing.B) {
	runBench(b, "uuid", "550e8400-e29b-41d4-a716-44665544000g")
}
