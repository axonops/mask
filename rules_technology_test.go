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
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/mask"
)

// ---------- ipv4_address ----------

func TestApply_IPv4Address(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "192.168.1.42", "192.168.*.*"},
		{"spec rfc1918", "10.0.0.1", "10.0.*.*"},
		{"empty", "", ""},
		{"zero address", "0.0.0.0", "0.0.*.*"},
		{"broadcast", "255.255.255.255", "255.255.*.*"},
		{"octet out of range fails closed", "999.999.999.999", "***************"},
		{"three octets fails closed", "192.168.1", "*********"},
		{"five octets fails closed", "1.2.3.4.5", "*********"},
		{"trailing dot fails closed", "192.168.1.42.", "*************"},
		{"leading dot fails closed", ".192.168.1.42", "*************"},
		{"cidr fails closed", "192.168.1.42/24", "***************"},
		{"hex fails closed", "0xC0.0xA8.0x01.0x2A", "*******************"},
		{"non-ascii digit fails closed", "١٩٢.١٦٨.١.٤٢", "************"},
		{"already masked ip fails closed", "192.168.*.*", "***********"},
		{"all-star equal length echoes as same-length", "***********", "***********"},
		{"space embedded fails closed", "192.168. 1.42", "*************"},
		{"4-digit octet fails closed", "1.2.3.1234", "**********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("ipv4_address", tc.in))
		})
	}
}

func TestApply_IPv4Address_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.Equal(t, "192.168.X.X", m.Apply("ipv4_address", "192.168.1.42"))
}

// ---------- ipv6_address ----------

func TestApply_IPv6Address(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:****:****:****:****"},
		{"spec compressed", "fe80::1", "fe80::****"},
		{"empty", "", ""},
		{"loopback", "::1", "::****"},
		{"compressed mid", "2001:db8::1", "2001:db8::****"},
		{"compressed mid two", "2001:db8::1:2", "2001:db8::****:****"},
		{"unspecified fails closed", "::", "**"},
		{"trailing compressed fails closed (no right)", "fe80::", "******"},
		{"uppercase hex", "FE80::1", "FE80::****"},
		{"ipv4 embedded fails closed", "::ffff:192.168.1.1", "******************"},
		{"zone id fails closed", "fe80::1%eth0", "************"},
		{"two compressions fails closed", "2001::1::1", "**********"},
		{"hextet too long fails closed", "20011:db8::1", "************"},
		{"non-hex fails closed", "2001:db8:gggg::1", "****************"},
		{"nine hextets fails closed", "1:2:3:4:5:6:7:8:9", "*****************"},
		{"seven hextets fails closed (no ::)", "1:2:3:4:5:6:7", "*************"},
		{"head compression overflowing preserve band fails closed", "::1:2:3:4:5:6:7", "***************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("ipv6_address", tc.in))
		})
	}
}

func TestApply_IPv6Address_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.Equal(t, "fe80::XXXX", m.Apply("ipv6_address", "fe80::1"))
}

// ---------- mac_address ----------

func TestApply_MACAddress(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec colon", "AA:BB:CC:DD:EE:FF", "AA:BB:CC:**:**:**"},
		{"spec hyphen", "AA-BB-CC-DD-EE-FF", "AA-BB-CC-**-**-**"},
		{"empty", "", ""},
		{"lowercase", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:**:**:**"},
		{"mixed case preserved", "Aa:bB:cC:dD:eE:fF", "Aa:bB:cC:**:**:**"},
		{"mixed separators fails closed", "AA:BB-CC:DD-EE:FF", "*****************"},
		{"dotted fails closed", "AABB.CCDD.EEFF", "**************"},
		{"no separators fails closed", "AABBCCDDEEFF", "************"},
		{"short fails closed", "AA:BB:CC:DD:EE", "**************"},
		{"non-hex fails closed", "AA:BB:CC:DD:EE:GG", "*****************"},
		{"all-zero", "00:00:00:00:00:00", "00:00:00:**:**:**"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("mac_address", tc.in))
		})
	}
}

// ---------- hostname ----------

func TestApply_Hostname(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "web-01.prod.example.com", "web-01.****.*******.***"},
		{"empty", "", ""},
		{"two labels", "example.com", "example.***"},
		{"single label fails closed", "db-master", "*********"},
		{"all-star equal length single-label fails closed", "*********", "*********"},
		{"trailing dot fails closed", "example.com.", "************"},
		{"leading dot fails closed", ".example.com", "************"},
		{"double dot fails closed", "foo..bar", "********"},
		{"uppercase first label preserved", "WEB-01.PROD.EXAMPLE.COM", "WEB-01.****.*******.***"},
		{"idn punycode", "xn--bcher-kva.example.com", "xn--bcher-kva.*******.***"},
		{"numeric first label", "42.example.com", "42.*******.***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("hostname", tc.in))
		})
	}
}

// ---------- url ----------

func TestApply_URL_SecurityPins(t *testing.T) {
	t.Parallel()
	m := mask.New()
	// Pin behaviour that a security review would otherwise catch as
	// a regression. All of these check that secret-bearing bytes
	// never pass through to the output unmasked.
	cases := []struct{ name, in, want string }{
		{"percent-encoded path preserves shape", "https://example.com/a%20b", "https://example.com/*****"},
		{"percent-encoded slash does not split segment", "https://example.com/a%2Fb", "https://example.com/*****"},
		{"trailing slash", "https://example.com/foo/", "https://example.com/***/"},
		{"double slash path", "https://example.com//a", "https://example.com//*"},
		{"bare-flag query is masked not echoed", "https://example.com/?AKIAIOSFODNN7EXAMPLE", "https://example.com/?********************"},
		{"empty-key query is masked", "https://example.com/?=secretvalue", "https://example.com/?************"},
		{"zone id in host fails closed", "https://[fe80::1%25eth0]/path", "*****************************"},
		{"non-ascii in host fails closed", "https://example\xffcom/x", "*********************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("url", tc.in))
		})
	}
}

func TestApply_URL(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "https://example.com/users/42?token=abc", "https://example.com/*****/**?token=****"},
		{"spec localhost port", "http://localhost:8080/api/v1", "http://localhost:8080/***/**"},
		{"empty", "", ""},
		{"no sensitive parts fails closed", "https://example.com", "*******************"},
		{"root path only fails closed", "https://example.com/", "********************"},
		{"userinfo defensively redacted", "https://alice:secret@example.com/path", "https://****:****@example.com/****"},
		{"userinfo user only", "https://alice@example.com/path", "https://****@example.com/****"},
		{"query only", "https://example.com?k=v", "https://example.com?k=****"},
		{"fragment only", "https://example.com#section", "https://example.com#****"},
		{"multiple query values", "https://example.com/?a=1&b=2&c=3", "https://example.com/?a=****&b=****&c=****"},
		{"bare query flag masked", "https://example.com/?flag", "https://example.com/?****"},
		{"malformed fails closed", "not a url", "*********"},
		{"data url fails closed", "data:text/plain,hello", "*********************"},
		{"ipv6 host", "https://[2001:db8::1]:8080/path", "https://[2001:db8::1]:8080/****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("url", tc.in))
		})
	}
}

// ---------- url_credentials ----------

func TestApply_ConnectionString_SecurityPins(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"case-insensitive secret key", "postgresql://db.example.com/d?Password=secret", "postgresql://db.example.com/d?Password=****"},
		{"all-caps secret key", "postgresql://db.example.com/d?PASSWORD=secret", "postgresql://db.example.com/d?PASSWORD=****"},
		{"bare flag masked when any secret present", "postgresql://db.example.com/d?password=x&SENSITIVE_FLAG", "postgresql://db.example.com/d?password=****&**************"},
		{"empty key pair masked", "postgresql://u:p@db.example.com/d?=secretvalue", "postgresql://****:****@db.example.com/d?************"},
		{"fragment masked", "postgresql://u:p@db.example.com/d#readonly", "postgresql://****:****@db.example.com/d#****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("connection_string", tc.in))
		})
	}
}

func TestApply_URLCredentials(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "https://admin:s3cret@db.example.com/mydb", "https://****:****@db.example.com/mydb"},
		{"empty", "", ""},
		{"no userinfo fails closed", "https://db.example.com/mydb", "***************************"},
		{"user only", "https://alice@example.com/mydb", "https://****@example.com/mydb"},
		{"preserves path verbatim", "https://u:p@example.com/secret/data", "https://****:****@example.com/secret/data"},
		{"preserves query verbatim", "https://u:p@example.com/?token=abc", "https://****:****@example.com/?token=abc"},
		{"malformed fails closed", "nope", "****"},
		{"ipv6 host", "https://u:p@[2001:db8::1]/mydb", "https://****:****@[2001:db8::1]/mydb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("url_credentials", tc.in))
		})
	}
}

// ---------- api_key ----------

func TestApply_APIKey(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec stripe-like", "sk_live_abc123def456ghi789", "sk_l******************i789"},
		{"spec aws", "AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"empty", "", ""},
		{"length exactly eight fails closed", "12345678", "********"},
		{"length nine keeps endpoints", "123456789", "1234*6789"},
		{"short fails closed", "x", "*"},
		{"four fails closed", "1234", "****"},
		{"unicode prefix preserved", "🔑🔑🔑🔑1234567890", "🔑🔑🔑🔑******7890"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("api_key", tc.in))
		})
	}
}

// ---------- jwt_token ----------

func TestApply_JWT(t *testing.T) {
	t.Parallel()
	m := mask.New()
	canonical := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	cases := []struct{ name, in, want string }{
		{"spec canonical", canonical, "eyJh****.****.****."},
		{"empty", "", ""},
		{"two segments fails closed", "aaaa.bbbb", "*********"},
		{"four segments fails closed", "aaaa.bbbb.cccc.dddd", "*******************"},
		{"header shorter than four fails closed", "ey.payload.sig", "**************"},
		{"empty payload fails closed", "eyJh..sig", "*********"},
		{"empty signature fails closed", "eyJh.payload.", "*************"},
		{"non-base64url fails closed", "eyJh.pay@load.sig", "*****************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("jwt_token", tc.in))
		})
	}
}

// ---------- bearer_token ----------

func TestApply_BearerToken(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec jwt", "Bearer eyJhbGciOiJIUzI1NiJ9.xxx.yyy", "Bearer eyJhbG****..."},
		{"spec opaque", "Bearer abc123def456", "Bearer abc123****..."},
		{"empty", "", ""},
		{"short token fails closed", "Bearer abc", "**********"},
		{"wrong scheme fails closed", "Basic dXNlcjpwYXNz", "******************"},
		{"lowercase scheme fails closed", "bearer abcdef123", "****************"},
		{"no scheme fails closed", "abc123def456", "************"},
		{"empty token after scheme fails closed", "Bearer ", "*******"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("bearer_token", tc.in))
		})
	}
}

// ---------- password ----------

func TestApply_Password(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "MyP@ssw0rd!", "********"},
		{"spec single rune", "x", "********"},
		{"empty preserves empty", "", ""},
		{"unicode", "メトホルミン", "********"},
		{"length is eight regardless", strings.Repeat("a", 500), "********"},
		{"already masked", "********", "********"},
		{"nul byte", "\x00", "********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("password", tc.in))
		})
	}
}

func TestApply_Password_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.Equal(t, "XXXXXXXX", m.Apply("password", "MyP@ssw0rd!"))
	// Configured mask char is honoured on empty input — stays empty.
	assert.Equal(t, "", m.Apply("password", ""))
}

// ---------- private_key_pem ----------

func TestApply_PrivateKeyPEM(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in string }{
		{"spec canonical", "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."},
		{"empty is still full redact", ""},
		{"garbage input", "\xff\xfe\xfd"},
		{"very long", strings.Repeat("A", 10000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, "[REDACTED]", m.Apply("private_key_pem", tc.in))
		})
	}
}

// ---------- connection_string ----------

func TestApply_ConnectionString(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec postgres", "postgresql://admin:s3cret@db.example.com:5432/myapp", "postgresql://****:****@db.example.com:5432/myapp"},
		{"spec mongo srv", "mongodb+srv://user:pass@cluster.mongodb.net/db", "mongodb+srv://****:****@cluster.mongodb.net/db"},
		{"empty", "", ""},
		{"no userinfo or secrets fails closed", "postgresql://db.example.com:5432/myapp", "**************************************"},
		{"user only", "postgresql://u@db.example.com/d", "postgresql://****@db.example.com/d"},
		{"secret query only", "postgresql://db.example.com/d?password=secret", "postgresql://db.example.com/d?password=****"},
		{"non-secret query preserved", "postgresql://u:p@db.example.com/d?sslmode=verify-full", "postgresql://****:****@db.example.com/d?sslmode=verify-full"},
		{"mixed query", "postgresql://db.example.com/d?user=u&password=p&sslmode=require", "postgresql://db.example.com/d?user=u&password=****&sslmode=require"},
		{"malformed fails closed", "not a connection string", "***********************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("connection_string", tc.in))
		})
	}
}

// TestApply_ConnectionString_OAuthAndCloudSecrets pins redaction
// of OAuth, cloud-provider, and Azure-style secret query parameters
// that the original secretQueryKeys list at rules_technology.go:79
// did not cover. Each case sits on a well-formed authority URL so
// the rule reaches the query-parsing path rather than falling back
// to same-length mask.
func TestApply_ConnectionString_OAuthAndCloudSecrets(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"oauth client_secret", "postgres://user@host/db?client_secret=abc123", "postgres://****@host/db?client_secret=****"},
		{"oauth refresh_token", "postgres://user@host/db?refresh_token=rt-xyz", "postgres://****@host/db?refresh_token=****"},
		{"oauth id_token", "postgres://user@host/db?id_token=eyJabc", "postgres://****@host/db?id_token=****"},
		{"aws secret access key", "postgres://user@host/db?aws_secret_access_key=AKIAEX", "postgres://****@host/db?aws_secret_access_key=****"},
		{"private_key", "postgres://user@host/db?private_key=PEMbody", "postgres://****@host/db?private_key=****"},
		{"azure connectionstring", "postgres://user@host/db?connectionstring=Server%3Db1", "postgres://****@host/db?connectionstring=****"},
		{"signature", "postgres://user@host/db?signature=base64data", "postgres://****@host/db?signature=****"},
		{"sig short form", "postgres://user@host/db?sig=abcdef", "postgres://****@host/db?sig=****"},
		{"sas token", "postgres://user@host/db?sas=svxyz", "postgres://****@host/db?sas=****"},
		{"bearer in query", "postgres://user@host/db?bearer=ya29.A0Ab", "postgres://****@host/db?bearer=****"},
		{"upper case key", "postgres://user@host/db?CLIENT_SECRET=abc", "postgres://****@host/db?CLIENT_SECRET=****"},
		{"percent-encoded key", "postgres://user@host/db?client%5Fsecret=abc", "postgres://****@host/db?client%5Fsecret=****"},
		{"mixed with non-secret", "postgres://host/db?sslmode=verify-full&client_secret=abc", "postgres://host/db?sslmode=verify-full&client_secret=****"},
		{"existing password key untouched", "postgres://host/db?password=plain", "postgres://host/db?password=****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("connection_string", tc.in))
		})
	}
}

// TestApply_ConnectionString_PassKey pins redaction of the `pass`
// short-form password parameter. The corpus generator's
// knownSecretKeys list at tests/corpus/gen/connection_string.go:90
// always included `pass`, but the rule's own secretQueryKeys map
// at rules_technology.go was missing it, so `?pass=...` inputs fell
// through the secret-detection path and failed closed entirely
// rather than redacting the value. Fix landed in #82.
func TestApply_ConnectionString_PassKey(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"bare pass key",
			"postgres://host/db?pass=secret",
			"postgres://host/db?pass=****"},
		{"pass before non-secret",
			"postgres://host/db?pass=secret&sslmode=verify-full",
			"postgres://host/db?pass=****&sslmode=verify-full"},
		{"pass after non-secret",
			"postgres://host/db?sslmode=verify-full&pass=secret",
			"postgres://host/db?sslmode=verify-full&pass=****"},
		{"uppercase PASS",
			"postgres://host/db?PASS=secret",
			"postgres://host/db?PASS=****"},
		{"mixed-case Pass",
			"postgres://host/db?Pass=secret",
			"postgres://host/db?Pass=****"},
		{"percent-encoded key pa%73s decodes to pass",
			"postgres://host/db?pa%73s=secret",
			"postgres://host/db?pa%73s=****"},
		// Substring-bait safety: `passcode_label` contains `pass`
		// as a substring but must NOT match the whole-key lookup.
		// Paired with a real `pass=` so the rule reaches the
		// query-parsing path rather than failing closed for lack
		// of any recognised secret.
		{"substring-bait passcode_label not matched, real pass alongside",
			"postgres://host/db?passcode_label=visible&pass=secret",
			"postgres://host/db?passcode_label=visible&pass=****"},
		// Substring-bait on its own (no real secret): rule sees no
		// recognised secret and no userinfo, so it falls back to
		// SameLengthMask of the whole input. Pins the fail-closed
		// gate so `passcode_label` cannot accidentally start matching.
		{"substring-bait passcode_label alone fails closed",
			"postgres://host/db?passcode_label=visible",
			"*****************************************"},
		// Empty value — the writer still emits the redaction marker
		// rather than echoing the empty value, mirroring the
		// password-key behaviour. Pinned so a future refactor
		// cannot start leaking empty-value secrets.
		{"empty value pass=",
			"postgres://host/db?pass=",
			"postgres://host/db?pass=****"},
		// Bare flag at end of query, no `=`, paired with a real
		// secret so the writer is reached. `pass` with no value
		// is same-length-masked by writeConnStringPair.
		{"bare pass flag paired with real secret",
			"postgres://host/db?pass&password=secret",
			"postgres://host/db?****&password=****"},
		// Duplicate key — each occurrence redacts.
		{"duplicate pass= keys",
			"postgres://host/db?pass=a&pass=b",
			"postgres://host/db?pass=****&pass=****"},
		// All four members of the short-form family side by side.
		{"full password family together",
			"postgres://host/db?password=a&passwd=b&pass=c&pwd=d",
			"postgres://host/db?password=****&passwd=****&pass=****&pwd=****"},
		// Co-existence with the documented password / passwd / pwd
		// family — every member of the family redacts.
		{"password sibling still redacts",
			"postgres://host/db?password=secret",
			"postgres://host/db?password=****"},
		{"passwd sibling still redacts",
			"postgres://host/db?passwd=secret",
			"postgres://host/db?passwd=****"},
		{"pwd sibling still redacts",
			"postgres://host/db?pwd=secret",
			"postgres://host/db?pwd=****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("connection_string", tc.in))
		})
	}
}

// TestApply_ConnectionString_SecretKeysSupersetGenerator pins the
// rule's secretQueryKeys set as a superset of the corpus generator's
// knownSecretKeys list. The two lists diverged once — the rule
// missed `pass` while the generator included it — and the corpus
// silently locked the divergence in as fail-closed pins because the
// corpus uses the rule itself as its oracle. This test prevents a
// recurrence: any future addition to the generator's known list
// must also appear in the rule. Mirrors the list at
// tests/corpus/gen/connection_string.go:88-95.
func TestApply_ConnectionString_SecretKeysSupersetGenerator(t *testing.T) {
	t.Parallel()
	m := mask.New()
	generatorKnown := []string{
		"password", "passwd", "pass", "pwd",
		"secret", "apikey", "api_key", "auth_token", "access_token", "token",
		"client_secret", "client_credentials", "refresh_token", "id_token",
		"aws_secret_access_key", "private_key", "sas", "sastoken",
		"signature", "sig", "connectionstring", "bearer", "authorization",
	}
	for _, k := range generatorKnown {
		t.Run(k, func(t *testing.T) {
			in := "postgres://host/db?" + k + "=secret"
			want := "postgres://host/db?" + k + "=****"
			assert.Equal(t, want, m.Apply("connection_string", in),
				"generator's knownSecretKeys[%q] must redact through the rule", k)
		})
	}
}

// TestApply_ConnectionString_MultiParamQuery pins the per-pair
// behaviour of the query masker when multiple parameters appear in
// any position relative to a secret. PostgreSQL, MongoDB, and
// MySQL/MariaDB connection strings routinely chain non-secret
// structural params (`sslmode`, `application_name`, `connectTimeout`,
// `replicaSet`) with credential params, and the rule must redact
// only the secret values regardless of order, count, or repetition.
func TestApply_ConnectionString_MultiParamQuery(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		// Secret BEFORE non-secret.
		{"secret first then non-secret",
			"postgres://host/db?client_secret=abc&sslmode=verify-full",
			"postgres://host/db?client_secret=****&sslmode=verify-full"},

		// Secret AFTER non-secret.
		{"non-secret first then secret",
			"postgres://host/db?sslmode=verify-full&password=plain",
			"postgres://host/db?sslmode=verify-full&password=****"},

		// Secret in the MIDDLE.
		{"secret between two non-secrets",
			"postgres://host/db?sslmode=verify-full&client_secret=abc&application_name=myapp",
			"postgres://host/db?sslmode=verify-full&client_secret=****&application_name=myapp"},

		// Two adjacent secrets — both must redact.
		{"two adjacent secrets",
			"postgres://host/db?client_secret=abc&refresh_token=def",
			"postgres://host/db?client_secret=****&refresh_token=****"},

		// Four different secret keywords in one query.
		{"four secrets of different keywords",
			"postgres://host/db?token=t&secret=s&apikey=k&password=p",
			"postgres://host/db?token=****&secret=****&apikey=****&password=****"},

		// Repeated same key — both occurrences must redact.
		{"repeated same secret key",
			"postgres://host/db?password=a&password=b",
			"postgres://host/db?password=****&password=****"},

		// Realistic PostgreSQL mix: structural sandwich + secret.
		{"postgres realistic mix",
			"postgres://host/db?application_name=myapp&password=secret&sslmode=require",
			"postgres://host/db?application_name=myapp&password=****&sslmode=require"},

		// MongoDB-style with auth + replicaSet + secret.
		{"mongodb mix with replicaSet",
			"mongodb://host/db?replicaSet=rs0&authSource=admin&password=hunter2&w=majority",
			"mongodb://host/db?replicaSet=rs0&authSource=admin&password=****&w=majority"},

		// Five secrets of distinct families redacted together.
		{"five secrets across families",
			"postgres://host/db?password=p&client_secret=c&refresh_token=r&aws_secret_access_key=a&private_key=k",
			"postgres://host/db?password=****&client_secret=****&refresh_token=****&aws_secret_access_key=****&private_key=****"},

		// Secret with empty value still masks.
		{"empty-value secret still masks",
			"postgres://host/db?password=&sslmode=require",
			"postgres://host/db?password=****&sslmode=require"},

		// Non-secret key whose name CONTAINS a secret keyword as a
		// substring (`secretsauce`, `application_name`, `my_token_id`)
		// must NOT be matched — the lookup is whole-key, not
		// substring. Pinning this prevents a future "lax substring
		// match" refactor from over-masking innocuous keys.
		{"secret-substring keys not matched",
			"postgres://user@host/db?secretsauce=ok&my_token_id=abc&application_name=myapp",
			"postgres://****@host/db?secretsauce=ok&my_token_id=abc&application_name=myapp"},

		// Non-secret key whose name HAPPENS to contain `secret` as a
		// substring sits next to a genuine `secret=` param.
		{"substring next to real secret",
			"postgres://host/db?secretsauce=ok&secret=actual",
			"postgres://host/db?secretsauce=ok&secret=****"},

		// Mixed: userinfo + multiple params + secret in middle.
		{"userinfo plus mixed query",
			"postgres://admin:adminpwd@db.example.com:5432/myapp?sslmode=require&client_secret=osc&application_name=svc",
			"postgres://****:****@db.example.com:5432/myapp?sslmode=require&client_secret=****&application_name=svc"},

		// JDBC-style with user/password as separate query params:
		// the current parser does not understand the `jdbc:postgresql://`
		// double-scheme form so the rule fails closed. Pin the
		// behaviour here so a future JDBC enhancement surfaces as
		// a deliberate change to this assertion.
		{"jdbc double-scheme fails closed",
			"jdbc:postgresql://host/db?user=admin&password=hunter2&ssl=true",
			"**************************************************************"},

		// Query parameter values that contain a literal `=` sign.
		// The first `=` separates key from value; subsequent `=`
		// signs are part of the value and must not confuse the
		// matcher.
		{"value contains equals sign",
			"postgres://host/db?signature=base64=padded==&sslmode=require",
			"postgres://host/db?signature=****&sslmode=require"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("connection_string", tc.in))
		})
	}
}

// ---------- database_dsn ----------

func TestApply_DatabaseDSN(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "user:password@tcp(localhost:3306)/dbname", "****:****@tcp(localhost:3306)/dbname"},
		{"empty", "", ""},
		{"unix socket", "user:pass@unix(/tmp/mysql.sock)/dbname", "****:****@unix(/tmp/mysql.sock)/dbname"},
		{"with params", "user:pass@tcp(host:3306)/db?parseTime=true&loc=Local", "****:****@tcp(host:3306)/db?parseTime=true&loc=Local"},
		{"user only", "user@tcp(host)/db", "****@tcp(host)/db"},
		{"no protocol fails closed", "user:pass@host/db", "*****************"},
		{"malformed fails closed", "nope", "****"},
		{"ambiguous multiple @protocol fails closed", "u@tcp(x)/d@tcp(y)/e", "*******************"},
		{"at-sign in password disambiguated", "u:p@ss@tcp(host:3306)/db", "****:****@tcp(host:3306)/db"},
		{"unterminated protocol fails closed", "u:p@tcp(", "********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("database_dsn", tc.in))
		})
	}
}

// TestApply_DatabaseDSN_QueryParamSecrets pins the redaction of
// known-secret query parameters in DSN form. Reuses the same
// curated keyword set as connection_string (rules_technology.go:79),
// so the OAuth, AWS, Azure, signature, and credential families all
// flow through `isSecretKey`. Surfaced by the multi-param corpus
// pins added in #54; fixed in #72.
func TestApply_DatabaseDSN_QueryParamSecrets(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"secret query alone",
			"root:rootpwd@tcp(localhost:3306)/db?password=other",
			"****:****@tcp(localhost:3306)/db?password=****"},
		{"secret AFTER non-secret",
			"user:pass@tcp(host:3306)/db?charset=utf8mb4&password=leak",
			"****:****@tcp(host:3306)/db?charset=utf8mb4&password=****"},
		{"secret BEFORE non-secret",
			"user:pass@tcp(host:3306)/db?password=leak&charset=utf8mb4",
			"****:****@tcp(host:3306)/db?password=****&charset=utf8mb4"},
		{"secret in MIDDLE of three params",
			"user:pass@tcp(host:3306)/db?parseTime=true&password=leak&loc=UTC",
			"****:****@tcp(host:3306)/db?parseTime=true&password=****&loc=UTC"},
		{"multiple distinct secrets",
			"user:pass@tcp(host:3306)/db?token=t&password=p&secret=s",
			"****:****@tcp(host:3306)/db?token=****&password=****&secret=****"},
		{"repeated same secret",
			"user:pass@tcp(host:3306)/db?password=a&password=b",
			"****:****@tcp(host:3306)/db?password=****&password=****"},
		{"oauth client_secret",
			"user:pass@tcp(host:3306)/db?client_secret=abc",
			"****:****@tcp(host:3306)/db?client_secret=****"},
		{"aws secret access key",
			"user:pass@tcp(host:3306)/db?aws_secret_access_key=AKIAEX",
			"****:****@tcp(host:3306)/db?aws_secret_access_key=****"},
		{"private_key",
			"user:pass@tcp(host:3306)/db?private_key=PEMbody",
			"****:****@tcp(host:3306)/db?private_key=****"},
		{"unix socket with secret",
			"user:pass@unix(/tmp/mysql.sock)/dbname?password=p&charset=utf8mb4",
			"****:****@unix(/tmp/mysql.sock)/dbname?password=****&charset=utf8mb4"},
		{"upper-case secret key",
			"user:pass@tcp(host:3306)/db?PASSWORD=leak",
			"****:****@tcp(host:3306)/db?PASSWORD=****"},
		{"substring-bait key not matched",
			"user:pass@tcp(host:3306)/db?secretsauce=ok&password=leak",
			"****:****@tcp(host:3306)/db?secretsauce=ok&password=****"},
		{"empty value still redacts",
			"user:pass@tcp(host:3306)/db?password=&charset=utf8mb4",
			"****:****@tcp(host:3306)/db?password=****&charset=utf8mb4"},
		{"all non-secret params pass through",
			"user:pass@tcp(host:3306)/db?charset=utf8mb4&parseTime=true&loc=UTC",
			"****:****@tcp(host:3306)/db?charset=utf8mb4&parseTime=true&loc=UTC"},
		// Percent-encoded characters in the key are decoded before
		// the secretQueryKeys lookup — `pass%77ord` decodes to
		// `password`. Pin this so a future refactor that drops the
		// QueryUnescape step (rules_technology.go:957) doesn't
		// silently leak via percent-encoding bypass.
		{"percent-encoded secret key still redacts",
			"user:pass@tcp(host:3306)/db?pass%77ord=leak",
			"****:****@tcp(host:3306)/db?pass%77ord=****"},
		// Bare flags are malformed per Go MySQL DSN grammar (which
		// requires explicit `key=value`); the rule conservatively
		// length-masks them rather than echoing bytes whose role is
		// ambiguous. Documented in RuleInfo.Description.
		{"bare flag length-masked",
			"user:pass@tcp(host:3306)/db?parseTime",
			"****:****@tcp(host:3306)/db?*********"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("database_dsn", tc.in))
		})
	}
}

// ---------- uuid ----------

func TestApply_UUID(t *testing.T) {
	t.Parallel()
	m := mask.New()
	cases := []struct{ name, in, want string }{
		{"spec canonical", "550e8400-e29b-41d4-a716-446655440000", "550e8400-****-****-****-********0000"},
		{"empty", "", ""},
		{"uppercase preserved", "550E8400-E29B-41D4-A716-446655440000", "550E8400-****-****-****-********0000"},
		{"nil uuid", "00000000-0000-0000-0000-000000000000", "00000000-****-****-****-********0000"},
		{"hyphenless fails closed", "550e8400e29b41d4a716446655440000", "********************************"},
		{"braced fails closed", "{550e8400-e29b-41d4-a716-446655440000}", "**************************************"},
		{"wrong length fails closed", "550e8400-e29b-41d4-a716-44665544000", "***********************************"},
		{"non-hex fails closed", "550e8400-e29b-41d4-a716-44665544000g", "************************************"},
		{"hyphen wrong position fails closed", "550e84-00e29b-41d4-a716-446655440000", "************************************"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply("uuid", tc.in))
		})
	}
}

// TestTechnology_MaskCharOverride confirms every rule that emits mask
// runes honours the per-instance mask character. One representative
// input per rule.
func TestTechnology_MaskCharOverride(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	cases := []struct{ rule, in, want string }{
		{"ipv4_address", "192.168.1.42", "192.168.X.X"},
		{"ipv6_address", "fe80::1", "fe80::XXXX"},
		{"mac_address", "AA:BB:CC:DD:EE:FF", "AA:BB:CC:XX:XX:XX"},
		{"hostname", "web-01.prod.example.com", "web-01.XXXX.XXXXXXX.XXX"},
		{"url", "https://example.com/users/42?token=abc", "https://example.com/XXXXX/XX?token=XXXX"},
		{"url_credentials", "https://admin:s3cret@db.example.com/mydb", "https://XXXX:XXXX@db.example.com/mydb"},
		{"api_key", "AKIAIOSFODNN7EXAMPLE", "AKIAXXXXXXXXXXXXMPLE"},
		// JWT: trailing dot is a literal format token, NOT the mask
		// character — stays as `.` regardless of WithMaskChar.
		{"jwt_token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig", "eyJhXXXX.XXXX.XXXX."},
		// Bearer: trailing `...` is a literal elision marker, NOT the
		// mask character — stays as literal `...` regardless.
		{"bearer_token", "Bearer abc123def456", "Bearer abc123XXXX..."},
		{"connection_string", "postgresql://admin:s3cret@db.example.com:5432/myapp", "postgresql://XXXX:XXXX@db.example.com:5432/myapp"},
		{"database_dsn", "user:password@tcp(localhost:3306)/dbname", "XXXX:XXXX@tcp(localhost:3306)/dbname"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", "550e8400-XXXX-XXXX-XXXX-XXXXXXXX0000"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Apply(tc.rule, tc.in))
		})
	}
}

// ---------- registrations and metadata ----------

func TestDescribe_TechnologyRules(t *testing.T) {
	t.Parallel()
	m := mask.New()
	names := []string{
		"ipv4_address", "ipv6_address", "mac_address", "hostname",
		"url", "url_credentials", "api_key", "jwt_token", "bearer_token",
		"password", "private_key_pem", "connection_string", "database_dsn", "uuid",
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			info, ok := m.Describe(n)
			require.True(t, ok, "rule %q not registered", n)
			assert.Equal(t, "technology", info.Category)
			assert.NotEmpty(t, info.Jurisdiction)
			assert.NotEmpty(t, info.Description)
			assert.Equal(t, n, info.Name)
			assert.Contains(t, info.Description, "Example:",
				"rule %q description must include an Example", n)
		})
	}
}

// TestTechnology_FailClosedOnMalformed confirms every rule either
// falls back to SameLengthMask or (for full-redact rules) returns
// the constant marker, never echoing an obviously-malformed input.
func TestTechnology_FailClosedOnMalformed(t *testing.T) {
	t.Parallel()
	m := mask.New()
	malformed := "not-a-valid-anything-of-any-kind-xx"
	// api_key is parserless — any input ≥ 9 runes gets keep-first-last
	// masking, so "malformed" is not a meaningful concept for that rule.
	structuralRules := []string{
		"ipv4_address", "ipv6_address", "mac_address", "hostname",
		"url", "url_credentials", "jwt_token", "bearer_token",
		"connection_string", "database_dsn", "uuid",
	}
	for _, n := range structuralRules {
		t.Run(n, func(t *testing.T) {
			got := m.Apply(n, malformed)
			assert.NotEqual(t, malformed, got, "rule %q echoed malformed input", n)
			assert.Equal(t, strings.Repeat("*", utf8.RuneCountInString(malformed)), got,
				"rule %q did not produce same-length mask on malformed input", n)
		})
	}
	// Full-redact rules.
	assert.Equal(t, "[REDACTED]", m.Apply("private_key_pem", malformed))
	// password masks to fixed 8.
	assert.Equal(t, "********", m.Apply("password", malformed))
}

// TestTechnology_NoPanicOnAdversarialInput mirrors the health
// category's contract: every rule must handle adversarial bytes
// without panicking and must emit well-formed UTF-8.
func TestTechnology_NoPanicOnAdversarialInput(t *testing.T) {
	t.Parallel()
	m := mask.New()
	adversarial := []string{
		"",
		"\xff\xfe\xfd",
		"\x00",
		strings.Repeat("x", 1000),
		"https://\x00example.com/",
		"https://u:p@[2001:db8::\u202E]/x",
		"\u200Bhttps://example.com/",
	}
	names := []string{
		"ipv4_address", "ipv6_address", "mac_address", "hostname",
		"url", "url_credentials", "api_key", "jwt_token", "bearer_token",
		"password", "private_key_pem", "connection_string", "database_dsn", "uuid",
	}
	for _, n := range names {
		for _, in := range adversarial {
			var got string
			assert.NotPanics(t, func() { got = m.Apply(n, in) },
				"rule %q panicked on input %q", n, in)
			assert.True(t, utf8.ValidString(got),
				"rule %q produced invalid UTF-8 for input %q: %q", n, in, got)
		}
	}
}

// TestTechnology_IdempotencyMatrix pins, per rule, whether applying
// the rule to its own output yields the same output. Regressions in
// either direction surface bugs.
func TestTechnology_IdempotencyMatrix(t *testing.T) {
	t.Parallel()
	m := mask.New()
	idempotent := []struct {
		name, in string
	}{
		{"hostname", "web-01.prod.example.com"},
		{"url", "https://example.com/users/42?token=abc"},
		{"url_credentials", "https://admin:s3cret@db.example.com/mydb"},
		{"api_key", "AKIAIOSFODNN7EXAMPLE"},
		{"bearer_token", "Bearer abc123def456"},
		{"password", "MyP@ssw0rd!"},
		{"private_key_pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."},
		{"connection_string", "postgresql://admin:s3cret@db.example.com:5432/myapp"},
		{"database_dsn", "user:password@tcp(localhost:3306)/dbname"},
	}
	for _, tc := range idempotent {
		t.Run(tc.name+"/idempotent", func(t *testing.T) {
			first := m.Apply(tc.name, tc.in)
			second := m.Apply(tc.name, first)
			assert.Equal(t, first, second, "rule %q was expected to be idempotent", tc.name)
		})
	}
	// Non-idempotent rules: applying to own output routes to
	// SameLengthMask because the mask rune is not a valid input token
	// for the rule's parser.
	nonIdempotent := []struct {
		name, in string
	}{
		{"ipv4_address", "192.168.1.42"},
		{"ipv6_address", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"mac_address", "AA:BB:CC:DD:EE:FF"},
		{"jwt_token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000"},
	}
	for _, tc := range nonIdempotent {
		t.Run(tc.name+"/non-idempotent", func(t *testing.T) {
			first := m.Apply(tc.name, tc.in)
			second := m.Apply(tc.name, first)
			assert.NotEqual(t, first, second,
				"rule %q was expected to NOT be idempotent (output collapses to same-length mask)", tc.name)
		})
	}
}
