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
	"testing"
	"unicode/utf8"

	"github.com/axonops/mask"
)

// Fuzz targets for the parsing-heavy rules. The invariants every
// target asserts are the library's fail-closed + UTF-8 contract:
//
//  1. Apply never panics for any input.
//  2. Output is always valid UTF-8.
//  3. For any non-empty input the output either differs from the
//     input, or equals [REDACTED], or equals an empty string
//     (the documented fallback paths).
//
// Each target seeds a small canonical corpus; `go test -run=^$
// -fuzz=FuzzApply_Email -fuzztime=10s` extends from there.

func fuzzInvariants(t *testing.T, rule, in string) {
	t.Helper()
	var out string
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("rule %q panicked on %q: %v", rule, in, r)
		}
	}()
	out = mask.Apply(rule, in)
	if !utf8.ValidString(out) {
		t.Fatalf("rule %q produced invalid UTF-8 for input %q: % x", rule, in, []byte(out))
	}
	if in == "" {
		return
	}
	if out == in {
		t.Fatalf("rule %q echoed input verbatim: %q", rule, in)
	}
}

func FuzzApply_Email(f *testing.F) {
	seeds := []string{"", "alice@example.com", "x@y.com", "@", "a@", "@b", "a@@b", "@.", "佐藤@example.com"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "email_address", in)
	})
}

func FuzzApply_Street(f *testing.F) {
	seeds := []string{"", "42", "42 Wallaby Way", "Apt 3", "1 NE", "42 N", "١٦٠٠ Pennsylvania Ave"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "street_address", in)
	})
}

func FuzzApply_DateOfBirth(f *testing.F) {
	seeds := []string{"", "1985-03-15", "15/03/1985", "March 15, 1985", "1985-03-15T00:00:00Z", "2026-02-29"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "date_of_birth", in)
	})
}

func FuzzApply_PhoneNumber(f *testing.F) {
	seeds := []string{
		"",
		"+44 7911 123456",
		"+1 (555) 123-4567",
		"07911 123456",
		"+447911123456",
		"0044 7911 123456",
		"00441234567890",
		"001-212-555-0100",
		"00",
		"007",
		// Failure-path seeds for the new 00 branch. The fuzzer is
		// unlikely to discover these quickly because they require a
		// specific 4-byte prefix shape.
		"00\x00",
		"00\xff7911 123456",
		"0044\x00body",
		"0044\xffbody",
		"00 ",
		"+44\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "phone_number", in)
	})
}

func FuzzApply_URL(f *testing.F) {
	seeds := []string{
		"",
		"https://example.com/a?b=c",
		"https://admin:secret@db.example.com:5432/myapp",
		"postgresql://u:p@h/d?sslmode=require",
		"not-a-url",
		"https://",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "url", in)
	})
}

func FuzzApply_IPv6(f *testing.F) {
	seeds := []string{"", "2001:db8::1", "::1", "fe80::1%eth0", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "not-v6"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "ipv6_address", in)
	})
}

func FuzzApply_JWT(f *testing.F) {
	seeds := []string{"", "eyJh.eyJz.abc", "a.b.c", "only.two", "four.parts.here.too"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "jwt_token", in)
	})
}

func FuzzApply_PostalCode(f *testing.F) {
	seeds := []string{"", "SW1A 2AA", "12345", "K1A 0B1", "NOT-A-CODE"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "postal_code", in)
	})
}

func FuzzApply_IBAN(f *testing.F) {
	seeds := []string{"", "GB82WEST12345698765432", "DE89370400440532013000", "short", "GB00 XXXX XXXX XXXX XX"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		fuzzInvariants(t, "iban", in)
	})
}
