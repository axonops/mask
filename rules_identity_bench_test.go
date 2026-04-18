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

var identitySink string

func BenchmarkApply_email_address(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("email_address", "alice@example.com")
	}
	identitySink = s
}

func BenchmarkApply_person_name_short(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("person_name", "John Doe")
	}
	identitySink = s
}

func BenchmarkApply_person_name_long(b *testing.B) {
	m := mask.New()
	input := "María José García López"
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("person_name", input)
	}
	identitySink = s
}

func BenchmarkApply_given_name(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("given_name", "Alice")
	}
	identitySink = s
}

func BenchmarkApply_family_name(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("family_name", "Smith")
	}
	identitySink = s
}

func BenchmarkApply_street_address_short(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("street_address", "42 Wallaby Way")
	}
	identitySink = s
}

func BenchmarkApply_street_address_long(b *testing.B) {
	m := mask.New()
	input := "1600 " + strings.Repeat("Pennsylvania ", 15) + "Avenue NW"
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("street_address", input)
	}
	identitySink = s
}

func BenchmarkApply_date_of_birth_iso(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("date_of_birth", "1985-03-15")
	}
	identitySink = s
}

func BenchmarkApply_date_of_birth_fallback(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("date_of_birth", "15.03.1985")
	}
	identitySink = s
}

func BenchmarkApply_date_of_birth_slash(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("date_of_birth", "15/03/1985")
	}
	identitySink = s
}

func BenchmarkApply_date_of_birth_month_name(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("date_of_birth", "March 15, 1985")
	}
	identitySink = s
}

func BenchmarkApply_username(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("username", "johndoe42")
	}
	identitySink = s
}

func BenchmarkApply_passport_number(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("passport_number", "GB1234567")
	}
	identitySink = s
}

func BenchmarkApply_driver_license_number_short(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("driver_license_number", "DL-1234-5678")
	}
	identitySink = s
}

func BenchmarkApply_driver_license_number_long(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("driver_license_number", "SMITH901015JN9AA")
	}
	identitySink = s
}

func BenchmarkApply_generic_national_id(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("generic_national_id", "AB123456CD")
	}
	identitySink = s
}

func BenchmarkApply_tax_identifier_short(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("tax_identifier", "12-3456789")
	}
	identitySink = s
}

func BenchmarkApply_tax_identifier_long(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("tax_identifier", "123.456.789-10")
	}
	identitySink = s
}
