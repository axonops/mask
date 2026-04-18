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

var (
	sink     string
	short16  = "SensitiveData123"
	long1000 = strings.Repeat("s", 1000)
)

func BenchmarkFullRedact(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.FullRedact(short16)
	}
	sink = s
}

func BenchmarkSameLengthMask_1000(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.SameLengthMask(long1000, '*')
	}
	sink = s
}

func BenchmarkKeepFirstN_16(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.KeepFirstN(short16, 4, '*')
	}
	sink = s
}

func BenchmarkKeepFirstN_1000(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.KeepFirstN(long1000, 4, '*')
	}
	sink = s
}

func BenchmarkKeepLastN_16(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.KeepLastN(short16, 4, '*')
	}
	sink = s
}

func BenchmarkKeepLastN_1000(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.KeepLastN(long1000, 4, '*')
	}
	sink = s
}

func BenchmarkKeepFirstLast_16(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.KeepFirstLast(short16, 4, 4, '*')
	}
	sink = s
}

func BenchmarkKeepFirstLast_1000(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.KeepFirstLast(long1000, 4, 4, '*')
	}
	sink = s
}

func BenchmarkPreserveDelimiters_Email(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.PreserveDelimiters("alice@example.com", "@.", '*')
	}
	sink = s
}

func BenchmarkPreserveDelimitersFunc_Email(b *testing.B) {
	r := mask.PreserveDelimitersFunc("@.")
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = r("alice@example.com")
	}
	sink = s
}

func BenchmarkReplaceRegexFunc_1000(b *testing.B) {
	r, err := mask.ReplaceRegexFunc(`\d+`, "N")
	if err != nil {
		b.Fatal(err)
	}
	input := strings.Repeat("abc-42 ", 200)
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = r(input)
	}
	sink = s
}

func BenchmarkDeterministicHash_1000(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.DeterministicHash(long1000)
	}
	sink = s
}

func BenchmarkDeterministicHash_Salted_1000(b *testing.B) {
	r := mask.DeterministicHashFunc(mask.WithKeyedSalt("secretkey", "v1"))
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = r(long1000)
	}
	sink = s
}

func BenchmarkDeterministicHash_SHA512_1000(b *testing.B) {
	r := mask.DeterministicHashFunc(mask.WithAlgorithm(mask.SHA512))
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = r(long1000)
	}
	sink = s
}

func BenchmarkDeterministicHash_SHA3_256_1000(b *testing.B) {
	r := mask.DeterministicHashFunc(mask.WithAlgorithm(mask.SHA3_256))
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = r(long1000)
	}
	sink = s
}

func BenchmarkReducePrecision_NumericShort(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.ReducePrecision("37.7749295", 2, '*')
	}
	sink = s
}

func BenchmarkReducePrecision_NumericLong(b *testing.B) {
	long := "37." + strings.Repeat("7", 998)
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.ReducePrecision(long, 2, '*')
	}
	sink = s
}

// BenchmarkReducePrecision_Fallback exercises the non-numeric fallback path
// (same_length_mask). Regression here indicates the fallback changed shape.
func BenchmarkReducePrecision_Fallback(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = mask.ReducePrecision("1.2e5", 2, '*')
	}
	sink = s
}
