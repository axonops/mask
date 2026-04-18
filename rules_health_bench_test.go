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

var healthSink string

func BenchmarkApply_medical_record_number_prefixed(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("medical_record_number", "MRN-123456789")
	}
	healthSink = s
}

func BenchmarkApply_medical_record_number_unprefixed(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("medical_record_number", "123456789")
	}
	healthSink = s
}

func BenchmarkApply_medical_record_number_fallback(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("medical_record_number", "MRN-1")
	}
	healthSink = s
}

func BenchmarkApply_medical_record_number_long(b *testing.B) {
	m := mask.New()
	long := "MRN-" + strings.Repeat("1", 1000)
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("medical_record_number", long)
	}
	healthSink = s
}

func BenchmarkApply_health_plan_beneficiary_id(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("health_plan_beneficiary_id", "HPB-987654321")
	}
	healthSink = s
}

func BenchmarkApply_medical_device_identifier(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("medical_device_identifier", "DEV-SN-12345678")
	}
	healthSink = s
}

func BenchmarkApply_diagnosis_code(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("diagnosis_code", "J45.20")
	}
	healthSink = s
}

func BenchmarkApply_prescription_text(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("prescription_text", "Metformin 500mg twice daily")
	}
	healthSink = s
}
