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

import "testing"

// runBench is defined in rules_technology_bench_test.go and reused
// across phases to keep benchmark boilerplate uniform.

// ---------- phone_number / mobile_phone_number ----------

func BenchmarkApply_phone_number_e164(b *testing.B) {
	runBench(b, "phone_number", "+44 7911 123456")
}
func BenchmarkApply_phone_number_us_local(b *testing.B) {
	runBench(b, "phone_number", "(555) 123-4567")
}
func BenchmarkApply_phone_number_invalid(b *testing.B) {
	runBench(b, "phone_number", "1-800-FLOWERS")
}
func BenchmarkApply_phone_number_long(b *testing.B) {
	// 30-digit body: exercises the O(n) isTelecomBody + countPhoneDigits loops.
	runBench(b, "phone_number", "+44 7911 123456 789012 345678 901234")
}
func BenchmarkApply_phone_number_00_prefix_spaced(b *testing.B) {
	runBench(b, "phone_number", "0044 7911 123456")
}
func BenchmarkApply_phone_number_00_prefix_compact(b *testing.B) {
	runBench(b, "phone_number", "00441234567890")
}
func BenchmarkApply_phone_number_00_prefix_short(b *testing.B) {
	// "00" alone — exercises the fall-through path and SameLengthMask.
	runBench(b, "phone_number", "00")
}
func BenchmarkApply_mobile_phone_number(b *testing.B) {
	runBench(b, "mobile_phone_number", "+44 7911 123456")
}

// ---------- imei / imsi / msisdn ----------

func BenchmarkApply_imei(b *testing.B)         { runBench(b, "imei", "353456789012345") }
func BenchmarkApply_imei_invalid(b *testing.B) { runBench(b, "imei", "35-345678-901234-5") }
func BenchmarkApply_imsi(b *testing.B)         { runBench(b, "imsi", "310260123456789") }
func BenchmarkApply_imsi_invalid(b *testing.B) { runBench(b, "imsi", "310-260-123456789") }
func BenchmarkApply_msisdn(b *testing.B)       { runBench(b, "msisdn", "447911123456") }
func BenchmarkApply_msisdn_invalid(b *testing.B) {
	runBench(b, "msisdn", "+447911123456")
}

// ---------- postal_code ----------

func BenchmarkApply_postal_code_uk(b *testing.B) { runBench(b, "postal_code", "SW1A 2AA") }
func BenchmarkApply_postal_code_us(b *testing.B) { runBench(b, "postal_code", "94103") }
func BenchmarkApply_postal_code_ca(b *testing.B) { runBench(b, "postal_code", "M5V 2T6") }
func BenchmarkApply_postal_code_unknown(b *testing.B) {
	runBench(b, "postal_code", "01310-100")
}

// ---------- geo_latitude / geo_longitude / geo_coordinates ----------

func BenchmarkApply_geo_latitude(b *testing.B) { runBench(b, "geo_latitude", "37.7749295") }
func BenchmarkApply_geo_latitude_invalid(b *testing.B) {
	// Integer input has no fractional part; routes to SameLengthMask.
	runBench(b, "geo_latitude", "37")
}
func BenchmarkApply_geo_longitude(b *testing.B) { runBench(b, "geo_longitude", "-122.4194155") }
func BenchmarkApply_geo_longitude_invalid(b *testing.B) {
	// Integer input has no fractional part; routes to SameLengthMask.
	runBench(b, "geo_longitude", "-122")
}
func BenchmarkApply_geo_coordinates(b *testing.B) {
	runBench(b, "geo_coordinates", "37.7749,-122.4194")
}
func BenchmarkApply_geo_coordinates_invalid(b *testing.B) {
	runBench(b, "geo_coordinates", "nothing,at all")
}
