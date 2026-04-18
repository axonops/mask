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

// ---------- us_ssn / ca_sin / uk_nino ----------

func BenchmarkApply_us_ssn(b *testing.B)         { runBench(b, "us_ssn", "123-45-6789") }
func BenchmarkApply_us_ssn_compact(b *testing.B) { runBench(b, "us_ssn", "123456789") }
func BenchmarkApply_us_ssn_invalid(b *testing.B) { runBench(b, "us_ssn", "not-a-ssn") }
func BenchmarkApply_ca_sin(b *testing.B)         { runBench(b, "ca_sin", "123-456-789") }
func BenchmarkApply_uk_nino(b *testing.B)        { runBench(b, "uk_nino", "AB123456C") }
func BenchmarkApply_uk_nino_spaced(b *testing.B) { runBench(b, "uk_nino", "AB 12 34 56 C") }

// ---------- in_aadhaar / in_pan ----------

func BenchmarkApply_in_aadhaar(b *testing.B) { runBench(b, "in_aadhaar", "1234 5678 9012") }
func BenchmarkApply_in_pan(b *testing.B)     { runBench(b, "in_pan", "ABCDE1234F") }

// ---------- au_medicare_number / sg_nric_fin ----------

func BenchmarkApply_au_medicare_number(b *testing.B) {
	runBench(b, "au_medicare_number", "2123 45670 1")
}
func BenchmarkApply_sg_nric_fin(b *testing.B) { runBench(b, "sg_nric_fin", "S1234567A") }

// ---------- br_cpf / br_cnpj ----------

func BenchmarkApply_br_cpf(b *testing.B)  { runBench(b, "br_cpf", "123.456.789-09") }
func BenchmarkApply_br_cnpj(b *testing.B) { runBench(b, "br_cnpj", "12.345.678/0001-95") }

// ---------- mx_curp / mx_rfc ----------

func BenchmarkApply_mx_curp(b *testing.B) { runBench(b, "mx_curp", "GAPA850101HDFRRL09") }
func BenchmarkApply_mx_rfc(b *testing.B)  { runBench(b, "mx_rfc", "GAPA8501014T3") }

// ---------- cn_resident_id / za_national_id / es_dni_nif_nie ----------

func BenchmarkApply_cn_resident_id(b *testing.B) {
	runBench(b, "cn_resident_id", "110101199003074578")
}
func BenchmarkApply_za_national_id(b *testing.B) {
	runBench(b, "za_national_id", "8501015009087")
}
func BenchmarkApply_es_dni_nif_nie_dni(b *testing.B) {
	runBench(b, "es_dni_nif_nie", "12345678Z")
}
func BenchmarkApply_es_dni_nif_nie_nie(b *testing.B) {
	runBench(b, "es_dni_nif_nie", "X1234567L")
}

// ---------- fallback / fail-closed hot path ----------
//
// These benchmarks measure the SameLengthMask fallback for the
// longer validators — the hot path taken when an adversarial or
// malformed value is passed in. Regressions here would suggest the
// validators are allocating on the failure branch.

func BenchmarkApply_ca_sin_invalid(b *testing.B)     { runBench(b, "ca_sin", "not-a-sin") }
func BenchmarkApply_uk_nino_invalid(b *testing.B)    { runBench(b, "uk_nino", "not-a-nino") }
func BenchmarkApply_in_aadhaar_invalid(b *testing.B) { runBench(b, "in_aadhaar", "not an aadhaar") }
func BenchmarkApply_br_cnpj_invalid(b *testing.B)    { runBench(b, "br_cnpj", "not-a-cnpj-number") }
func BenchmarkApply_mx_curp_invalid(b *testing.B)    { runBench(b, "mx_curp", "gapa850101hdfrrl09") }
func BenchmarkApply_cn_resident_id_invalid(b *testing.B) {
	runBench(b, "cn_resident_id", "1101011990030745Y8")
}
