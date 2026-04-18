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

	"github.com/axonops/mask"
)

var financialSink string

func BenchmarkApply_payment_card_pan_16(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_pan", "4111222233334444")
	}
	financialSink = s
}

func BenchmarkApply_payment_card_pan_dashed(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_pan", "4111-2222-3333-4444")
	}
	financialSink = s
}

func BenchmarkApply_payment_card_pan_invalid(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_pan", "411122223333") // 12 digits, below range
	}
	financialSink = s
}

func BenchmarkApply_payment_card_pan_first6(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_pan_first6", "4111222233334444")
	}
	financialSink = s
}

func BenchmarkApply_payment_card_pan_last4(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_pan_last4", "4111222233334444")
	}
	financialSink = s
}

func BenchmarkApply_payment_card_cvv(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_cvv", "123")
	}
	financialSink = s
}

func BenchmarkApply_payment_card_pin(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_pin", "1234")
	}
	financialSink = s
}

func BenchmarkApply_bank_account_number(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("bank_account_number", "1234-5678-9012")
	}
	financialSink = s
}

func BenchmarkApply_uk_sort_code(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("uk_sort_code", "12-34-56")
	}
	financialSink = s
}

func BenchmarkApply_us_aba_routing_number(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("us_aba_routing_number", "021000021")
	}
	financialSink = s
}

// BenchmarkApply_us_aba_routing_number_long_invalid exercises the
// byte-walk validation loop with a long non-conforming input so the
// early-exit cost is benchmarked.
func BenchmarkApply_us_aba_routing_number_long_invalid(b *testing.B) {
	m := mask.New()
	long := "021-000-021-extra-nonsense-0123456789"
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("us_aba_routing_number", long)
	}
	financialSink = s
}

// BenchmarkApply_payment_card_pan_invalid_nondigit exercises the non-digit
// early-exit arm of countDigitsAllDigits, distinct from the length-fail
// arm already covered by payment_card_pan_invalid.
func BenchmarkApply_payment_card_pan_invalid_nondigit(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("payment_card_pan", "4111-XXXX-3333-4444")
	}
	financialSink = s
}

func BenchmarkApply_iban_compact(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("iban", "GB82WEST12345698765432")
	}
	financialSink = s
}

func BenchmarkApply_iban_spaced(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("iban", "GB82 WEST 1234 5698 7654 32")
	}
	financialSink = s
}

func BenchmarkApply_iban_invalid(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("iban", "gb82west12345698765432") // lowercase fallback
	}
	financialSink = s
}

func BenchmarkApply_swift_bic_8(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("swift_bic", "BARCGB2L")
	}
	financialSink = s
}

func BenchmarkApply_swift_bic_11(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("swift_bic", "DEUTDEFF500")
	}
	financialSink = s
}

func BenchmarkApply_swift_bic_invalid(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("swift_bic", "BARCGB")
	}
	financialSink = s
}

func BenchmarkApply_monetary_amount(b *testing.B) {
	m := mask.New()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = m.Apply("monetary_amount", "$1,234.56")
	}
	financialSink = s
}
