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
	"strings"
)

// Tier-S constant-returners — same_length_mask, nullify,
// deterministic_hash, diagnosis_code, prescription_text. Inputs are
// diverse; outputs are determined by mask.Apply.

type sameLengthMaskGen struct{}

func (sameLengthMaskGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, randomDigits(r, 1+r.IntN(40)))
	}
	for i := 0; i < 40; i++ {
		const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		n := 1 + r.IntN(30)
		b := make([]byte, n)
		for j := range b {
			b[j] = alpha[r.IntN(len(alpha))]
		}
		inputs = append(inputs, string(b))
	}
	// Unicode.
	for _, s := range []string{"café", "日本", "Ελληνικά", "👋🏽", "Α", "Я", "ا"} {
		inputs = append(inputs, s)
	}
	return uniqueLinesToPairs(inputs)
}

type nullifyGen struct{}

func (nullifyGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, randomHex(r, 1+r.IntN(40)))
	}
	for _, s := range []string{"value", "123", "foo bar", "日本"} {
		inputs = append(inputs, s)
	}
	return uniqueLinesToPairs(inputs)
}

type deterministicHashGen struct{}

func (deterministicHashGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("user%d@example.com", r.IntN(1_000_000)))
	}
	for i := 0; i < 40; i++ {
		inputs = append(inputs, randomHex(r, 16+r.IntN(16)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("session-%s", randomHex(r, 32)))
	}
	for _, s := range []string{"alice@example.com", "bob@test.org", "carol@company.co.uk"} {
		inputs = append(inputs, s)
	}
	return uniqueLinesToPairs(inputs)
}

type diagnosisCodeGen struct{}

func (diagnosisCodeGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	// ICD-10 shapes: letter + 2 digits + optional .nn
	var inputs []string
	for i := 0; i < 80; i++ {
		letter := string(rune('A' + r.IntN(26)))
		major := r.IntN(100)
		if r.IntN(2) == 0 {
			minor := r.IntN(100)
			inputs = append(inputs, fmt.Sprintf("%s%02d.%02d", letter, major, minor))
		} else {
			inputs = append(inputs, fmt.Sprintf("%s%02d", letter, major))
		}
	}
	// Common ICD-10 codes (no real PHI).
	for _, c := range []string{"J45.20", "M54.5", "I10", "E11.9", "F32.9", "K21.9", "R10.84"} {
		inputs = append(inputs, c)
	}
	return uniqueLinesToPairs(inputs)
}

type prescriptionTextGen struct{}

func (prescriptionTextGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	drugs := []string{"amoxicillin", "ibuprofen", "metformin", "lisinopril",
		"sertraline", "amlodipine", "omeprazole", "atorvastatin"}
	doses := []string{"500mg", "200mg", "10mg", "20mg", "5mg", "1g", "250mg"}
	freqs := []string{"twice daily", "once daily", "three times daily",
		"as needed", "every 4 hours", "morning"}
	for i := 0; i < 100; i++ {
		inputs = append(inputs, fmt.Sprintf("%s %s %s",
			drugs[r.IntN(len(drugs))], doses[r.IntN(len(doses))], freqs[r.IntN(len(freqs))]))
	}
	for i := 0; i < 20; i++ {
		inputs = append(inputs, "Take "+drugs[r.IntN(len(drugs))]+" with food")
	}
	return uniqueLinesToPairs(inputs)
}

type privateKeyPEMGen struct{}

func (privateKeyPEMGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	headers := []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
		"OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"}
	for i := 0; i < 60; i++ {
		h := headers[r.IntN(len(headers))]
		body := randomB64URL(r, 40+r.IntN(120))
		inputs = append(inputs, fmt.Sprintf("-----BEGIN %s-----%s-----END %s-----", h, body, h))
	}
	// Whole single-line PEM bodies (without armoring).
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomB64URL(r, 64+r.IntN(64)))
	}
	// Edge: malformed armoring.
	for i := 0; i < 15; i++ {
		inputs = append(inputs, "-----BEGIN PRIVATE KEY-----no end marker")
	}
	return uniqueLinesToPairs(inputs)
}

type paymentCardCVVGen struct{}

func (paymentCardCVVGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	// 3-digit CVV.
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%03d", r.IntN(1000)))
	}
	// 4-digit (Amex CID).
	for i := 0; i < 40; i++ {
		inputs = append(inputs, fmt.Sprintf("%04d", r.IntN(10000)))
	}
	// Edge: 1, 2, 5 digits.
	for n := 1; n <= 5; n++ {
		for i := 0; i < 5; i++ {
			inputs = append(inputs, randomDigits(r, n))
		}
	}
	// Edge: letters.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "abc")
		inputs = append(inputs, "12a")
	}
	return uniqueLinesToPairs(inputs)
}

type paymentCardPINGen struct{}

func (paymentCardPINGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%04d", r.IntN(10000)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, fmt.Sprintf("%06d", r.IntN(1_000_000)))
	}
	for n := 1; n <= 6; n++ {
		for i := 0; i < 4; i++ {
			inputs = append(inputs, randomDigits(r, n))
		}
	}
	return uniqueLinesToPairs(inputs)
}

type auMedicareGen struct{}

func (auMedicareGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		inputs = append(inputs, fmt.Sprintf("%04d %05d %d",
			r.IntN(10000), r.IntN(100000), 1+r.IntN(9)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 10))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 9+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

type sgNRICFINGen struct{}

func (sgNRICFINGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	prefixes := []string{"S", "T", "F", "G", "M"}
	for i := 0; i < 80; i++ {
		inputs = append(inputs, prefixes[r.IntN(len(prefixes))]+
			fmt.Sprintf("%07d", r.IntN(10_000_000))+randomUpper(r, 1))
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, strings.ToLower(prefixes[r.IntN(len(prefixes))])+
			fmt.Sprintf("%07d", r.IntN(10_000_000))+
			strings.ToLower(randomUpper(r, 1)))
	}
	return uniqueLinesToPairs(inputs)
}

type mxCURPGen struct{}

func (mxCURPGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		// 4 letters + 6 digits + 6 letters + 2 alphanumeric = 18 chars.
		inputs = append(inputs,
			randomUpper(r, 4)+
				fmt.Sprintf("%06d", r.IntN(1_000_000))+
				randomUpper(r, 6)+
				randomBICChars(r, 2))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomUpper(r, 16+r.IntN(4)))
	}
	return uniqueLinesToPairs(inputs)
}

type mxRFCGen struct{}

func (mxRFCGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	// 4-letter natural-person form.
	for i := 0; i < 50; i++ {
		inputs = append(inputs,
			randomUpper(r, 4)+
				fmt.Sprintf("%06d", r.IntN(1_000_000))+
				randomBICChars(r, 3))
	}
	// 3-letter corporate form.
	for i := 0; i < 50; i++ {
		inputs = append(inputs,
			randomUpper(r, 3)+
				fmt.Sprintf("%06d", r.IntN(1_000_000))+
				randomBICChars(r, 3))
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomUpper(r, 11+r.IntN(3)))
	}
	return uniqueLinesToPairs(inputs)
}

type cnResidentIDGen struct{}

func (cnResidentIDGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		// 17 digits + check digit (digit or X).
		body := randomDigits(r, 17)
		check := "0123456789X"[r.IntN(11)]
		inputs = append(inputs, body+string(check))
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 16+r.IntN(3)))
	}
	return uniqueLinesToPairs(inputs)
}

type zaNationalIDGen struct{}

func (zaNationalIDGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 100; i++ {
		inputs = append(inputs, randomDigits(r, 13))
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 11+r.IntN(4)))
	}
	return uniqueLinesToPairs(inputs)
}

type esDNINIFNIEGen struct{}

func (esDNINIFNIEGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	// DNI: 8 digits + letter.
	for i := 0; i < 60; i++ {
		inputs = append(inputs, fmt.Sprintf("%08d%s", r.IntN(100_000_000), randomUpper(r, 1)))
	}
	// NIE: X/Y/Z + 7 digits + letter.
	for i := 0; i < 30; i++ {
		prefix := []byte{"XYZ"[r.IntN(3)]}
		inputs = append(inputs, string(prefix)+fmt.Sprintf("%07d", r.IntN(10_000_000))+randomUpper(r, 1))
	}
	// NIF (legal entity): letter + 7 digits + check.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomUpper(r, 1)+fmt.Sprintf("%07d", r.IntN(10_000_000))+randomUpper(r, 1))
	}
	for i := 0; i < 15; i++ {
		inputs = append(inputs, randomDigits(r, 7+r.IntN(3)))
	}
	return uniqueLinesToPairs(inputs)
}

type driverLicenseGen struct{}

func (driverLicenseGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	// Mixed alphanumeric — varies wildly by jurisdiction.
	for i := 0; i < 80; i++ {
		prefix := randomUpper(r, 1+r.IntN(3))
		digits := randomDigits(r, 6+r.IntN(6))
		inputs = append(inputs, prefix+digits)
	}
	// All digits.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 9+r.IntN(4)))
	}
	// All letters (rare but possible).
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomUpper(r, 8+r.IntN(4)))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 4+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

type genericNationalIDGen struct{}

func (genericNationalIDGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	// Mixed: similar to driver_license but no leading-prefix bias.
	for i := 0; i < 80; i++ {
		inputs = append(inputs, randomDigits(r, 9+r.IntN(6)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomBICChars(r, 9+r.IntN(4)))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 5+r.IntN(3)))
	}
	return uniqueLinesToPairs(inputs)
}

type taxIdentifierGen struct{}

func (taxIdentifierGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	// US-EIN: NN-NNNNNNN.
	for i := 0; i < 40; i++ {
		inputs = append(inputs, fmt.Sprintf("%02d-%07d", r.IntN(100), r.IntN(10_000_000)))
	}
	// UK UTR: 10 digits.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 10))
	}
	// VAT-like: 2 letters + 8-12 digits.
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomUpper(r, 2)+randomDigits(r, 8+r.IntN(5)))
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, randomDigits(r, 4+r.IntN(3)))
	}
	return uniqueLinesToPairs(inputs)
}

type medicalRecordNumberGen struct{}

func (medicalRecordNumberGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		prefix := []string{"MRN-", "MR", "PT", "NHS"}[r.IntN(4)]
		inputs = append(inputs, prefix+randomDigits(r, 8+r.IntN(4)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 8+r.IntN(4)))
	}
	return uniqueLinesToPairs(inputs)
}

type healthPlanBeneficiaryGen struct{}

func (healthPlanBeneficiaryGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		prefix := []string{"HPB-", "BEN-", "MEM"}[r.IntN(3)]
		inputs = append(inputs, prefix+randomDigits(r, 9+r.IntN(3)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 10+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

type medicalDeviceIdentifierGen struct{}

func (medicalDeviceIdentifierGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		prefix := []string{"DEV-SN-", "DEV-", "SN-", "ID-"}[r.IntN(4)]
		inputs = append(inputs, prefix+randomDigits(r, 8+r.IntN(4)))
	}
	for i := 0; i < 30; i++ {
		inputs = append(inputs, randomDigits(r, 10+r.IntN(2)))
	}
	return uniqueLinesToPairs(inputs)
}

// geoLatGen, geoLonGen, geoCoordGen — decimal precision reduction.
type geoLatitudeGen struct{}

func (geoLatitudeGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		lat := -90.0 + r.Float64()*180.0
		inputs = append(inputs, fmt.Sprintf("%.6f", lat))
	}
	for i := 0; i < 40; i++ {
		lat := -90.0 + r.Float64()*180.0
		inputs = append(inputs, fmt.Sprintf("%.4f", lat))
	}
	for _, s := range []string{"0", "90", "-90", "0.0", "37.7749295", "-122.4194", "51.5074"} {
		inputs = append(inputs, s)
	}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, "not-a-number")
	}
	return uniqueLinesToPairs(inputs)
}

type geoLongitudeGen struct{}

func (geoLongitudeGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		lon := -180.0 + r.Float64()*360.0
		inputs = append(inputs, fmt.Sprintf("%.6f", lon))
	}
	for i := 0; i < 40; i++ {
		lon := -180.0 + r.Float64()*360.0
		inputs = append(inputs, fmt.Sprintf("%.4f", lon))
	}
	for _, s := range []string{"0", "180", "-180", "0.0", "-122.4194295", "2.349014"} {
		inputs = append(inputs, s)
	}
	return uniqueLinesToPairs(inputs)
}

type geoCoordinatesGen struct{}

func (geoCoordinatesGen) Generate(seed uint64) []Pair {
	r := rand.New(rand.NewPCG(0xC0FFEE, seed))
	var inputs []string
	for i := 0; i < 80; i++ {
		lat := -90.0 + r.Float64()*180.0
		lon := -180.0 + r.Float64()*360.0
		inputs = append(inputs, fmt.Sprintf("%.6f,%.6f", lat, lon))
	}
	for i := 0; i < 40; i++ {
		lat := -90.0 + r.Float64()*180.0
		lon := -180.0 + r.Float64()*360.0
		inputs = append(inputs, fmt.Sprintf("%.6f, %.6f", lat, lon))
	}
	for _, s := range []string{
		"37.7749295,-122.4194",
		"51.5074, -0.1278",
		"-33.8688, 151.2093",
		"0,0",
	} {
		inputs = append(inputs, s)
	}
	// Edge: only one number.
	for i := 0; i < 10; i++ {
		inputs = append(inputs, fmt.Sprintf("%.6f", -90.0+r.Float64()*180.0))
	}
	return uniqueLinesToPairs(inputs)
}

func init() {
	register("same_length_mask", sameLengthMaskGen{})
	register("nullify", nullifyGen{})
	register("deterministic_hash", deterministicHashGen{})
	register("diagnosis_code", diagnosisCodeGen{})
	register("prescription_text", prescriptionTextGen{})
	register("private_key_pem", privateKeyPEMGen{})
	register("payment_card_cvv", paymentCardCVVGen{})
	register("payment_card_pin", paymentCardPINGen{})
	register("au_medicare_number", auMedicareGen{})
	register("sg_nric_fin", sgNRICFINGen{})
	register("mx_curp", mxCURPGen{})
	register("mx_rfc", mxRFCGen{})
	register("cn_resident_id", cnResidentIDGen{})
	register("za_national_id", zaNationalIDGen{})
	register("es_dni_nif_nie", esDNINIFNIEGen{})
	register("driver_license_number", driverLicenseGen{})
	register("generic_national_id", genericNationalIDGen{})
	register("tax_identifier", taxIdentifierGen{})
	register("medical_record_number", medicalRecordNumberGen{})
	register("health_plan_beneficiary_id", healthPlanBeneficiaryGen{})
	register("medical_device_identifier", medicalDeviceIdentifierGen{})
	register("geo_latitude", geoLatitudeGen{})
	register("geo_longitude", geoLongitudeGen{})
	register("geo_coordinates", geoCoordinatesGen{})
}
