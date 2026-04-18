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
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/axonops/mask"
)

// ruleNameConstants lists every exported `mask.Rule*` constant in the
// library. The drift-guard test below asserts this set matches
// `mask.Rules()` exactly, so a new built-in rule without a matching
// constant — or a removed constant still referenced in the registry —
// fails the build.
var ruleNameConstants = []string{
	// Utility primitives
	mask.RuleFullRedact,
	mask.RuleSameLengthMask,
	mask.RuleNullify,
	mask.RuleDeterministicHash,
	// Global identity
	mask.RuleEmailAddress,
	mask.RulePersonName,
	mask.RuleGivenName,
	mask.RuleFamilyName,
	mask.RuleStreetAddress,
	mask.RuleDateOfBirth,
	mask.RuleUsername,
	mask.RulePassportNumber,
	mask.RuleDriverLicenseNumber,
	mask.RuleGenericNationalID,
	mask.RuleTaxIdentifier,
	// Country-specific identity
	mask.RuleUSSSN,
	mask.RuleCASIN,
	mask.RuleUKNINO,
	mask.RuleINAadhaar,
	mask.RuleINPAN,
	mask.RuleAUMedicareNumber,
	mask.RuleSGNRICFIN,
	mask.RuleBRCPF,
	mask.RuleBRCNPJ,
	mask.RuleMXCURP,
	mask.RuleMXRFC,
	mask.RuleCNResidentID,
	mask.RuleZANationalID,
	mask.RuleESDNINIFNIE,
	// Financial
	mask.RulePaymentCardPAN,
	mask.RulePaymentCardPANFirst6,
	mask.RulePaymentCardPANLast4,
	mask.RulePaymentCardCVV,
	mask.RulePaymentCardPIN,
	mask.RuleBankAccountNumber,
	mask.RuleUKSortCode,
	mask.RuleUSABARoutingNumber,
	mask.RuleIBAN,
	mask.RuleSWIFTBIC,
	mask.RuleMonetaryAmount,
	// Health
	mask.RuleMedicalRecordNumber,
	mask.RuleHealthPlanBeneficiaryID,
	mask.RuleMedicalDeviceIdentifier,
	mask.RuleDiagnosisCode,
	mask.RulePrescriptionText,
	// Technology
	mask.RuleIPv4Address,
	mask.RuleIPv6Address,
	mask.RuleMACAddress,
	mask.RuleHostname,
	mask.RuleURL,
	mask.RuleURLCredentials,
	mask.RuleAPIKey,
	mask.RuleJWTToken,
	mask.RuleBearerToken,
	mask.RulePassword,
	mask.RulePrivateKeyPEM,
	mask.RuleConnectionString,
	mask.RuleDatabaseDSN,
	mask.RuleUUID,
	// Telecom
	mask.RulePhoneNumber,
	mask.RuleMobilePhoneNumber,
	mask.RuleIMEI,
	mask.RuleIMSI,
	mask.RuleMSISDN,
	// Location
	mask.RulePostalCode,
	mask.RuleGeoLatitude,
	mask.RuleGeoLongitude,
	mask.RuleGeoCoordinates,
}

// TestRuleNameConstants_MatchRegistry asserts that the exported
// constants cover exactly the set of built-in rules registered on a
// fresh Masker. A mismatch in either direction fails the build.
func TestRuleNameConstants_MatchRegistry(t *testing.T) {
	t.Parallel()
	m := mask.New()
	registered := m.Rules()
	sort.Strings(registered)

	declared := make([]string, len(ruleNameConstants))
	copy(declared, ruleNameConstants)
	sort.Strings(declared)

	assert.Equal(t, registered, declared,
		"exported Rule* constants must match the built-in registry one-for-one")
}
