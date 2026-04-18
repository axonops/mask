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

package mask

// Exported rule-name constants for every built-in rule registered by the
// library. These exist so callers can opt into compile-time safety against
// typos — `mask.Apply(mask.RuleEmailAddress, v)` instead of the stringly
// typed `mask.Apply("email_address", v)`. String-literal call sites continue
// to work without change.
//
// A drift-guard test in rule_names_test.go asserts that this set matches the
// built-in registry one-for-one. Adding a new built-in rule without
// declaring the matching constant here fails the build.

// Utility primitive rules registered as named masking rules. Use
// these constants in calls to [Apply] for compile-time safety
// against typos in rule names.
const (
	RuleFullRedact        = "full_redact"
	RuleSameLengthMask    = "same_length_mask"
	RuleNullify           = "nullify"
	RuleDeterministicHash = "deterministic_hash"
)

// Global identity rules covering personal identifiers that are not
// specific to a single jurisdiction (names, email addresses, dates
// of birth, passport numbers, and so on).
const (
	RuleEmailAddress        = "email_address"
	RulePersonName          = "person_name"
	RuleGivenName           = "given_name"
	RuleFamilyName          = "family_name"
	RuleStreetAddress       = "street_address"
	RuleDateOfBirth         = "date_of_birth"
	RuleUsername            = "username"
	RulePassportNumber      = "passport_number"
	RuleDriverLicenseNumber = "driver_license_number"
	RuleGenericNationalID   = "generic_national_id"
	RuleTaxIdentifier       = "tax_identifier"
)

// Country-specific identity rules for national identifiers tied to
// a particular jurisdiction (US SSN, UK NINO, IN Aadhaar, and so on).
const (
	RuleUSSSN            = "us_ssn"
	RuleCASIN            = "ca_sin"
	RuleUKNINO           = "uk_nino"
	RuleINAadhaar        = "in_aadhaar"
	RuleINPAN            = "in_pan"
	RuleAUMedicareNumber = "au_medicare_number"
	RuleSGNRICFIN        = "sg_nric_fin"
	RuleBRCPF            = "br_cpf"
	RuleBRCNPJ           = "br_cnpj"
	RuleMXCURP           = "mx_curp"
	RuleMXRFC            = "mx_rfc"
	RuleCNResidentID     = "cn_resident_id"
	RuleZANationalID     = "za_national_id"
	RuleESDNINIFNIE      = "es_dni_nif_nie"
)

// Financial rules for payment-card data, bank account identifiers,
// routing codes, and monetary amounts.
const (
	RulePaymentCardPAN       = "payment_card_pan"
	RulePaymentCardPANFirst6 = "payment_card_pan_first6"
	RulePaymentCardPANLast4  = "payment_card_pan_last4"
	RulePaymentCardCVV       = "payment_card_cvv"
	RulePaymentCardPIN       = "payment_card_pin"
	RuleBankAccountNumber    = "bank_account_number"
	RuleUKSortCode           = "uk_sort_code"
	RuleUSABARoutingNumber   = "us_aba_routing_number"
	RuleIBAN                 = "iban"
	RuleSWIFTBIC             = "swift_bic"
	RuleMonetaryAmount       = "monetary_amount"
)

// Health rules for protected health information: medical record
// numbers, health plan beneficiary identifiers, device UDIs,
// diagnosis codes, and free-text prescription strings.
const (
	RuleMedicalRecordNumber     = "medical_record_number"
	RuleHealthPlanBeneficiaryID = "health_plan_beneficiary_id"
	RuleMedicalDeviceIdentifier = "medical_device_identifier"
	RuleDiagnosisCode           = "diagnosis_code"
	RulePrescriptionText        = "prescription_text"
)

// Technology rules for infrastructure and application identifiers:
// network addresses, URLs, credentials, tokens, keys, connection
// strings, and UUIDs.
const (
	RuleIPv4Address      = "ipv4_address"
	RuleIPv6Address      = "ipv6_address"
	RuleMACAddress       = "mac_address"
	RuleHostname         = "hostname"
	RuleURL              = "url"
	RuleURLCredentials   = "url_credentials"
	RuleAPIKey           = "api_key"
	RuleJWTToken         = "jwt_token"
	RuleBearerToken      = "bearer_token"
	RulePassword         = "password"
	RulePrivateKeyPEM    = "private_key_pem"
	RuleConnectionString = "connection_string"
	RuleDatabaseDSN      = "database_dsn"
	RuleUUID             = "uuid"
)

// Telecom rules for subscriber and device identifiers: phone
// numbers, IMEI, IMSI, and MSISDN values.
const (
	RulePhoneNumber       = "phone_number"
	RuleMobilePhoneNumber = "mobile_phone_number"
	RuleIMEI              = "imei"
	RuleIMSI              = "imsi"
	RuleMSISDN            = "msisdn"
)

// Location rules for postal codes and geographic coordinates —
// individual latitude and longitude values as well as
// comma-separated latitude/longitude pairs.
const (
	RulePostalCode     = "postal_code"
	RuleGeoLatitude    = "geo_latitude"
	RuleGeoLongitude   = "geo_longitude"
	RuleGeoCoordinates = "geo_coordinates"
)
