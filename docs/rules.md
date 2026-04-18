# Built-in Rules

<sub>← [Back to README](../README.md) · **Rule Catalogue** · [Extending](./extending.md)</sub>

Full catalogue of the 68 rules registered with every `*Masker` out of the box. Every rule is fail-closed and honours the configured mask character (`SetMaskChar` / `WithMaskChar`). Use `mask.Rules()` to list every registered name and `mask.Describe(name)` to retrieve a rule's category, jurisdiction, and description at runtime.

## Table of contents

- [Utility primitives (rules)](#utility-primitives-rules) — 4 rules
- [Identity](#identity) — 11 global rules
- [Country-specific identity](#country-specific-identity) — 14 jurisdiction-qualified rules
- [Financial](#financial) — 11 payment-card, banking, and tax rules
- [Health](#health) — 5 healthcare identifier and clinical-content rules
- [Technology](#technology) — 14 infrastructure and application-security rules
- [Telecom and location](#telecom-and-location) — 9 phone, mobile, postcode and geographic rules

## Utility primitives (rules)

Four general-purpose rules registered as masking rules. These are also exposed as Go functions — see [Extending](./extending.md).

| Rule | Description | Example |
|---|---|---|
| `full_redact` | Replaces any value with the constant `[REDACTED]`. | `anything` → `[REDACTED]` |
| `same_length_mask` | Replaces every rune of the input with the configured mask character, preserving length. | `Hello` → `*****` |
| `nullify` | Replaces any value with the empty string. | `anything` → (empty) |
| `deterministic_hash` | Replaces the value with a truncated SHA-256 digest. Pseudonymisation, not anonymisation — see [SECURITY.md](../SECURITY.md) for the salt and version policy. | `alice@example.com` → `sha256:ff8d9819fc0e12bf` |

## Identity

Personal and identity fields common to most jurisdictions. See [Country-specific identity](#country-specific-identity) for regional IDs.

| Rule | Description | Example |
|---|---|---|
| `date_of_birth` | Preserves the year and masks month and day across three common formats (ISO, slash, month-name); separator style is unchanged. | `1985-03-15` → `1985-**-**` |
| `driver_license_number` | Preserves the first 2 and last 3 or 4 non-separator characters of a driver licence number. | `DL-1234-5678` → `DL-****-5678` |
| `email_address` | Preserves the first character of the local-part and the full domain; masks the rest of the local-part. | `alice@example.com` → `a****@example.com` |
| `family_name` | Preserves the first character of the surname. | `Smith` → `S****` |
| `generic_national_id` | Preserves the first 2 and last 2 characters; use sparingly — prefer country-specific rules where available. | `AB123456CD` → `AB******CD` |
| `given_name` | Preserves the first character of the given name. | `Alice` → `A****` |
| `passport_number` | Preserves a two-letter country prefix (if present) and the last 2 characters. | `GB1234567` → `GB*****67` |
| `person_name` | Preserves the first initial of each space-separated name component. | `Alice Smith` → `A**** S****` |
| `street_address` | Keeps the leading house number and recognised trailing street type; masks the street-name body. | `42 Wallaby Way` → `42 ******* Way` |
| `tax_identifier` | Preserves the last 3 or 4 non-separator characters; preserves separators. | `12-3456789` → `**-***6789` |
| `username` | Preserves the first 2 characters of a username. | `johndoe42` → `jo*******` |

## Country-specific identity

Jurisdiction-qualified identity fields. All report `category = "identity"` with a specific `Jurisdiction`.

| Rule | Description | Example |
|---|---|---|
| `au_medicare_number` | Preserves the last 2 digits of a 10-digit Australian Medicare number. | `2123 45670 1` → `**** ****0 1` |
| `br_cnpj` | Preserves the last 2 digits of a 14-digit Brazilian CNPJ; accepts canonical and compact forms. | `12.345.678/0001-95` → `**.***.***/****-95` |
| `br_cpf` | Preserves the last 2 digits of an 11-digit Brazilian CPF; accepts canonical and compact forms. | `123.456.789-09` → `***.***.***-09` |
| `ca_sin` | Preserves the last 3 digits of a 9-digit Canadian Social Insurance Number. | `123-456-789` → `***-***-789` |
| `cn_resident_id` | Preserves the first 6 (region code) and last 4 characters of an 18-character PRC Resident Identity Card number. | `110101199003074578` → `110101********4578` |
| `es_dni_nif_nie` | Preserves the leading character (for NIE/NIF) and trailing control letter of a 9-character Spanish DNI/NIF/NIE. | `12345678Z` → `********Z` |
| `in_aadhaar` | Preserves the last 4 digits of a 12-digit Aadhaar number. | `1234 5678 9012` → `**** **** 9012` |
| `in_pan` | Preserves the first 3 and last 2 characters of a 10-character Indian Permanent Account Number. | `ABCDE1234F` → `ABC*****4F` |
| `mx_curp` | Preserves the first 4 and last 3 characters of an 18-character Mexican CURP. | `GAPA850101HDFRRL09` → `GAPA***********L09` |
| `mx_rfc` | Preserves the first 3 and last 3 characters of a 12- or 13-character Mexican RFC. | `GAPA8501014T3` → `GAP*******4T3` |
| `sg_nric_fin` | Preserves the leading letter and trailing letter of a 9-character Singapore NRIC/FIN. | `S1234567A` → `S*******A` |
| `uk_nino` | Preserves the 2 prefix letters and 1 suffix letter of a UK National Insurance Number. | `AB123456C` → `AB******C` |
| `us_ssn` | Preserves the last 4 digits of a 9-digit US Social Security Number. | `123-45-6789` → `***-**-6789` |
| `za_national_id` | Preserves the first 6 (date of birth) and last 4 digits of a 13-digit South African national ID. | `8501015009087` → `850101***9087` |

## Financial

Payment-card, banking, and tax-identifier rules. The `payment_card_pan_first6`, `payment_card_pan_last4`, and `payment_card_pan` rules together cover the three common PCI DSS display modes.

| Rule | Description | Example |
|---|---|---|
| `bank_account_number` | Preserves the last 4 digits of a bank account number, masks the rest. | `12345678` → `****5678` |
| `iban` | Preserves the country code, check digits, and last 4 non-separator characters. | `GB82WEST12345698765432` → `GB82**************5432` |
| `monetary_amount` | Full redact. Length-preserving output would leak the order of magnitude of the amount. | `$1,234.56` → `[REDACTED]` |
| `payment_card_cvv` | Same-length mask — CVV is Sensitive Authentication Data that MUST NOT be retained post-authorisation. | `123` → `***` |
| `payment_card_pan` | Preserves the first 6 and last 4 digits of a Primary Account Number (PCI DSS display mode). | `4111-1111-1111-1111` → `4111-11**-****-1111` |
| `payment_card_pan_first6` | Preserves the first 6 digits; masks the rest. | `4111-1111-1111-1111` → `4111-11**-****-****` |
| `payment_card_pan_last4` | Preserves the last 4 digits; masks the rest. | `4111-1111-1111-1111` → `****-****-****-1111` |
| `payment_card_pin` | Same-length mask; callers concerned about PIN-width leakage should register `full_redact` under this name. | `1234` → `****` |
| `swift_bic` | Preserves the 4-character bank code; accepts 8- or 11-character uppercase ASCII alphanumerics. | `BARCGB2L` → `BARC****` |
| `uk_sort_code` | Preserves the first 2 digits of a UK 6-digit sort code (the bank identifier); preserves separators. | `12-34-56` → `12-**-**` |
| `us_aba_routing_number` | Preserves the last 4 digits of a 9-digit US ABA routing number. | `123456789` → `*****6789` |

## Health

Healthcare identifiers and clinical content. Identifier rules are pseudonymisation, not HIPAA Safe Harbor de-identification — combined with any quasi-identifier (date of service, ZIP, age) they remain re-identifiable. Register a stricter rule (for example `full_redact`) under the same name if your use case requires Safe Harbor compliance.

| Rule | Description | Example |
|---|---|---|
| `diagnosis_code` | Full redact. ICD-10 codes are quasi-identifiers when combined with dates or ZIP codes. | `J45.20` → `[REDACTED]` |
| `health_plan_beneficiary_id` | Preserves the leading alpha-and-separator prefix and keeps the last 4 non-separator characters. | `HPB-987654321` → `HPB-*****4321` |
| `medical_device_identifier` | Preserves the leading alpha-and-separator prefix (including multi-segment prefixes like `DEV-SN-`) and keeps the last 4 non-separator characters. | `DEV-SN-12345678` → `DEV-SN-****5678` |
| `medical_record_number` | Preserves the leading alpha-and-separator prefix and keeps the last 4 non-separator characters of the body. | `MRN-123456789` → `MRN-*****6789` |
| `prescription_text` | Full redact. Free-text prescription fields may expose conditions and clinical details. | `Metformin 500mg twice daily` → `[REDACTED]` |

## Technology

Infrastructure and application-security fields. The URL family never emits `net/url`'s re-encoded output — every rule rebuilds from validated raw fields so percent-encoding and userinfo bytes cannot leak.

| Rule | Description | Example |
|---|---|---|
| `api_key` | Preserves the first 4 and last 4 runes and same-length-masks the middle; input shorter than 9 runes fails closed. | `AKIAIOSFODNN7EXAMPLE` → `AKIA************MPLE` |
| `bearer_token` | Preserves the `Bearer` scheme and its trailing space, keeps the first 6 runes of the token, then appends the literal elision marker `****...` (four mask runes plus three dots — the dots are not the configured mask character, they distinguish the marker from a masked token). | `Bearer abc123def456` → `Bearer abc123****...` |
| `connection_string` | Preserves scheme, host, port, path and non-secret query parameters; redacts userinfo and the values of known secret query parameters. | `postgresql://admin:s3cret@db.example.com:5432/myapp` → `postgresql://****:****@db.example.com:5432/myapp` |
| `database_dsn` | Parses the Go MySQL DSN form and redacts userinfo. | `user:password@tcp(localhost:3306)/dbname` → `****:****@tcp(localhost:3306)/dbname` |
| `hostname` | Preserves the first label and same-length-masks the remaining labels; single-label inputs fail closed. | `web-01.prod.example.com` → `web-01.****.*******.***` |
| `ipv4_address` | Preserves the first 2 octets and masks the last 2 as single mask runes. | `192.168.1.42` → `192.168.*.*` |
| `ipv6_address` | Preserves the first 4 hextets and masks the interface identifier; compressed form is preserved when `::` is in the tail. | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` → `2001:0db8:85a3:0000:****:****:****:****` |
| `jwt_token` | Preserves the first 4 runes of the header segment and masks all three segments with fixed 4-rune blocks; the output ends with a trailing dot. | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc` → `eyJh****.****.****.` |
| `mac_address` | Preserves the OUI (first 3 octets) and masks the device identifier; accepts `:` and `-` separators. | `AA:BB:CC:DD:EE:FF` → `AA:BB:CC:**:**:**` |
| `password` | Emits a fixed 8-rune mask regardless of source length so password length is not leaked; empty input returns empty. | `MyP@ssw0rd!` → `********` |
| `private_key_pem` | Full redact. Private key material must never be partially revealed. | `-----BEGIN RSA PRIVATE KEY-----...` → `[REDACTED]` |
| `url` | Preserves scheme, host, and port; same-length-masks path segments; masks query values and fragment with fixed 4-rune blocks; redacts userinfo defensively. | `https://example.com/users/42?token=abc` → `https://example.com/*****/**?token=****` |
| `url_credentials` | Preserves scheme, host, path, query and fragment; redacts userinfo only. | `https://admin:s3cret@db.example.com/mydb` → `https://****:****@db.example.com/mydb` |
| `uuid` | Preserves the first 8 and last 4 hex runes of a canonical UUID; non-canonical forms fail closed. | `550e8400-e29b-41d4-a716-446655440000` → `550e8400-****-****-****-********0000` |

## Telecom and location

Phone numbers, mobile identifiers, postcodes, and geographic coordinates.

| Rule | Description | Example |
|---|---|---|
| `geo_coordinates` | Splits on a single comma and applies `geo_latitude` / `geo_longitude` to each half. | `37.7749,-122.4194` → `37.77**,-122.41**` |
| `geo_latitude` | Reduces decimal precision to 2 places by truncation; integer input fails closed. Roughly 1.1 km resolution. | `37.7749295` → `37.77*****` |
| `geo_longitude` | Reduces decimal precision to 2 places by truncation; integer input fails closed. | `-122.4194155` → `-122.41*****` |
| `imei` | Preserves the last 4 digits of a 15-digit IMEI. | `353456789012345` → `***********2345` |
| `imsi` | Preserves the first 5 (MCC+MNC) and last 4 digits of a 15-digit IMSI. | `310260123456789` → `31026******6789` |
| `mobile_phone_number` | Alias of `phone_number`. | `+44 7911 123456` → `+44 **** **3456` |
| `msisdn` | Preserves the first 2 and last 4 digits of a 10-15 digit MSISDN. | `447911123456` → `44******3456` |
| `phone_number` | Preserves a leading `+NN` country code (if present) and the last 4 digits; masks middle digits while preserving structural separators. | `+44 7911 123456` → `+44 **** **3456` |
| `postal_code` | Shape-aware across UK (outward code), US 5-digit ZIP (first 3), and Canada (FSA); other shapes fail closed. | `SW1A 2AA` → `SW1A ***` |

---

<sub>Need a rule that's not here? See [Extending](./extending.md) for five custom-rule patterns.</sub>
