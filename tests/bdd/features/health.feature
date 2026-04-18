@health
Feature: Health masking rules
  The health category covers the five HIPAA-scoped fields documented in
  docs/v0.9.0-requirements.md §"Healthcare". Identifier rules preserve
  a leading alphabetic format-literal prefix and keep the last 4
  non-separator characters of the numeric body; clinical free-text
  rules full-redact.

  Scenario Outline: Mask medical record numbers
    Given a fresh masker
    When I apply "medical_record_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input         | expected       |
      | MRN-123456789 | MRN-*****6789  |
      | 123456789     | *****6789      |
      | MRN-12345     | MRN-*2345      |
      | MRN-1234      | ********       |
      | MRN-          | ****           |
      |               |                |

  Scenario: Medical record number honours per-instance mask character
    Given a fresh masker with mask character "X"
    When I apply "medical_record_number" to "MRN-123456789"
    Then the result is "MRN-XXXXX6789"

  Scenario: Medical record number prefix is ASCII-only
    # Cyrillic `М` is not an ASCII letter, so the prefix walk
    # terminates at byte zero and the whole input is treated as
    # the body. Pinned so the ASCII-only rule is a consumer
    # contract, not just an implementation detail.
    Given a fresh masker
    When I apply "medical_record_number" to "МRN-123456789"
    Then the result is "***-*****6789"

  Scenario: Period is data, not a separator, in medical record numbers
    # `MRN.123456789` — prefix walk stops at `.`, body is
    # `.123456789` (10 non-separator runes), so 6 runes are
    # masked (period + five digits) and the last 4 digits kept.
    Given a fresh masker
    When I apply "medical_record_number" to "MRN.123456789"
    Then the result is "MRN******6789"

  Scenario Outline: Mask health plan beneficiary IDs
    Given a fresh masker
    When I apply "health_plan_beneficiary_id" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input         | expected       |
      | HPB-987654321 | HPB-*****4321  |
      | 987654321     | *****4321      |
      | HPB-1234      | ********       |
      | HPB-          | ****           |

  Scenario Outline: Mask medical device identifiers
    Given a fresh masker
    When I apply "medical_device_identifier" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input             | expected           |
      | DEV-SN-12345678   | DEV-SN-****5678    |
      | DEV/SN/12345678   | DEV/SN/****5678    |
      | DEV SN 12345678   | DEV SN ****5678    |
      | DEV-SN-           | *******            |

  Scenario Outline: Mask diagnosis codes
    Given a fresh masker
    When I apply "diagnosis_code" to "<input>"
    Then the result is "[REDACTED]"

    Examples:
      | input  |
      | J45.20 |
      | E11.9  |
      |        |
      | 感冒   |

  Scenario Outline: Mask prescription text
    Given a fresh masker
    When I apply "prescription_text" to "<input>"
    Then the result is "[REDACTED]"

    Examples:
      | input                       |
      | Metformin 500mg twice daily |
      | Lisinopril 10mg daily       |
      | [REDACTED]                  |
      |                             |
      | メトホルミン 500mg          |

  Scenario Outline: Every health rule handles empty input consistently
    Given a fresh masker
    When I apply "<rule>" to ""
    Then the result is "<expected>"

    Examples:
      | rule                         | expected   |
      | medical_record_number        |            |
      | health_plan_beneficiary_id   |            |
      | medical_device_identifier    |            |
      | diagnosis_code               | [REDACTED] |
      | prescription_text            | [REDACTED] |
