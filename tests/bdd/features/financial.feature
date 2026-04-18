@financial
Feature: Financial masking rules
  The financial category covers payment-card, banking, and monetary
  fields documented in docs/v0.9.0-requirements.md §"Financial". Each
  rule preserves grouping separators where the spec demands, fails
  closed on malformed input, and honours the configured mask character.

  Scenario Outline: Mask payment card numbers (first 6 + last 4)
    Given a fresh masker
    When I apply "payment_card_pan" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                     | expected                  |
      | 4111222233334444          | 411122******4444          |
      | 4111-2222-3333-4444       | 4111-22**-****-4444       |
      | 371449635398431           | 371449*****8431           |
      | 4111222233334             | 411122***3334             |
      | 411122223333              | ************              |
      | 41112222333344445555      | ********************      |
      |                           |                           |

  Scenario: Payment card PAN honours per-instance mask character
    Given a fresh masker with mask character "X"
    When I apply "payment_card_pan" to "4111222233334444"
    Then the result is "411122XXXXXX4444"

  Scenario Outline: Mask payment card PAN keeping only first 6
    Given a fresh masker
    When I apply "payment_card_pan_first6" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                | expected             |
      | 4111222233334444     | 411122**********     |
      | 4111-2222-3333-4444  | 4111-22**-****-****  |
      | 5555444433332222     | 555544**********     |
      | 411122223333         | ************         |

  Scenario Outline: Mask payment card PAN keeping only last 4
    Given a fresh masker
    When I apply "payment_card_pan_last4" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                | expected             |
      | 4111222233334444     | ************4444     |
      | 4111-2222-3333-4444  | ****-****-****-4444  |
      | 5555-4444-3333-2222  | ****-****-****-2222  |
      | 1234                 | ****                 |
      |                      |                      |

  Scenario Outline: Mask payment card CVV
    Given a fresh masker
    When I apply "payment_card_cvv" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input | expected |
      | 123   | ***      |
      | 1234  | ****     |
      | abc   | ***      |
      | 9876  | ****     |
      |       |          |

  Scenario Outline: Mask payment card PIN
    Given a fresh masker
    When I apply "payment_card_pin" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input  | expected |
      | 1234   | ****     |
      | 123456 | ******   |
      | 0000   | ****     |
      | abc1   | ****     |
      |        |          |

  Scenario Outline: Mask bank account numbers
    Given a fresh masker
    When I apply "bank_account_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input          | expected       |
      | 12345678       | ****5678       |
      | 1234-5678-9012 | ****-****-9012 |
      | 9876543210     | ******3210     |
      | 123            | ***            |
      |                |                |

  Scenario Outline: Mask UK sort codes
    Given a fresh masker
    When I apply "uk_sort_code" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input    | expected |
      | 12-34-56 | 12-**-** |
      | 123456   | 12****   |
      | 12 34 56 | 12 ** ** |
      | 12345    | *****    |
      |          |          |

  Scenario Outline: Mask US ABA routing numbers
    Given a fresh masker
    When I apply "us_aba_routing_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input     | expected  |
      | 021000021 | *****0021 |
      | 123456789 | *****6789 |
      | 02100002  | ********  |
      | abc       | ***       |
      |           |           |

  Scenario Outline: Mask IBANs
    # Spec prose requires "country code, check digits, and last 4"
    # preserved. We implement length-preserving first 4 + last 4 and
    # pin the byte-exact output. The two spec example star-counts
    # differ from strict length-preservation; the prose is authoritative
    # and our tests reflect the prose, not the literal example output.
    Given a fresh masker
    When I apply "iban" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                        | expected                     |
      | GB82WEST12345698765432       | GB82**************5432       |
      | DE89370400440532013000       | DE89**************3000       |
      | GB82 WEST 1234 5698 7654 32  | GB82 **** **** **** **54 32  |
      | GB82WEST1234567              | GB82*******4567              |
      | gb82west12345698765432       | **********************       |

  Scenario Outline: Mask SWIFT/BIC codes
    Given a fresh masker
    When I apply "swift_bic" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input        | expected     |
      | BARCGB2L     | BARC****     |
      | DEUTDEFF500  | DEUT*******  |
      | DEUTDEFF1234 | ************ |
      | barcgb2l     | ********     |
      | BARCGB       | ******       |

  Scenario Outline: Mask monetary amounts
    Given a fresh masker
    When I apply "monetary_amount" to "<input>"
    Then the result is "[REDACTED]"

    Examples:
      | input     |
      | $1,234.56 |
      | €99.99    |
      | -500      |
      | 0         |
      | [REDACTED] |

  Scenario Outline: Every financial rule returns empty on empty input
    Given a fresh masker
    When I apply "<rule>" to ""
    Then the result is "<expected>"

    Examples:
      | rule                    | expected   |
      | payment_card_pan        |            |
      | payment_card_pan_first6 |            |
      | payment_card_pan_last4  |            |
      | payment_card_cvv        |            |
      | payment_card_pin        |            |
      | bank_account_number     |            |
      | uk_sort_code            |            |
      | us_aba_routing_number   |            |
      | iban                    |            |
      | swift_bic               |            |
      | monetary_amount         | [REDACTED] |
