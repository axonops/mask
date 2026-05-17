@telecom
Feature: Telecom and location masking rules
  The telecom category covers the 9 rules from
  docs/v0.9.0-requirements.md §"Telecommunications and Location":
  phone_number, mobile_phone_number (alias of phone_number),
  imei, imsi, msisdn, postal_code, geo_latitude, geo_longitude,
  geo_coordinates. Every rule is fail-closed — malformed input
  routes to a same-length mask rather than being echoed.

  Scenario Outline: Mask phone numbers
    Given a fresh masker
    When I apply "phone_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input            | expected         |
      | +44 7911 123456  | +44 **** **3456  |
      | (555) 123-4567   | (***) ***-4567   |
      | +1-800-555-0199  | +1-***-***-0199  |
      | 1-800-FLOWERS    | *************    |
      |                  |                  |

  Scenario: phone_number honours per-instance mask character
    Given a fresh masker with mask character "X"
    When I apply "phone_number" to "+44 7911 123456"
    Then the result is "+44 XXXX XX3456"

  Scenario Outline: Mask phone numbers with 00 international prefix
    # `00<CC>` is the ITU-T E.123 international access prefix used as
    # an alternative to `+` across most of Europe, Africa, Asia, and
    # Oceania. The `00` is preserved verbatim — not rewritten to `+`.
    # Compact form (no separator between CC and body) is accepted for
    # `00` only; the `+` parser rejects compact form (see scenario
    # below pinning that asymmetry).
    Given a fresh masker
    When I apply "phone_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | 0044 7911 123456   | 0044 **** **3456   |
      | 001-212-555-0100   | 001-***-***-0100   |
      | 00352 26 12 34     | 00352 ** 12 34     |
      | 00441234567890     | 00441*****7890     |
      | 00                 | **                 |
      | 007                | ***                |
      | 00044 7911 123456  | ***** **** **3456  |
      | 00 7911 123456     | ** **** **3456     |
      | 00-                | ***                |
      | 0044123            | *******            |
      | 07911 123456       | ***** **3456       |

  Scenario: phone_number rejects compact form on the + prefix
    # Deliberate divergence: `00<CC><digits>` is accepted as compact
    # form, `+<CC><digits>` is not. Documented in rules_telecom.go
    # splitPhonePrefix. This scenario pins the asymmetry against
    # accidental "consistency fixes".
    Given a fresh masker
    When I apply "phone_number" to "+441234567890"
    Then the result is "*************"

  Scenario Outline: mobile_phone_number is an alias of phone_number
    Given a fresh masker
    When I apply "mobile_phone_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input            | expected         |
      | +44 7911 123456  | +44 **** **3456  |
      | 07911 123456     | ***** **3456     |
      | 0044 7911 123456 | 0044 **** **3456 |
      | (555) 123-4567   | (***) ***-4567   |
      | 1-800-FLOWERS    | *************    |
      |                  |                  |

  Scenario Outline: Mask IMEIs
    Given a fresh masker
    When I apply "imei" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | 353456789012345    | ***********2345    |
      | 35345678901234     | **************     |
      | 3534567890123456   | ****************   |
      |                    |                    |

  Scenario Outline: Mask IMSIs
    Given a fresh masker
    When I apply "imsi" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | 310260123456789    | 31026******6789    |
      | 234150000123456    | 23415******3456    |
      | 31026012345678     | **************     |
      | 3102601234567890   | ****************   |
      |                    |                    |

  Scenario Outline: Mask MSISDNs
    Given a fresh masker
    When I apply "msisdn" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input             | expected          |
      | 447911123456      | 44******3456      |
      | 4479111234        | 44****1234        |
      | +447911123456     | *************     |
      |                   |                   |

  Scenario Outline: Mask postal codes
    # Shape-aware dispatch: UK, US, and Canada. Other shapes fail
    # closed. Lowercase variants fail closed to keep output
    # unambiguous.
    Given a fresh masker
    When I apply "postal_code" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input      | expected   |
      | SW1A 2AA   | SW1A ***   |
      | SW1A2AA    | SW1A***    |
      | M1 1AA     | M1 ***     |
      | M11AA      | M1***      |
      | BT15JE     | BT1***     |
      | EC1A7AB    | EC1A***    |
      | 94103      | 941**      |
      | M5V 2T6    | M5V ***    |
      | M5V2T6     | ******     |
      | sw1a 2aa   | ********   |
      | 94103-6789 | **********  |
      | 01310-100  | *********  |
      |            |            |

  Scenario Outline: Mask geo latitudes
    Given a fresh masker
    When I apply "geo_latitude" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input        | expected      |
      | 37.7749295   | 37.77*****    |
      | -33.8688197  | -33.86*****   |
      | 42           | **            |
      | 3.77e1       | ******        |
      |              |               |

  Scenario Outline: Mask geo longitudes
    Given a fresh masker
    When I apply "geo_longitude" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input         | expected       |
      | -122.4194155  | -122.41*****   |
      | 139.6503      | 139.65**       |
      | 0.12345       | 0.12***        |
      | 180           | ***            |
      |               |                |

  Scenario Outline: Mask geo coordinate pairs
    Given a fresh masker
    When I apply "geo_coordinates" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | 37.7749,-122.4194  | 37.77**,-122.41**  |
      | 37.7749            | *******            |
      | 37.77,abc          | *********          |
      | 37.77, -122.42     | **************     |
      |                    |                    |

  Scenario Outline: Every telecom rule handles empty input consistently
    Given a fresh masker
    When I apply "<rule>" to ""
    Then the result is "<expected>"

    Examples:
      | rule                | expected |
      | phone_number        |          |
      | mobile_phone_number |          |
      | imei                |          |
      | imsi                |          |
      | msisdn              |          |
      | postal_code         |          |
      | geo_latitude        |          |
      | geo_longitude       |          |
      | geo_coordinates     |          |
