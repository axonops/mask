@identity
Feature: Identity masking rules
  The identity category covers personal and identity fields documented in
  docs/v0.9.0-requirements.md §"Personal and Identity". Each rule is
  format-aware, fails closed on malformed input, and honours the
  configured mask character.

  Scenario Outline: Mask email addresses
    Given a fresh masker
    When I apply "email_address" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                        | expected                       |
      | alice@example.com            | a****@example.com              |
      | bob.smith+work@company.co.uk | b*************@company.co.uk   |
      | x@y.com                      | *@y.com                        |
      | not-an-email                 | ************                   |
      | @example.com                 | ************                   |
      | alice@                       | ******                         |
      | a@b@c.com                    | a**@c.com                      |

  Scenario: Email address honours per-instance mask character
    Given a fresh masker with mask character "X"
    When I apply "email_address" to "alice@example.com"
    Then the result is "aXXXX@example.com"

  Scenario Outline: Mask person names
    Given a fresh masker
    When I apply "person_name" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | John Doe           | J*** D**           |
      | María García-López | M**** G*****-L**** |
      | D'Angelo Smith     | D'A***** S****     |
      | O'Brien            | O'B****            |
      | 佐藤 太郎          | 佐* 太*            |

  Scenario: CJK person name without separators is a single token
    # Known deviation from the spec example (佐藤太郎 → 佐*太*) because the
    # Go stdlib has no CJK-aware segmenter. Pinned here so the behaviour
    # cannot regress silently. See the godoc on maskPersonName.
    Given a fresh masker
    When I apply "person_name" to "佐藤太郎"
    Then the result is "佐***"

  Scenario Outline: Mask given and family names
    Given a fresh masker
    When I apply "<rule>" to "<input>"
    Then the result is "<expected>"

    Examples:
      | rule        | input  | expected |
      | given_name  | Alice  | A****    |
      | given_name  | María  | M****    |
      | family_name | Smith  | S****    |
      | family_name | O'Brien | O******  |

  Scenario Outline: Mask street addresses
    Given a fresh masker
    When I apply "street_address" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                         | expected                    |
      | 42 Wallaby Way                | 42 ******* Way              |
      | 1600 Pennsylvania Avenue NW   | 1600 ************ Avenue NW |
      | 42 Wallaby way                | 42 ******* way              |
      | 42 Main                       | 42 ****                     |
      | Way 42                        | ******                      |
      | Apt 3                         | *****                       |
      | 42 N                          | 42 *                        |
      | 1 NE                          | 1 **                        |
      | 42                            | **                          |

  Scenario Outline: Mask dates of birth
    Given a fresh masker
    When I apply "date_of_birth" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                | expected             |
      | 1985-03-15           | 1985-**-**           |
      | 15/03/1985           | **/****/1985         |
      | March 15, 1985       | ***** **, 1985       |
      | 1985                 | ****                 |
      | 1985-03-15T00:00:00Z | ******************** |
      | 15.03.1985           | **********           |

  Scenario Outline: Mask usernames
    Given a fresh masker
    When I apply "username" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input     | expected  |
      | johndoe42 | jo******* |
      | admin     | ad***     |
      | alice_42  | al******  |
      | x         | *         |
      | ab        | **        |
      |           |           |

  Scenario Outline: Mask passport numbers
    Given a fresh masker
    When I apply "passport_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input      | expected    |
      | GB1234567  | GB*****67   |
      | 123456789  | *****6789   |
      | gb1234567  | gb*****67   |
      | 1A234567   | ****4567    |
      | GB         | **          |
      | 1234       | ****        |
      | GBCD       | ****        |

  Scenario Outline: Mask driver licence numbers
    Given a fresh masker
    When I apply "driver_license_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input            | expected            |
      | DL-1234-5678     | DL-****-5678        |
      | SMITH901015JN9AA | SM***********9AA    |
      | D 1234 5678      | D 1*** 5678         |
      | A-B              | ***                 |
      |                  |                     |

  Scenario Outline: Mask generic national identifiers
    Given a fresh masker
    When I apply "generic_national_id" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input        | expected     |
      | AB123456CD   | AB******CD   |
      | 佐藤1234太郎 | 佐藤****太郎 |
      | 123456789    | 12*****89    |
      | ABCD         | ****         |
      | AB1          | ***          |
      |              |              |

  Scenario Outline: Every identity rule returns empty on empty input
    Given a fresh masker
    When I apply "<rule>" to ""
    Then the result is ""

    Examples:
      | rule                  |
      | email_address         |
      | person_name           |
      | given_name            |
      | family_name           |
      | street_address        |
      | date_of_birth         |
      | username              |
      | passport_number       |
      | driver_license_number |
      | generic_national_id   |
      | tax_identifier        |

  Scenario Outline: Mask tax identifiers
    Given a fresh masker
    When I apply "tax_identifier" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input           | expected       |
      | 12-3456789      | **-***6789     |
      | 1234            | *234           |
      | 12345678        | ****5678       |
      | 123.456.789-10  | ***.***.*89-10 |
      | **-***6789      | **-***6789     |
