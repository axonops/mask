@country
Feature: Country-specific identity masking rules
  The country catalogue covers 14 jurisdiction-specific identity
  numbers from docs/v0.9.0-requirements.md §"Personal and Identity"
  (us_ssn through es_dni_nif_nie). Each rule preserves a small
  deterministic window (first N, last M, or both) appropriate to the
  jurisdiction and masks the rest; every rule fails closed on
  malformed input.

  Scenario Outline: Mask US SSNs
    Given a fresh masker
    When I apply "us_ssn" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input        | expected     |
      | 123-45-6789  | ***-**-6789  |
      | 123456789    | *****6789    |
      | 12345678     | ********     |
      | 12-345-6789  | ***********  |
      |              |              |

  Scenario Outline: Mask Canadian SINs
    Given a fresh masker
    When I apply "ca_sin" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input        | expected    |
      | 123-456-789  | ***-***-789 |
      | 123456789    | ******789   |
      | 12345678     | ********    |
      | 1234-56-789  | *********** |
      |              |             |

  Scenario Outline: Mask UK National Insurance Numbers
    Given a fresh masker
    When I apply "uk_nino" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input         | expected      |
      | AB123456C     | AB******C     |
      | AB 12 34 56 C | AB ** ** ** C |
      | ab123456c     | *********     |
      |               |               |

  Scenario Outline: Mask Indian Aadhaar
    Given a fresh masker
    When I apply "in_aadhaar" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input          | expected       |
      | 1234 5678 9012 | **** **** 9012 |
      | 123456789012   | ********9012   |
      | 12345678901    | ***********    |
      | 1234 5678 901  | *************  |
      |                |                |

  Scenario Outline: Mask Indian PAN
    Given a fresh masker
    When I apply "in_pan" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input      | expected   |
      | ABCDE1234F | ABC*****4F |
      | abcde1234f | ********** |
      | ABCDE12345 | ********** |
      | ABCD1234FG | ********** |
      |            |            |

  Scenario Outline: Mask Australian Medicare numbers
    # Spec text says "last 3-4 digits" but the spec example keeps
    # the trailing 2 digits; we follow the example.
    Given a fresh masker
    When I apply "au_medicare_number" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input        | expected     |
      | 2123 45670 1 | **** ****0 1 |
      | 2123456701   | ********01   |
      | 212345670    | *********    |
      | 2123 45670 1A| ************* |
      |              |              |

  Scenario Outline: Mask Singapore NRIC/FIN
    Given a fresh masker
    When I apply "sg_nric_fin" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input     | expected  |
      | S1234567A | S*******A |
      | T7654321B | T*******B |
      | s1234567a | ********* |
      | S123A     | *****     |
      |           |           |

  Scenario Outline: Mask Brazilian CPF
    Given a fresh masker
    When I apply "br_cpf" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input          | expected       |
      | 123.456.789-09 | ***.***.***-09 |
      | 12345678909    | *********09    |
      | 001.234.567-89 | ***.***.***-89 |
      | 123/456/789-09 | ************** |
      |                |                |

  Scenario Outline: Mask Brazilian CNPJ
    Given a fresh masker
    When I apply "br_cnpj" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | 12.345.678/0001-95 | **.***.***/****-95 |
      | 12345678000195     | ************95     |
      | 12-345-678/0001-95 | ****************** |
      | 12.345.678/0001-9  | *****************  |
      |                    |                    |

  Scenario Outline: Mask Mexican CURP
    # Spec output is 17 chars for an 18-char input; we honour the
    # library-wide same-length invariant and emit 18 chars.
    Given a fresh masker
    When I apply "mx_curp" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | GAPA850101HDFRRL09 | GAPA***********L09 |
      | HEGG560427MVZRRL04 | HEGG***********L04 |
      | gapa850101hdfrrl09 | ****************** |
      | GAPA850101HDFRRL0  | *****************  |
      |                    |                    |

  Scenario Outline: Mask Mexican RFC
    Given a fresh masker
    When I apply "mx_rfc" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input         | expected      |
      | GAPA8501014T3 | GAP*******4T3 |
      | ABC850101DEF  | ABC******DEF  |
      | gapa8501014t3 | ************* |
      | ABC850101     | *********     |
      |               |               |

  Scenario Outline: Mask Chinese Resident Identity Card numbers
    Given a fresh masker
    When I apply "cn_resident_id" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input              | expected           |
      | 110101199003074578 | 110101********4578 |
      | 11010119900307457X | 110101********457X |
      | 11010119900307457x | 110101********457x |
      | 11010119900307457Y | ****************** |
      |                    |                    |

  Scenario Outline: Mask South African national IDs
    Given a fresh masker
    When I apply "za_national_id" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input          | expected       |
      | 8501015009087  | 850101***9087  |
      | 9001010000005  | 900101***0005  |
      | 850101500908   | ************   |
      | 85010150090870 | ************** |
      |                |                |

  Scenario Outline: Mask Spanish DNI/NIF/NIE
    Given a fresh masker
    When I apply "es_dni_nif_nie" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input     | expected  |
      | 12345678Z | ********Z |
      | X1234567L | X*******L |
      | Y1234567M | Y*******M |
      | Z1234567N | Z*******N |
      | 12345678z | ********* |
      | ABCDEFGHI | ********* |
      |           |           |

  Scenario Outline: Every country rule handles empty input consistently
    Given a fresh masker
    When I apply "<rule>" to ""
    Then the result is ""

    Examples:
      | rule               |
      | us_ssn             |
      | ca_sin             |
      | uk_nino            |
      | in_aadhaar         |
      | in_pan             |
      | au_medicare_number |
      | sg_nric_fin        |
      | br_cpf             |
      | br_cnpj            |
      | mx_curp            |
      | mx_rfc             |
      | cn_resident_id     |
      | za_national_id     |
      | es_dni_nif_nie     |
