@primitives
Feature: Utility primitives
  The mask library ships composable building blocks — FullRedact, Nullify,
  SameLengthMask, KeepFirstN, KeepLastN, KeepFirstLast, PreserveDelimiters,
  ReplaceRegex, TruncateVisible, DeterministicHash, FixedReplacement, and
  ReducePrecision. This feature documents the contract every consumer can
  rely on.

  Scenario Outline: Full redact always returns the constant marker
    Given a fresh masker
    When I apply "full_redact" to "<input>"
    Then the result is "[REDACTED]"

    Examples:
      | input       |
      |             |
      | anything    |
      | 佐藤太郎     |
      | ****        |

  Scenario Outline: Same length mask preserves rune count
    Given a fresh masker with mask character "<char>"
    When I apply "same_length_mask" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input    | char | expected |
      | Hello    | *    | *****    |
      | 佐藤太郎  | *    | ****     |
      |          | *    |          |
      | Hello    | X    | XXXXX    |

  Scenario Outline: Keep first N characters (direct helper)
    When I use KeepFirstN on "<input>" with n <n> and char "<char>"
    Then the result is "<expected>"

    Examples:
      | input    | n  | char | expected   |
      | abcdef   | 0  | *    | ******     |
      | abcdef   | 3  | *    | abc***     |
      | abcdef   | 99 | *    | abcdef     |
      | abcdef   | -1 | *    | ******     |
      | Müller   | 3  | *    | Mül***     |
      | 佐藤太郎  | 2  | *    | 佐藤**      |
      |          | 2  | *    |            |

  Scenario Outline: Keep last N characters (direct helper)
    When I use KeepLastN on "<input>" with n <n> and char "<char>"
    Then the result is "<expected>"

    Examples:
      | input    | n  | char | expected   |
      | abcdef   | 0  | *    | ******     |
      | abcdef   | 3  | *    | ***def     |
      | abcdef   | 99 | *    | abcdef     |
      | Müller   | 3  | *    | ***ler     |
      | 佐藤太郎  | 2  | *    | **太郎      |

  Scenario Outline: Keep first and last characters (direct helper)
    When I use KeepFirstLast on "<input>" with first <first> last <last> and char "<char>"
    Then the result is "<expected>"

    Examples:
      | input          | first | last | char | expected       |
      | SensitiveData  | 4     | 4    | *    | Sens*****Data  |
      | ABCD           | 2     | 2    | *    | ABCD           |
      | ABCD           | 3     | 2    | *    | ABCD           |
      | ABCDE          | 2     | 2    | *    | AB*DE          |
      | María          | 2     | 1    | *    | Ma**a          |
      |                | 2     | 2    | *    |                |

  Scenario Outline: Preserve delimiters while masking surrounding runes
    When I use PreserveDelimiters on "<input>" with delim "<delim>" and char "<char>"
    Then the result is "<expected>"

    Examples:
      | input              | delim | char | expected          |
      | alice@example.com  | @.    | *    | *****@*******.*** |
      | 1-800-555-0199     | -     | *    | *-***-***-****    |
      | abc                |       | *    | ***               |
      | 佐藤・太郎          | ・    | *    | **・**             |

  Scenario Outline: Replace regex with a valid pattern
    When I use ReplaceRegex on "<input>" with pattern "<pattern>" and replacement "<replacement>"
    Then the replace result is "<expected>" and the error is absent

    Examples:
      | input  | pattern | replacement | expected |
      | id-42  | \d+     | N           | id-N     |
      | abc    | z+      | X           | abc      |
      | abc    | (a)(b)  | $2$1        | bac      |
      | abc    | b       |             | ac       |

  Scenario: Replace regex with an invalid pattern is rejected
    When I use ReplaceRegex on "anything" with pattern "[a-" and replacement "X"
    Then the replace result is empty and the error is present

  Scenario Outline: Truncate visible to N characters
    When I use TruncateVisible on "<input>" with n <n>
    Then the result is "<expected>"

    Examples:
      | input    | n  | expected |
      | abcdef   | 0  |          |
      | abcdef   | -1 |          |
      | abcdef   | 3  | abc      |
      | abcdef   | 99 | abcdef   |
      | Müller   | 3  | Mül      |

  Scenario: Deterministic hash is deterministic across invocations
    Given a fresh masker
    When I apply "deterministic_hash" to "alice@example.com" 100 times
    Then every result is identical

  Scenario: Deterministic hash uses SHA-256 by default
    Given a fresh masker
    When I apply "deterministic_hash" to "alice@example.com"
    Then the result starts with "sha256:"
    And the result has length 23

  Scenario Outline: Deterministic hash emits the selected algorithm prefix
    When I compute DeterministicHashWith on "alice@example.com" using algorithm "<algo>"
    Then the result starts with "<prefix>:"
    And the result has length <length>

    Examples:
      | algo     | prefix    | length |
      | SHA256   | sha256    | 23     |
      | SHA512   | sha512    | 23     |
      | SHA3_256 | sha3-256  | 25     |
      | SHA3_512 | sha3-512  | 25     |

  Scenario Outline: Deterministic hash with a salt matches an independent HMAC reference vector
    When I compute DeterministicHashWith on "hello" using algorithm "<algo>" and salt "k" version "v1"
    Then the result is exactly "<expected>"

    Examples:
      | algo     | expected                     |
      | SHA256   | sha256:v1:406e4b43f87095aa   |
      | SHA512   | sha512:v1:86b6102b754ae558   |
      | SHA3_256 | sha3-256:v1:f3ac848aab5f2471 |
      | SHA3_512 | sha3-512:v1:f4b5180b78087d99 |

  Scenario Outline: Salt version is emitted between the algorithm prefix and the digest
    When I compute DeterministicHashWith on "hello" using algorithm "<algo>" and salt "k" version "<version>"
    Then the result starts with "<prefix>"

    Examples:
      | algo     | version   | prefix            |
      | SHA256   | v1        | sha256:v1:        |
      | SHA512   | v1        | sha512:v1:        |
      | SHA3_256 | 2026-01   | sha3-256:2026-01: |
      | SHA3_512 | v_1.2-rc  | sha3-512:v_1.2-rc: |

  Scenario: Deterministic hash with different salts produces different outputs
    When I compute DeterministicHashWith on "alice@example.com" with salt "a" version "v1"
    And I also compute DeterministicHashWith on "alice@example.com" with salt "b" version "v1"
    Then the two results differ

  Scenario: Deterministic hash salt does not appear in the masked output
    When I compute DeterministicHashWith on "SEKRET-value-SEKRET" with salt "SEKRET" version "v1"
    Then the result does not contain "SEKRET"

  Scenario: Deterministic hash with an empty version fails closed
    When I compute DeterministicHashWith on "hello" with salt "k" version ""
    Then the result is exactly "[REDACTED]"

  Scenario Outline: Deterministic hash with a non-conforming version fails closed
    When I compute DeterministicHashWith on "hello" with salt "k" version "<version>"
    Then the result is exactly "[REDACTED]"

    Examples:
      | version                            |
      | v:1                                |
      | v 1                                |
      | v/1                                |
      | café                               |
      | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  |

  Scenario: Nullify returns an empty string
    Given a fresh masker
    When I apply "nullify" to "anything"
    Then the result is ""

  Scenario Outline: Fixed replacement ignores input
    When I use FixedReplacementFunc with replacement "<replacement>" on "<input>"
    Then the result is "<replacement>"

    Examples:
      | replacement | input    |
      | N/A         | secret   |
      | N/A         |          |
      | [NONE]      | 佐藤太郎  |

  Scenario Outline: Reduce precision for numeric input
    When I use ReducePrecision on "<input>" with decimals <decimals> and char "<char>"
    Then the result is "<expected>"

    Examples:
      | input        | decimals | char | expected    |
      | 37.7749295   | 2        | *    | 37.77*****  |
      | -37.7749     | 2        | *    | -37.77**    |
      | +37.77       | 2        | *    | +37.77      |
      | 037.70       | 1        | *    | 037.7*      |
      | 42           | 2        | *    | 42          |
      | 37.7         | 5        | *    | 37.7        |
      |              | 2        | *    |             |

  Scenario Outline: Reduce precision falls back for non-numeric input
    When I use ReducePrecision on "<input>" with decimals 2 and char "*"
    Then the result is "<expected>"

    Examples:
      | input       | expected  |
      | 1.2e5       | *****     |
      | NaN         | ***       |
      | Inf         | ***       |
      | 1.2.3       | *****     |
      | 37,77       | *****     |
