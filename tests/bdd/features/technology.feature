@technology
Feature: Technology and infrastructure masking rules
  The technology category covers the 14 rules documented in
  docs/v0.9.0-requirements.md §"Technology and Infrastructure".
  Identifier rules (IP, MAC, UUID) preserve the structural prefix
  and mask the variable tail; content rules (URL, JWT, DSN)
  parse the input and mask only sensitive subcomponents; secret
  rules (password, private_key_pem) use a fixed-shape or full
  redaction independent of input length.

  Scenario Outline: Mask IPv4 addresses
    Given a fresh masker
    When I apply "ipv4_address" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input           | expected         |
      | 192.168.1.42    | 192.168.*.*      |
      | 10.0.0.1        | 10.0.*.*         |
      | 0.0.0.0         | 0.0.*.*          |
      | 255.255.255.255 | 255.255.*.*      |
      | 192.168.1       | *********        |
      | 999.999.999.999 | ***************  |
      |                 |                  |

  Scenario: IPv4 rule honours per-instance mask character
    Given a fresh masker with mask character "X"
    When I apply "ipv4_address" to "192.168.1.42"
    Then the result is "192.168.X.X"

  Scenario Outline: Mask IPv6 addresses
    Given a fresh masker
    When I apply "ipv6_address" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                                   | expected                                |
      | 2001:0db8:85a3:0000:0000:8a2e:0370:7334 | 2001:0db8:85a3:0000:****:****:****:**** |
      | fe80::1                                 | fe80::****                              |
      | ::1                                     | ::****                                  |
      | 2001:db8::1:2                           | 2001:db8::****:****                     |
      | fe80::1%eth0                            | ************                            |
      | ::ffff:192.168.1.1                      | ******************                      |
      |                                         |                                         |

  Scenario Outline: Mask MAC addresses
    Given a fresh masker
    When I apply "mac_address" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input             | expected            |
      | AA:BB:CC:DD:EE:FF | AA:BB:CC:**:**:**   |
      | AA-BB-CC-DD-EE-FF | AA-BB-CC-**-**-**   |
      | aa:bb:cc:dd:ee:ff | aa:bb:cc:**:**:**   |
      | AA:BB-CC:DD-EE:FF | *****************   |
      | AABB.CCDD.EEFF    | **************      |
      | AABBCCDDEEFF      | ************        |
      |                   |                     |

  Scenario Outline: Mask hostnames
    # Single-label hostnames fail closed — the spec's literal echo
    # of `db-master` contradicts the library's fail-closed contract,
    # and we've chosen to honour the contract. Label mask width is
    # same-length (matches the `com → ***` branch of the spec).
    Given a fresh masker
    When I apply "hostname" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                   | expected                |
      | web-01.prod.example.com | web-01.****.*******.*** |
      | example.com             | example.***             |
      | db-master               | *********               |
      | .example.com            | ************            |
      | example.com.            | ************            |
      | foo..bar                | ********                |
      |                         |                         |

  Scenario Outline: Mask URLs
    # Path segments are same-length-masked; query values get a
    # fixed 4-rune mask regardless of their length; fragments
    # get a fixed 4-rune mask. URLs with no sensitive components
    # (no userinfo, no path beyond `/`, no query, no fragment)
    # fail closed to avoid echoing the input.
    Given a fresh masker
    When I apply "url" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                                   | expected                                |
      | https://example.com/users/42?token=abc  | https://example.com/*****/**?token=****  |
      | http://localhost:8080/api/v1            | http://localhost:8080/***/**            |
      | https://example.com#section             | https://example.com#****                |
      | https://alice:secret@example.com/path   | https://****:****@example.com/****      |
      | https://example.com                     | *******************                     |
      | not a url                               | *********                               |
      |                                         |                                         |

  Scenario Outline: Mask URL credentials only
    Given a fresh masker
    When I apply "url_credentials" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                                    | expected                                |
      | https://admin:s3cret@db.example.com/mydb | https://****:****@db.example.com/mydb   |
      | https://alice@example.com/mydb           | https://****@example.com/mydb           |
      | https://db.example.com/mydb              | ***************************             |
      |                                          |                                         |

  Scenario Outline: Mask API keys
    Given a fresh masker
    When I apply "api_key" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                      | expected                   |
      | AKIAIOSFODNN7EXAMPLE       | AKIA************MPLE       |
      | sk_live_abc123def456ghi789 | sk_l******************i789 |
      | 12345678                   | ********                   |
      | 123456789                  | 1234*6789                  |
      |                            |                            |

  Scenario Outline: Mask JWT tokens
    # The spec output ends with a trailing dot — this is a literal
    # format token, not a sentence terminator.
    Given a fresh masker
    When I apply "jwt_token" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                                                                                        | expected                |
      | eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U | eyJh****.****.****.     |
      | eyJh.payload.sig                                                                             | eyJh****.****.****.     |
      | aaaa.bbbb                                                                                    | *********               |
      | eyJh.pay@load.sig                                                                            | *****************       |
      |                                                                                              |                         |

  Scenario Outline: Mask bearer tokens
    # Output ends with literal `****...` (four mask runes then three
    # ASCII dots), a constant elision marker regardless of token
    # length.
    Given a fresh masker
    When I apply "bearer_token" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                               | expected                   |
      | Bearer abc123def456                 | Bearer abc123****...       |
      | Bearer eyJhbGciOiJIUzI1NiJ9.xxx.yyy | Bearer eyJhbG****...       |
      | Bearer abc                          | **********                 |
      | Basic dXNlcjpwYXNz                  | ******************         |
      | bearer abcdef123                    | ****************           |
      |                                     |                            |

  Scenario Outline: Mask passwords
    Given a fresh masker
    When I apply "password" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input       | expected |
      | MyP@ssw0rd! | ******** |
      | x           | ******** |
      | a           | ******** |
      | longpassword | ******** |
      |             |          |

  Scenario: Password rule honours per-instance mask character
    Given a fresh masker with mask character "X"
    When I apply "password" to "MyP@ssw0rd!"
    Then the result is "XXXXXXXX"

  Scenario Outline: Full-redact private keys
    Given a fresh masker
    When I apply "private_key_pem" to "<input>"
    Then the result is "[REDACTED]"

    Examples:
      | input                                 |
      | -----BEGIN RSA PRIVATE KEY-----\nMIIE |
      | -----BEGIN EC PRIVATE KEY-----        |
      | -----BEGIN OPENSSH PRIVATE KEY-----   |
      |                                       |
      | garbage input                         |

  Scenario Outline: Mask connection strings
    Given a fresh masker
    When I apply "connection_string" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                                                              | expected                                                           |
      | postgresql://admin:s3cret@db.example.com:5432/myapp                | postgresql://****:****@db.example.com:5432/myapp                   |
      | mongodb+srv://user:pass@cluster.mongodb.net/db                     | mongodb+srv://****:****@cluster.mongodb.net/db                     |
      | postgresql://db.example.com/d?password=secret                      | postgresql://db.example.com/d?password=****                        |
      | postgresql://db.example.com/d?user=u&password=p&sslmode=require    | postgresql://db.example.com/d?user=u&password=****&sslmode=require |
      | postgresql://db.example.com:5432/myapp                             | **************************************                             |
      |                                                                    |                                                                    |

  Scenario Outline: Mask Go MySQL DSNs
    Given a fresh masker
    When I apply "database_dsn" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                                    | expected                                 |
      | user:password@tcp(localhost:3306)/dbname | ****:****@tcp(localhost:3306)/dbname     |
      | user:pass@unix(/tmp/mysql.sock)/dbname   | ****:****@unix(/tmp/mysql.sock)/dbname   |
      | user@tcp(host)/db                        | ****@tcp(host)/db                        |
      | user:pass@host/db                        | *****************                        |
      |                                          |                                          |

  Scenario Outline: Mask UUIDs
    Given a fresh masker
    When I apply "uuid" to "<input>"
    Then the result is "<expected>"

    Examples:
      | input                                | expected                             |
      | 550e8400-e29b-41d4-a716-446655440000 | 550e8400-****-****-****-********0000 |
      | 550E8400-E29B-41D4-A716-446655440000 | 550E8400-****-****-****-********0000 |
      | 00000000-0000-0000-0000-000000000000 | 00000000-****-****-****-********0000 |
      | 550e8400e29b41d4a716446655440000     | ********************************     |
      |                                      |                                      |

  Scenario Outline: Every technology rule handles empty input consistently
    Given a fresh masker
    When I apply "<rule>" to ""
    Then the result is "<expected>"

    Examples:
      | rule              | expected   |
      | ipv4_address      |            |
      | ipv6_address      |            |
      | mac_address       |            |
      | hostname          |            |
      | url               |            |
      | url_credentials   |            |
      | api_key           |            |
      | jwt_token         |            |
      | bearer_token      |            |
      | password          |            |
      | private_key_pem   | [REDACTED] |
      | connection_string |            |
      | database_dsn      |            |
      | uuid              |            |
