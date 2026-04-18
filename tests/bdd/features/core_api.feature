Feature: Core masking API
  The mask library exposes a package-level API plus per-instance Maskers.
  This feature documents the contract for Apply, Register, and the
  configuration knobs that every consumer relies on.

  @core_api
  Scenario: Applying an unknown rule returns full redact
    Given a fresh masker
    When I mask "alice@example.com" with rule "nope_not_a_rule"
    Then the result is "[REDACTED]"

  @core_api
  Scenario: Registering a custom rule and applying it
    Given a fresh masker
    And I register a custom rule "reverse_custom" that reverses its input
    When I mask "abc" with rule "reverse_custom"
    Then the result is "cba"

  @core_api
  Scenario: Duplicate rule registration is rejected
    Given a fresh masker
    And I register a custom rule "dup_feature" that reverses its input
    When I register "dup_feature" a second time
    Then the registration fails with error kind "duplicate"

  @core_api
  Scenario Outline: Invalid rule name is rejected
    Given a fresh masker
    When I register "<name>" with a valid function
    Then the registration fails with error kind "invalid"

    Examples:
      | name        |
      |             |
      | Uppercase   |
      | with space  |
      | 1leading    |
      | with-dash   |

  @core_api
  Scenario: Two instances have isolated registries
    Given two fresh maskers named "A" and "B"
    When I register a "reverse_iso" rule on masker "A"
    Then masker "A" has rule "reverse_iso"
    And masker "B" does not have rule "reverse_iso"

  @core_api
  Scenario: Describe returns metadata for a registered rule
    Given a fresh masker
    And I register a custom rule "desc_feature" that reverses its input
    When I describe rule "desc_feature"
    Then the describe result name is "desc_feature"
    And the describe result is present

  @core_api
  Scenario: Any built-in rule can be discovered at runtime with its category, jurisdiction and example
    # Consumer contract: every built-in rule is discoverable at runtime
    # with a populated category, jurisdiction, and a description that
    # carries an input-to-output example.
    Given a fresh masker
    When I describe rule "email_address"
    Then the describe result is present
    And the describe result name is "email_address"
    And the describe result category is "identity"
    And the describe result jurisdiction is "global"
    And the describe result description contains "Example:"

  @core_api @smoke
  Scenario: Per-instance mask character override survives Apply
    # Smoke test for the Phase 2 core API — Phase 3 adds primitives that read
    # the configured mask character and replace this with a real assertion.
    Given a fresh masker with mask character "X"
    And I register a custom rule "char_instance_rule" that reverses its input
    When I mask "abc" with rule "char_instance_rule"
    Then the result is "cba"

  @core_api @smoke
  Scenario: Global mask character override survives Apply
    # Smoke test for the Phase 2 core API — Phase 3 adds primitives that read
    # the configured mask character and replace this with a real assertion.
    Given the global mask character is set to "X"
    And I register a custom rule "char_global_rule" that reverses its input on the global registry
    When I mask "abc" with rule "char_global_rule" on the global registry
    Then the result is "cba"

  @core_api
  Scenario: Rules are returned in sorted order
    Given a fresh masker
    And I register a custom rule "zzz_sort" that reverses its input
    And I register a custom rule "aaa_sort" that reverses its input
    And I register a custom rule "mmm_sort" that reverses its input
    When I list rules
    Then the listed rules contain, in order, "aaa_sort", "mmm_sort", "zzz_sort"
