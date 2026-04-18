@documentation
Feature: AI-assistant documentation
  A developer who points an AI assistant at `github.com/axonops/mask`
  should be able to find the package's purpose, core API, and
  integration flow in a single concise file. These scenarios pin
  the `llms.txt` / `llms-full.txt` contract.

  Scenario: llms.txt advertises the package purpose and core API
    Given a developer points an AI assistant at the repository
    When the assistant reads "llms.txt"
    Then the file starts with a heading matching "# mask"
    And the file contains the phrase "fail-closed"
    And the file contains the phrase "Thread-safety contract"
    And the file documents the API entry point "mask.Apply"
    And the file documents the API entry point "mask.Register"
    And the file documents the API entry point "mask.New"

  Scenario: llms-full.txt concatenates every canonical source
    Given a developer points an AI assistant at the repository
    When the assistant reads "llms-full.txt"
    Then the file contains the section header "# llms.txt"
    And the file contains the section header "# README.md"
    And the file contains the section header "# CONTRIBUTING.md"
    And the file contains the section header "# SECURITY.md"
    And the file contains the section header "# docs/rules.md"
    And the file contains the section header "# docs/extending.md"
    And the file contains the section header "# Full godoc reference (go doc -all)"
