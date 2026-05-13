// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mask_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The governance bundle — CLA, Code of Conduct, NOTICE, CLA workflow,
// contributors generator, issue templates, and the updates to
// CONTRIBUTING.md and README.md — is pinned here so an accidental
// delete breaks the build rather than surfacing silently on the first
// external contribution.

func TestGovernance_CLADocumentExists(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("CLA.md")
	require.NoError(t, err, "CLA.md must exist at the repo root")

	s := string(body)
	// Spot-check the legally load-bearing sections so a future edit that
	// accidentally cuts them fails CI.
	for _, section := range []string{
		"Grant of copyright licence",
		"Grant of patent licence",
		"Representations",
		"AxonOps",
	} {
		assert.Contains(t, s, section, "CLA.md must contain %q", section)
	}
}

func TestGovernance_CodeOfConductExists(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("CODE_OF_CONDUCT.md")
	require.NoError(t, err, "CODE_OF_CONDUCT.md must exist at the repo root")

	s := string(body)
	assert.Contains(t, s, "Contributor Covenant",
		"CODE_OF_CONDUCT.md must be derived from the Contributor Covenant")
	assert.Contains(t, s, "oss@axonops.com",
		"CODE_OF_CONDUCT.md must carry the AxonOps enforcement contact")
	assert.NotContains(t, s, "[INSERT CONTACT METHOD]",
		"CODE_OF_CONDUCT.md must have the contact placeholder filled in")
}

func TestGovernance_NoticeFileExists(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("NOTICE")
	require.NoError(t, err, "NOTICE must exist at the repo root (Apache 2.0 § 4(d))")

	s := string(body)
	assert.Contains(t, s, "AxonOps Limited")
	assert.Contains(t, s, "Apache License")
}

func TestGovernance_CLAWorkflowExists(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(".github/workflows/cla.yml")
	require.NoError(t, err, ".github/workflows/cla.yml must exist")

	var v any
	require.NoError(t, yaml.Unmarshal(body, &v), "cla.yml must be valid YAML")

	s := string(body)
	// The action must be pinned to a specific version, not @main or @master.
	assert.Regexp(t, `contributor-assistant/github-action@v\d+\.\d+\.\d+`, s,
		"CLA action must be pinned to a semver tag")
	// The PAT secret must be wired — using GITHUB_TOKEN alone cannot push
	// through the `main` branch protection.
	assert.Contains(t, s, "CLA_ASSISTANT_PAT",
		"CLA workflow must reference the CLA_ASSISTANT_PAT secret for the bot push")
	// Allowlist must cover the automation bots that cannot sign via PR
	// comment. Humans (including the project owner) are deliberately NOT
	// allowlisted — they go through the signing flow once and are then
	// recorded in signatures/version1/cla.json.
	assert.Contains(t, s, "dependabot[bot]")
	assert.Contains(t, s, "renovate[bot]")
	assert.Contains(t, s, "github-actions[bot]")
}

func TestGovernance_ContributorsWorkflowExists(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(".github/workflows/contributors.yml")
	require.NoError(t, err, ".github/workflows/contributors.yml must exist")

	var v any
	require.NoError(t, yaml.Unmarshal(body, &v))

	s := string(body)
	// The generator runs only when the signatures file is touched, so the
	// workflow must declare that path on its push trigger.
	assert.Contains(t, s, "signatures/version1/cla.json",
		"contributors.yml must trigger on the signatures file")
	// It pushes back to main with the PAT so it can bypass branch
	// protection; using GITHUB_TOKEN would fail.
	assert.Contains(t, s, "CLA_ASSISTANT_PAT",
		"contributors.yml must use the CLA_ASSISTANT_PAT secret for its push")
}

func TestGovernance_CIIgnoresSignaturesAndContributors(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(".github/workflows/ci.yml")
	require.NoError(t, err)

	s := string(body)
	// The CLA Assistant bot pushes signatures/... directly to main and
	// the contributors regenerator pushes CONTRIBUTORS.md. Neither can
	// affect library behaviour; main-branch CI MUST skip them.
	assert.Regexp(t, `paths-ignore:\s*\n\s*-\s*"signatures/\*\*"`, s,
		"ci.yml main-branch trigger must paths-ignore signatures/**")
	assert.Regexp(t, `paths-ignore:\s*(?s:.*)-\s*"CONTRIBUTORS\.md"`, s,
		"ci.yml main-branch trigger must paths-ignore CONTRIBUTORS.md")
}

func TestGovernance_ContributorsGeneratorRoundtrips(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not on PATH: %v", err)
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skipf("jq not on PATH: %v", err)
	}
	t.Parallel()

	// A synthetic signatures file with two signatures — ordered out of
	// date sequence so we verify the generator sorts them.
	dir := t.TempDir()
	sigs := filepath.Join(dir, "cla.json")
	out := filepath.Join(dir, "CONTRIBUTORS.md")

	sample := `{
      "signedContributors": [
        {"name": "Bobby Newmark", "login": "bobby", "id": 2, "pull_request_no": 12, "created_at": "2026-05-10T10:00:00Z"},
        {"name": "Anna Nakano", "login": "anna", "id": 1, "pull_request_no": 7,  "created_at": "2026-04-20T08:00:00Z"}
      ]
    }`
	require.NoError(t, os.WriteFile(sigs, []byte(sample), 0o644))

	cmd := exec.Command("./scripts/generate-contributors.sh", sigs, out)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run(), "generator must exit 0 on a valid signatures file")

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	rendered := string(data)

	// Both signatories are in the output.
	assert.Contains(t, rendered, "@anna")
	assert.Contains(t, rendered, "@bobby")
	// Anna signed earlier — she must appear first in the sorted table.
	assert.Less(t, strings.Index(rendered, "anna"), strings.Index(rendered, "bobby"),
		"contributors table must sort by signed_at ascending")
	// The auto-generation banner is present so nobody edits by hand.
	assert.Contains(t, rendered, "auto-generated")
}

func TestGovernance_ContributingMentionsCLAAndSigning(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("CONTRIBUTING.md")
	require.NoError(t, err)

	s := string(body)
	assert.Contains(t, s, "Contributor License Agreement",
		"CONTRIBUTING.md must introduce the CLA")
	assert.Contains(t, s, "Signing your commits",
		"CONTRIBUTING.md must carry the signed-commits setup guide")
	assert.Contains(t, s, "CODE_OF_CONDUCT.md",
		"CONTRIBUTING.md must link the Code of Conduct")
}

func TestGovernance_ReadmeMentionsCLAAndCodeOfConduct(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("README.md")
	require.NoError(t, err)

	s := string(body)
	assert.Contains(t, s, "CLA.md",
		"README must link the CLA document")
	assert.Contains(t, s, "CODE_OF_CONDUCT.md",
		"README must link the Code of Conduct")
	assert.Contains(t, s, "CONTRIBUTORS.md",
		"README must link the generated contributors list")
}

func TestGovernance_PRTemplateMentionsCLA(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(".github/PULL_REQUEST_TEMPLATE.md")
	require.NoError(t, err)

	s := string(body)
	assert.Contains(t, s, "Contributor License Agreement",
		"PR template must reference the CLA")
	assert.Contains(t, s, "signed",
		"PR template must remind contributors about signed commits")
}

func TestGovernance_IssueTemplatesExist(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		".github/ISSUE_TEMPLATE/bug_report.yml",
		".github/ISSUE_TEMPLATE/feature_request.yml",
		".github/ISSUE_TEMPLATE/rule_request.yml",
		".github/ISSUE_TEMPLATE/config.yml",
	} {
		_, err := os.ReadFile(path)
		assert.NoError(t, err, "%s must exist", path)
	}
}

func TestGovernance_ScorecardWorkflowExists(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(".github/workflows/scorecard.yml")
	require.NoError(t, err, ".github/workflows/scorecard.yml must exist")

	var v any
	require.NoError(t, yaml.Unmarshal(body, &v), "scorecard.yml must be valid YAML")

	s := string(body)

	// Least-privilege permission scopes required by Scorecard. SARIF
	// upload needs security-events:write; publish_results requires
	// the OIDC token (id-token:write); the Token-Permissions and
	// Pinned-Dependencies checks need actions:read; the analysis
	// itself needs contents:read.
	for _, scope := range []string{
		"security-events: write",
		"id-token: write",
		"actions: read",
	} {
		assert.Contains(t, s, scope,
			"scorecard.yml must declare permission scope %q", scope)
	}

	// `contents: read` must appear at BOTH the workflow level (default
	// least-privilege baseline) AND the job level (GitHub replaces,
	// not merges, when a job overrides permissions). A bare Contains
	// check would pass if only one of the two were present.
	assert.GreaterOrEqualf(t,
		strings.Count(s, "contents: read"), 2,
		"scorecard.yml must declare `contents: read` at workflow AND job level")

	// The Scorecard action MUST be pinned by 40-hex commit SHA, not a
	// mutable tag — Scorecard's own Pinned-Dependencies check
	// downgrades the score otherwise. The equivalent semver tag
	// travels in a trailing comment for human readability.
	assert.Regexp(t, `ossf/scorecard-action@[0-9a-f]{40}`, s,
		"ossf/scorecard-action must be pinned by full 40-hex commit SHA")

	// publish_results: true is what posts the score to scorecard.dev
	// so the README badge stays live. Disabling it silently breaks
	// the public viewer.
	assert.Contains(t, s, "publish_results: true",
		"scorecard.yml must publish results to scorecard.dev")

	// Mirror ci.yml: bot pushes that only touch signatures or the
	// generated contributors list must not retrigger the scan.
	// Regex form tolerates quoted, single-quoted, or bare-scalar YAML.
	assert.Regexp(t, `(?s)paths-ignore:.*signatures/\*\*`, s,
		"scorecard.yml must paths-ignore signatures/**")
	assert.Regexp(t, `(?s)paths-ignore:.*CONTRIBUTORS\.md`, s,
		"scorecard.yml must paths-ignore CONTRIBUTORS.md")
}
