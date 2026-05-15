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
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// relocatedLogoPath is the canonical home of the README hero image
// after the Phase 7b move from the repo root. Tests below pin the
// migration so the README is never left dangling.
const relocatedLogoPath = ".github/images/logo-readme.png"

// TestReadme_LogoMigrated pins the gopher.png → .github/images
// relocation: the new path must exist, the old root-level file must
// NOT exist, and the README must reference the new path.
func TestReadme_LogoMigrated(t *testing.T) {
	t.Parallel()

	info, err := os.Stat(relocatedLogoPath)
	require.NoError(t, err, "relocated logo must exist at %s", relocatedLogoPath)
	assert.Greater(t, info.Size(), int64(0), "relocated logo must be non-empty")

	if _, err := os.Stat("gopher.png"); err == nil {
		t.Errorf("gopher.png is still present at the repo root; it must be removed after the move to %s", relocatedLogoPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat gopher.png: %v", err)
	}

	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	assert.Contains(t, string(readme), relocatedLogoPath,
		"README.md must reference the relocated logo at %s", relocatedLogoPath)
}

// requiredShopFrontSections is the AC5 list — every entry must appear
// as an H2 heading in README.md, in the specified relative order.
// Other headings may appear between them.
var requiredShopFrontSections = []string{
	"Status",
	"Overview",
	"Key Features",
	"Why mask?",
	"Quick Start",
	"Built-in Rules",
	"Utility Primitives",
	"Thread Safety",
	"Fail Closed",
	"Configuration",
	"For AI Assistants",
	"Contributing",
	"Security",
	"Licence",
}

var headingH2Pattern = regexp.MustCompile(`(?m)^##\s+(.*?)\s*$`)

// TestReadme_ShopFrontStructure parses README.md, extracts every H2
// heading, and asserts the 14 required sections appear in the
// expected relative order.
func TestReadme_ShopFrontStructure(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("README.md")
	require.NoError(t, err)

	matches := headingH2Pattern.FindAllStringSubmatch(string(body), -1)
	headings := make([]string, 0, len(matches))
	for _, m := range matches {
		headings = append(headings, stripEmojiAndPunct(m[1]))
	}
	require.NotEmpty(t, headings, "README.md contains no H2 headings")

	lastIdx := -1
	for _, want := range requiredShopFrontSections {
		foundAt := -1
		for i, got := range headings {
			if i <= lastIdx {
				continue
			}
			if strings.EqualFold(got, want) {
				foundAt = i
				break
			}
		}
		if foundAt < 0 {
			t.Errorf("required section %q is missing from README.md (or appears before %q). Found headings: %v",
				want, requiredShopFrontSections[max(0, indexOf(requiredShopFrontSections, want)-1)], headings)
			continue
		}
		lastIdx = foundAt
	}
}

// expectedBadgeURLFragments are the five URL fragments listed in
// Requirement 2.4 — verified by substring match on the raw markdown,
// no network required.
var expectedBadgeURLFragments = []string{
	"github.com/axonops/mask/actions/workflows/ci.yml",
	"pkg.go.dev/badge/github.com/axonops/mask",
	"goreportcard.com/badge/github.com/axonops/mask",
	"License-Apache",
	"status-stable",
}

// TestReadme_BadgeMarkdownReferencesExpectedURLs asserts the README
// header contains each required badge URL fragment. Syntactic only —
// no HTTP request.
func TestReadme_BadgeMarkdownReferencesExpectedURLs(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("README.md")
	require.NoError(t, err)
	s := string(body)
	for _, frag := range expectedBadgeURLFragments {
		assert.Contains(t, s, frag,
			"README.md badge row must reference %q", frag)
	}
}

// navAnchorPattern extracts in-page anchors from markdown links
// that look like [text](#anchor).
var navAnchorPattern = regexp.MustCompile(`\[([^\]]+)\]\(#([^)]+)\)`)

// TestReadme_NavAnchorsResolve parses the navigation strip (the line
// containing "Quick Start" links) and asserts every in-page anchor
// resolves to a heading in README.md, using GitHub's slugger algorithm.
func TestReadme_NavAnchorsResolve(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("README.md")
	require.NoError(t, err)

	lines := strings.Split(string(body), "\n")
	var navLine string
	for _, l := range lines {
		if strings.Contains(l, "Quick Start") && strings.Contains(l, "Primitives") && strings.Contains(l, "API Reference") {
			navLine = l
			break
		}
	}
	require.NotEmpty(t, navLine, "README.md must contain a navigation strip linking Quick Start, Primitives, and API Reference")

	// Collect every heading slug present in the document.
	headingSlugs := map[string]string{}
	for _, m := range headingPattern.FindAllStringSubmatch(string(body), -1) {
		slug := githubSlug(m[2])
		headingSlugs[slug] = m[2]
	}
	require.NotEmpty(t, headingSlugs)

	// Every #anchor in the nav line must match a heading slug.
	anchors := navAnchorPattern.FindAllStringSubmatch(navLine, -1)
	require.NotEmpty(t, anchors, "navigation strip contains no in-page anchors")
	for _, a := range anchors {
		label, anchor := a[1], a[2]
		if _, ok := headingSlugs[anchor]; !ok {
			t.Errorf("navigation link %q targets #%s which does not resolve to any heading in README.md. Available slugs: %v",
				label, anchor, sortedKeys(headingSlugs))
		}
	}
}

// headingPattern matches any markdown heading from H1 to H6,
// capturing level and text.
var headingPattern = regexp.MustCompile(`(?m)^(#{1,6})\s+(.*?)\s*$`)

// TestReadme_FeatureTableLinksResolve finds the Key Features table
// and asserts every row's Docs column is either a markdown link or
// the em-dash character — the latter only permitted for the
// "Zero dependencies" row per AC10.
func TestReadme_FeatureTableLinksResolve(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("README.md")
	require.NoError(t, err)
	section := extractSection(string(body), "## ✨ Key Features", "## ")
	require.NotEmpty(t, section, "Key Features section must be present in README.md")

	// Table rows start with `|` and contain three columns separated by `|`.
	// Skip the header row and the delimiter row.
	var dataRows [][]string
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := splitTableRow(line)
		if len(cells) < 3 {
			continue
		}
		// Skip header and delimiter rows — a delimiter row is all
		// dashes/colons; a header has "Feature" in the first cell.
		if strings.Contains(strings.ToLower(cells[0]), "feature") && strings.Contains(strings.ToLower(cells[1]), "description") {
			continue
		}
		if regexp.MustCompile(`^[-: ]+$`).MatchString(cells[0]) {
			continue
		}
		dataRows = append(dataRows, cells)
	}
	require.NotEmpty(t, dataRows, "Key Features table must have data rows")

	markdownLink := regexp.MustCompile(`\[[^\]]+\]\([^)]+\)`)
	for _, row := range dataRows {
		docsCell := strings.TrimSpace(row[2])
		feature := strings.TrimSpace(row[0])
		switch {
		case markdownLink.MatchString(docsCell):
			// Good — has a link.
		case docsCell == "—":
			assert.Contains(t, strings.ToLower(feature), "zero dependencies",
				"feature row %q uses em-dash in Docs; only the Zero dependencies row is permitted to do so", feature)
		default:
			t.Errorf("feature row %q has neither a markdown link nor an em-dash in the Docs cell (got %q)", feature, docsCell)
		}
	}
}

// githubSlug converts a heading string to the anchor slug GitHub
// generates from it. The algorithm matches github-slugger: lowercase;
// strip everything that is not a letter, digit, dash, underscore or
// whitespace; convert every whitespace rune to a dash.
func githubSlug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteRune('-')
		}
	}
	return b.String()
}

// stripEmojiAndPunct returns heading text without emoji, punctuation,
// or leading/trailing whitespace, so the required-section slice can
// use plain names while the README uses decorated headings.
func stripEmojiAndPunct(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '?':
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// extractSection returns the slice of the body between the heading
// whose line starts with `start` and the next heading starting with
// `boundary`. Returns "" if start is not found.
func extractSection(body, start, boundary string) string {
	idx := strings.Index(body, start)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(start):]
	next := strings.Index(rest, "\n"+boundary)
	if next < 0 {
		return rest
	}
	return rest[:next]
}

// splitTableRow splits `| a | b | c |` into ["a", "b", "c"], honouring
// escaped pipes (not used here, kept simple).
func splitTableRow(line string) []string {
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Small helper; full sort import avoided for a debug-only path.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if s == needle {
			return i
		}
	}
	return -1
}
