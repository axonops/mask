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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/mask"
)

// TestDocumentation_EveryRuleHasDescription asserts that every
// registered rule has a populated RuleInfo — name, category,
// jurisdiction, and description — and that the description carries
// a concrete `input → output` example (standing project rule).
func TestDocumentation_EveryRuleHasDescription(t *testing.T) {
	t.Parallel()
	m := mask.New()
	for _, name := range m.Rules() {
		t.Run(name, func(t *testing.T) {
			info, ok := m.Describe(name)
			require.True(t, ok, "rule %q is listed by Rules() but Describe returned !ok", name)
			assert.Equal(t, name, info.Name, "rule %q has a mismatched Name field", name)
			assert.NotEmpty(t, info.Category, "rule %q has an empty Category", name)
			assert.NotEmpty(t, info.Jurisdiction, "rule %q has an empty Jurisdiction", name)
			assert.NotEmpty(t, info.Description, "rule %q has an empty Description", name)
			assert.Contains(t, info.Description, "Example:",
				"rule %q description must carry an `Example:` line", name)
		})
	}
}

// readmeRuleRowPattern matches a Markdown table row whose first cell
// contains a backtick-wrapped lowercase-snake-case rule name. The
// rule-tables are the single source of truth for the catalogue in
// README.md; the drift guard below parses every such row and
// compares the set against the registry.
var readmeRuleRowPattern = regexp.MustCompile("(?m)^\\| `([a-z][a-z0-9_]*)` \\|")

// TestDocumentation_ReadmeRulesInSyncWithCatalog parses README.md's
// rule tables and asserts that every registered rule appears in
// exactly one table, and every table entry corresponds to a
// registered rule. A divergence in either direction fails the
// build: the README rule tables and the catalogue are the same
// source of truth.
func TestDocumentation_ReadmeRulesInSyncWithCatalog(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("README.md")
	require.NoError(t, err, "README.md must be readable from the repo root")

	readmeCounts := map[string]int{}
	for _, match := range readmeRuleRowPattern.FindAllStringSubmatch(string(data), -1) {
		readmeCounts[match[1]]++
	}

	m := mask.New()
	registered := map[string]struct{}{}
	for _, name := range m.Rules() {
		registered[name] = struct{}{}
	}

	for name := range registered {
		count := readmeCounts[name]
		assert.Equalf(t, 1, count,
			"rule %q should appear in exactly one README rule-table row (found %d)",
			name, count)
	}
	for name := range readmeCounts {
		_, ok := registered[name]
		assert.Truef(t, ok,
			"README references rule %q but no such rule is registered",
			name)
	}
}
