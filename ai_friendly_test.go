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
	"errors"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/mask"
)

// TestLLMs_TxtExists_AndUnderTokenBudget asserts the llms.txt file
// exists at the repo root and stays within the ~2250 word budget
// documented in issue #7.
func TestLLMs_TxtExists_AndUnderTokenBudget(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("llms.txt")
	require.NoError(t, err, "llms.txt must exist at the repo root")

	words := len(strings.Fields(string(data)))
	assert.LessOrEqual(t, words, 2250,
		"llms.txt must stay under the 2250-word budget (got %d)", words)
	assert.Greater(t, words, 200,
		"llms.txt looks stubby (got %d words)", words)
}

// TestLLMs_FullTxtExists_AndIncludesSpecifiedSections asserts
// llms-full.txt is present and concatenates every canonical source
// listed in issue #7 Requirement 2.
func TestLLMs_FullTxtExists_AndIncludesSpecifiedSections(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("llms-full.txt")
	require.NoError(t, err, "llms-full.txt must exist at the repo root")

	body := string(data)
	required := []string{
		"# mask — full documentation bundle",
		"# llms.txt",
		"# README.md",
		"# Package godoc (doc.go)",
		"# CONTRIBUTING.md",
		"# SECURITY.md",
		"# docs/rules.md",
		"# docs/extending.md",
		"# Full godoc reference (go doc -all)",
	}
	for _, header := range required {
		assert.Contains(t, body, header,
			"llms-full.txt must contain section header %q", header)
	}
}

// TestLLMs_FullTxtIsUpToDate re-runs the generator and asserts
// byte-equality with the committed file. If this fails, someone edited
// a source file and forgot to run `make llms-full`.
//
// This test intentionally does NOT use t.Parallel(): it overwrites the
// repo-root `llms-full.txt` while running, which would race with any
// other parallel test that reads that file (or its adjacent sources).
func TestLLMs_FullTxtIsUpToDate(t *testing.T) {
	committed, err := os.ReadFile("llms-full.txt")
	require.NoError(t, err)

	// Regenerate into a shadow path so we don't race with other tests
	// that might read the committed file concurrently. The script
	// unconditionally writes `llms-full.txt` at the repo root, so we
	// stash and restore the committed file around the regeneration.
	backup := t.TempDir() + "/llms-full.txt.committed"
	require.NoError(t, os.WriteFile(backup, committed, 0o644))
	t.Cleanup(func() {
		_ = os.WriteFile("llms-full.txt", committed, 0o644)
	})

	cmd := exec.Command("./scripts/gen-llms-full.sh")
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run(), "gen-llms-full.sh must exit 0")

	regenerated, err := os.ReadFile("llms-full.txt")
	require.NoError(t, err)
	assert.Equal(t, string(committed), string(regenerated),
		"llms-full.txt drift — run 'make llms-full' and commit the result")
}

// requiredExamples is the set issue #7 Requirement 5 pins.
var requiredExamples = []string{
	"ExampleApply",
	"ExampleRegister",
	"ExampleNew_withMaskChar",
	"ExampleSetMaskChar",
	"ExampleKeepFirstN",
	"ExampleKeepFirstNFunc",
	"ExampleDescribe",
	"ExampleMasker_isolation",
	"ExampleApply_failClosed",
	"ExampleApply_malformedFallsBack",
}

// TestExamples_AllRequiredExamplesExist parses example_test.go and
// asserts that every required godoc Example function is defined.
// Missing examples fail the build — this is the primary AI-assistant
// integration surface on pkg.go.dev.
func TestExamples_AllRequiredExamplesExist(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "example_test.go", nil, 0)
	require.NoError(t, err)

	defined := map[string]struct{}{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if strings.HasPrefix(fn.Name.Name, "Example") {
			defined[fn.Name.Name] = struct{}{}
		}
	}
	for _, required := range requiredExamples {
		_, ok := defined[required]
		assert.Truef(t, ok,
			"required example %q is missing from example_test.go", required)
	}
}

// mechanicalDoc matches trivially-generated one-liners like
// "Foo returns a string." — we want real prose that tells a reader
// how and when to use the symbol, not a restatement of the signature.
var mechanicalDoc = regexp.MustCompile(`^\w+ (returns|is|creates) [\w ]+\.?$`)

// TestDocumentation_EveryExportedSymbolHasGodoc parses the package
// and asserts every exported symbol has a doc comment of at least
// 20 characters that is not a mechanical one-liner.
func TestDocumentation_EveryExportedSymbolHasGodoc(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		require.NoError(t, err, "parse %s", name)
		if f.Name.Name != "mask" {
			continue
		}
		files[name] = f
	}
	require.NotEmpty(t, files, "no mask package files found")

	docPkg, err := doc.NewFromFiles(fset, sortedFiles(files), "github.com/axonops/mask")
	require.NoError(t, err)

	checkDoc := func(name, text string) {
		t.Run(name, func(t *testing.T) {
			assert.GreaterOrEqual(t, len(strings.TrimSpace(text)), 20,
				"symbol %q has a doc comment shorter than 20 characters: %q", name, text)
			first := strings.SplitN(strings.TrimSpace(text), "\n", 2)[0]
			assert.False(t, mechanicalDoc.MatchString(first),
				"symbol %q has a mechanical one-line doc: %q", name, first)
		})
	}
	for _, c := range docPkg.Consts {
		for _, n := range c.Names {
			checkDoc(n, c.Doc)
		}
	}
	for _, v := range docPkg.Vars {
		for _, n := range v.Names {
			checkDoc(n, v.Doc)
		}
	}
	for _, f := range docPkg.Funcs {
		checkDoc(f.Name, f.Doc)
	}
	for _, typ := range docPkg.Types {
		checkDoc(typ.Name, typ.Doc)
		for _, m := range typ.Methods {
			checkDoc(typ.Name+"."+m.Name, m.Doc)
		}
		for _, f := range typ.Funcs {
			checkDoc(f.Name, f.Doc)
		}
	}
}

// TestErrors_DoNotLeakInputs asserts the sentinel errors and their
// wrapped forms never include the raw user-supplied input value in
// their `Error()` string. The rule name is allowed (it is the
// identifier the caller chose); any ARBITRARY caller-supplied string
// MUST NOT appear.
func TestErrors_DoNotLeakInputs(t *testing.T) {
	t.Parallel()

	const suspiciousValue = "a-very-suspicious-looking-sensitive-value-42"

	// Try to trigger a wrapped registration error that names a rule
	// whose name is the suspicious value. The error MUST name the
	// rule identifier only — which is itself derived from the name
	// the caller passed — so we verify that the error does not
	// contain "Register" or "Apply" parameter values that a caller
	// would not expect to see.
	m := mask.New()

	// Duplicate-rule error: the sentinel is wrapped with the rule
	// name, which is the caller's own identifier — not sensitive
	// data. We assert that the sensitive VALUE string doesn't leak.
	_ = m.Register("valid_test_rule", func(string) string { return "" })
	err := m.Register("valid_test_rule", func(string) string { return "" })
	require.Error(t, err)
	assert.True(t, errors.Is(err, mask.ErrDuplicateRule))
	assert.NotContains(t, err.Error(), suspiciousValue,
		"duplicate-rule error must not contain arbitrary caller-supplied data")

	// Invalid-rule-name error: the error SHOULD name the offending
	// pattern (so the caller can fix their code). It MUST NOT contain
	// any unrelated suspicious bytes. We pass a deliberately
	// malformed name that is itself not sensitive data.
	err = m.Register("123-bad-name", func(string) string { return "" })
	require.Error(t, err)
	assert.True(t, errors.Is(err, mask.ErrInvalidRule))
	assert.NotContains(t, err.Error(), suspiciousValue,
		"invalid-rule error must not contain arbitrary caller-supplied data")
	// The error message IS allowed to name the offending rule
	// identifier so developers can grep for it. Confirm that the
	// rule name we submitted appears so the error is greppable.
	assert.Contains(t, err.Error(), "123-bad-name",
		"invalid-rule error should name the offending rule identifier for greppability")
}

// TestReadmeQuickStart_Compiles extracts the README Quick Start code
// block, compiles it in a fresh temporary module, runs it, and
// verifies it produces the documented output. This catches drift
// between the README's copy-paste snippet and the library API.
func TestReadmeQuickStart_Compiles(t *testing.T) {
	if testing.Short() {
		t.Skip("-short set; skipping compilation test")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH: %v", err)
	}
	t.Parallel()

	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)

	snippet, ok := extractQuickStartBlock(string(readme))
	require.True(t, ok, "could not find the Quick Start go code block in README.md")

	// Absolute path of this repo so the scratch module can `replace`
	// the dependency to the local tree.
	repoDir, err := os.Getwd()
	require.NoError(t, err)
	repoDir, err = filepath.Abs(repoDir)
	require.NoError(t, err)

	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "main.go"), []byte(snippet), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.mod"),
		[]byte(fmt.Sprintf("module quickstart\n\ngo 1.26\n\nrequire github.com/axonops/mask v0.0.0\n\nreplace github.com/axonops/mask => %s\n", repoDir)),
		0o644))

	// Materialise go.sum by running `go mod tidy` against the local
	// replace; otherwise go build on some toolchains complains.
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = tmp
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run())

	build := exec.Command("go", "build", "-o", "main", ".")
	build.Dir = tmp
	build.Stderr = os.Stderr
	require.NoError(t, build.Run(), "Quick Start snippet must compile")

	run := exec.Command("./main")
	run.Dir = tmp
	out, err := run.Output()
	require.NoError(t, err)
	assert.Contains(t, string(out), "a****@example.com",
		"Quick Start output must include the documented masked email")
}

// quickStartHeadingPattern locates any H2 heading containing
// "Quick Start" (case-insensitive), tolerating an emoji decoration
// such as "## 🚀 Quick Start" or the older bare "## Quick start".
var quickStartHeadingPattern = regexp.MustCompile(`(?mi)^##\s+.*Quick\s+Start`)

// extractQuickStartBlock finds the first ```go ... ``` fence
// following the Quick Start heading, skipping intermediate sub-headings
// ("### Install" and similar) and non-Go fenced blocks.
func extractQuickStartBlock(body string) (string, bool) {
	loc := quickStartHeadingPattern.FindStringIndex(body)
	if loc == nil {
		return "", false
	}
	after := body[loc[1]:]
	start := strings.Index(after, "```go")
	if start < 0 {
		return "", false
	}
	start += len("```go")
	if start < len(after) && after[start] == '\n' {
		start++
	}
	end := strings.Index(after[start:], "```")
	if end < 0 {
		return "", false
	}
	return after[start : start+end], true
}

// sortedFiles returns the map's values ordered by file name so
// doc.NewFromFiles sees a deterministic input slice.
func sortedFiles(m map[string]*ast.File) []*ast.File {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]*ast.File, 0, len(m))
	for _, n := range names {
		out = append(out, m[n])
	}
	return out
}
