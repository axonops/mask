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

package mask

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeterministicHash_NoMD5orSHA1Imports asserts that no .go file in this
// package imports crypto/md5 or crypto/sha1. This is defence in depth: a
// future change that downgrades the hash algorithm — accidentally or
// otherwise — fails at CI rather than silently shipping a weak pseudonym.
//
// A substring grep is deliberately rejected: "sha3-256" contains the
// substring "sha1" via unfortunate coincidence only when you misread, but
// other false positives ("sha1something") are the real risk. Parsing the
// AST and inspecting the import path strings is unambiguous.
func TestDeterministicHash_NoMD5orSHA1Imports(t *testing.T) {
	t.Parallel()

	// Walk the current package directory only. The Go test binary's working
	// directory is the package directory.
	wd, err := os.Getwd()
	require.NoError(t, err)

	fset := token.NewFileSet()
	forbidden := map[string]struct{}{
		`"crypto/md5"`:  {},
		`"crypto/sha1"`: {},
	}

	var offenders []string
	err = filepath.WalkDir(wd, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			// Skip sub-test suites so we only scan package-level files.
			if path != wd && filepath.Base(path) == "tests" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			// The rule applies to production sources; tests may legitimately
			// need to reference forbidden names in string literals (this
			// file does, to declare the forbidden set).
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if _, bad := forbidden[imp.Path.Value]; bad {
				offenders = append(offenders, path+" imports "+imp.Path.Value)
			}
		}
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, offenders, "forbidden cryptographic imports found: %v", offenders)
}
