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

package steps

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

// RegisterDocumentationSteps wires the step definitions used by the
// @documentation feature file. Called from the suite's step registrar.
func RegisterDocumentationSteps(sc *godog.ScenarioContext, w *World) {
	sc.Step(`^a developer points an AI assistant at the repository$`, w.pointAssistantAtRepository)
	sc.Step(`^the assistant reads "([^"]+)"$`, w.assistantReadsFile)
	sc.Step(`^the file starts with a heading matching "([^"]+)"$`, w.fileStartsWithHeading)
	sc.Step(`^the file contains the phrase "([^"]+)"$`, w.fileContainsPhrase)
	sc.Step(`^the file documents the API entry point "([^"]+)"$`, w.fileContainsPhrase)
	sc.Step(`^the file contains the section header "([^"]+)"$`, w.fileContainsPhrase)
}

// pointAssistantAtRepository is a no-op setup step that reads as
// scenario context in Gherkin — nothing to initialise on the World.
func (w *World) pointAssistantAtRepository() error { return nil }

// assistantReadsFile loads the file at a path relative to the repo
// root into w.lastResult so subsequent assertions can inspect it.
// The BDD runner executes from `tests/bdd`, so we walk up until the
// named file is found. That handles both `go test -tags bdd
// ./tests/bdd/...` and `go test -tags bdd ./...` invocations.
func (w *World) assistantReadsFile(name string) error {
	path, err := findRepoFile(name)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	w.lastResult = string(data)
	return nil
}

// fileStartsWithHeading asserts the first non-blank line of the
// loaded file begins with the given heading text.
func (w *World) fileStartsWithHeading(heading string) error {
	for _, line := range strings.Split(w.lastResult, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, heading) {
			return nil
		}
		return fmt.Errorf("expected first non-blank line to start with %q, got %q", heading, line)
	}
	return fmt.Errorf("file is empty")
}

// fileContainsPhrase is shared by the "phrase", "API entry point",
// and "section header" steps — they all reduce to substring match.
func (w *World) fileContainsPhrase(phrase string) error {
	if !strings.Contains(w.lastResult, phrase) {
		return fmt.Errorf("expected file to contain %q", phrase)
	}
	return nil
}

// findRepoFile walks upward from the current working directory until
// it finds name at a directory level, returning the absolute path.
// Used so tests can be invoked from any subdirectory.
func findRepoFile(name string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate %q from any parent of cwd", name)
		}
		dir = parent
	}
}
