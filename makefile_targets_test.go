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
)

// TestMakefileHasBenchRegressionTarget is a defence against accidentally
// deleting the bench-regression target. The CI benchstat-regression-guard
// job invokes `make bench-regression`; if the target disappears the
// guard silently exits zero.
func TestMakefileHasBenchRegressionTarget(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("Makefile")
	require.NoError(t, err, "Makefile must be readable from the repo root")

	// Anchored regex: a line that begins with 'bench-regression:' at
	// column 0 declares the target. The `.PHONY` directive on the
	// preceding line is also required by project convention.
	body := string(data)
	assert.Regexp(t, regexp.MustCompile(`(?m)^\.PHONY:\s+bench-regression\b`), body,
		"Makefile must declare 'bench-regression' as .PHONY")
	assert.Regexp(t, regexp.MustCompile(`(?m)^bench-regression:`), body,
		"Makefile must define a 'bench-regression' target")
}
