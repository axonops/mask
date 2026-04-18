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

//go:build bdd

package bdd_test

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"

	"github.com/axonops/mask/tests/bdd/steps"
)

// TestGodog is the single entry point for the godog BDD suite. It runs every
// .feature file under tests/bdd/features.
func TestGodog(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: steps.Register,
		Options: &godog.Options{
			Format:    "pretty",
			Paths:     []string{"features"},
			Output:    colors.Colored(os.Stdout),
			Randomize: -1,
			TestingT:  t,
		},
	}
	if got := suite.Run(); got != 0 {
		t.Fatalf("godog suite exited with %d", got)
	}
}
