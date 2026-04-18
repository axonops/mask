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
	"strings"

	"github.com/axonops/mask"
)

// ExampleApply shows the simplest possible usage — apply a rule to a value
// and print the result. A per-instance Masker is used here so the example
// does not mutate the package-level registry.
func ExampleApply() {
	m := mask.New()
	_ = m.Register("apply_example_rule", func(s string) string {
		if len(s) == 0 {
			return s
		}
		return string(s[0]) + "***"
	})

	fmt.Println(m.Apply("apply_example_rule", "secret"))
	// Output: s***
}

// ExampleRegister shows how to add a custom masking rule and use it. A
// per-instance Masker keeps the package-level registry clean.
func ExampleRegister() {
	m := mask.New()
	if err := m.Register("uppercase_example", strings.ToUpper); err != nil && !errors.Is(err, mask.ErrDuplicateRule) {
		panic(err)
	}

	fmt.Println(m.Apply("uppercase_example", "secret"))
	// Output: SECRET
}

// ExampleApply_unknownRule demonstrates the fail-closed contract: unknown
// rules never return the original value.
func ExampleApply_unknownRule() {
	fmt.Println(mask.Apply("no_such_rule", "alice@example.com"))
	// Output: [REDACTED]
}

// ExampleMasker_isolation shows that two [mask.Masker] instances have
// independent registries.
func ExampleMasker_isolation() {
	a := mask.New()
	b := mask.New()

	_ = a.Register("isolated_rule_a", strings.ToUpper)

	fmt.Println("a has rule:", a.HasRule("isolated_rule_a"))
	fmt.Println("b has rule:", b.HasRule("isolated_rule_a"))
	// Output:
	// a has rule: true
	// b has rule: false
}

// ExampleNew_withMaskChar shows how to override the mask character for an
// instance. Built-in rules read the configured character at apply time.
func ExampleNew_withMaskChar() {
	m := mask.New(mask.WithMaskChar('X'))
	// Without built-in rules in place the example focuses on demonstrating
	// option handling; later phases will show real masked output.
	fmt.Println(m.Apply("no_such_rule_yet", "value"))
	// Output: [REDACTED]
}

// ExampleDescribe shows runtime discovery of a rule's metadata.
func ExampleDescribe() {
	m := mask.New()
	_ = m.Register("discoverable_example", strings.ToUpper)

	info, ok := m.Describe("discoverable_example")
	fmt.Println("found:", ok)
	fmt.Println("name:", info.Name)
	// Output:
	// found: true
	// name: discoverable_example
}
