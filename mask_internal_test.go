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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInit_BuiltinRegistrarsDoNotDeadlock guards the split between initOnce
// and builtinsOnce. If a future change merges them, any registrar that calls
// into a public Masker method (directly or transitively) will re-enter the
// same sync.Once and deadlock — a bug that would silently affect every
// consumer on first use. The test installs a stand-in registrar that mimics
// the Phase 3 pattern and asserts that construction completes promptly.
func TestInit_BuiltinRegistrarsDoNotDeadlock(t *testing.T) {
	// Intentionally NOT t.Parallel — mutates the package-level
	// builtinRegistrars slice, which is read unsynchronised by any Masker's
	// ensureInit. Parallel tests that call New() would race against it.
	saved := builtinRegistrars
	t.Cleanup(func() { builtinRegistrars = saved })

	called := false
	builtinRegistrars = append([]func(*Masker){}, saved...)
	builtinRegistrars = append(builtinRegistrars, func(m *Masker) {
		called = true
		m.mustRegisterBuiltin("synthetic_builtin_test_rule", func(s string) string {
			return "masked:" + s
		}, RuleInfo{
			Name:         "synthetic_builtin_test_rule",
			Category:     "utility",
			Jurisdiction: "global",
			Description:  "synthetic test rule exercising the registrar path",
		})
	})

	done := make(chan *Masker, 1)
	go func() {
		done <- New()
	}()

	select {
	case m := <-done:
		require.True(t, called, "registrar never ran")
		assert.Equal(t, "masked:hello", m.Apply("synthetic_builtin_test_rule", "hello"))

		info, ok := m.Describe("synthetic_builtin_test_rule")
		require.True(t, ok)
		assert.Equal(t, "utility", info.Category)
		assert.Equal(t, "global", info.Jurisdiction)
	case <-time.After(2 * time.Second):
		t.Fatal("ensureInit deadlocked — builtin registrar could not complete within 2s")
	}
}

// TestInit_ZeroValueMaskerWithBuiltinRegistrar_DoesNotDeadlock covers the
// zero-value Masker path, which reaches ensureInit from Apply rather than
// New. This is the failure mode most likely to be hit in real code.
func TestInit_ZeroValueMaskerWithBuiltinRegistrar_DoesNotDeadlock(t *testing.T) {
	// Intentionally NOT t.Parallel — mutates the package-level
	// builtinRegistrars slice.
	saved := builtinRegistrars
	t.Cleanup(func() { builtinRegistrars = saved })

	builtinRegistrars = append([]func(*Masker){}, saved...)
	builtinRegistrars = append(builtinRegistrars, func(m *Masker) {
		m.mustRegisterBuiltin("zero_value_builtin_rule", func(s string) string {
			return "zv:" + s
		}, RuleInfo{Name: "zero_value_builtin_rule"})
	})

	done := make(chan string, 1)
	go func() {
		var m Masker
		done <- m.Apply("zero_value_builtin_rule", "x")
	}()

	select {
	case got := <-done:
		assert.Equal(t, "zv:x", got)
	case <-time.After(2 * time.Second):
		t.Fatal("zero-value Masker deadlocked during lazy init")
	}
}
