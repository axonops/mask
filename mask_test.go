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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/mask"
)

// packageLevelTestSeq supplies a monotonic suffix for tests that
// register rules against the package-level registry. The package
// registry has no Deregister method by design (registration is an
// init-time concern); `-count=N` reruns would therefore collide on
// a fixed name.
var packageLevelTestSeq atomic.Uint64

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// reverse is a small deterministic masking function used across tests.
func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func TestApply_UnknownRule_ReturnsFullRedact(t *testing.T) {
	t.Parallel()
	m := mask.New()
	assert.Equal(t, mask.FullRedactMarker, m.Apply("definitely_does_not_exist", "secret"))
}

func TestApply_WithRegisteredRule_Uses_It(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("reverse_instance", reverse))
	assert.Equal(t, "cba", m.Apply("reverse_instance", "abc"))
}

func TestRegister_DuplicateName_ReturnsErrDuplicateRule(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("dup_rule", reverse))

	err := m.Register("dup_rule", reverse)
	require.Error(t, err)
	assert.ErrorIs(t, err, mask.ErrDuplicateRule)
	assert.Contains(t, err.Error(), `"dup_rule"`)
}

func TestRegister_InvalidName_ReturnsErrInvalidRule(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ruleID  string
		wantMsg string
	}{
		{"empty", "", "grammar"},
		{"whitespace only", "   ", "grammar"},
		{"leading whitespace", " rule", "grammar"},
		{"uppercase letter", "Rule", "grammar"},
		{"contains space", "my rule", "grammar"},
		{"leading digit", "1rule", "grammar"},
		{"hyphen separator", "my-rule", "grammar"},
		{"camel case", "myRule", "grammar"},
		{"unicode letter", "règle", "grammar"},
		{"trailing dot", "rule.", "grammar"},
		{"trailing bang", "rule!", "grammar"},
		{"trailing emoji", "rule_🙂", "grammar"},
		{"colon separator", "rule:sub", "grammar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := mask.New()
			err := m.Register(tc.ruleID, reverse)
			require.Error(t, err)
			assert.ErrorIs(t, err, mask.ErrInvalidRule)
		})
	}
}

func TestRegister_NilRuleFunc_ReturnsErrInvalidRule(t *testing.T) {
	t.Parallel()
	m := mask.New()
	err := m.Register("valid_name", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, mask.ErrInvalidRule)
	assert.Contains(t, err.Error(), "nil RuleFunc")
}

func TestNew_WithMaskChar_OverridesDefault(t *testing.T) {
	t.Parallel()
	m := mask.New(mask.WithMaskChar('X'))
	assert.NotNil(t, m)
	// A built-in rule honours the configured mask character at apply time.
	assert.Equal(t, "aXXXX@example.com", m.Apply("email_address", "alice@example.com"))
	// Unknown rule still returns the fail-closed marker, independent of char.
	assert.Equal(t, mask.FullRedactMarker, m.Apply("no_such_rule", "x"))
}

func TestMasker_ZeroValue_Usable(t *testing.T) {
	t.Parallel()
	var m mask.Masker

	assert.Equal(t, mask.FullRedactMarker, m.Apply("anything", "value"))
	require.NoError(t, m.Register("z_rule", reverse))
	assert.Equal(t, "cba", m.Apply("z_rule", "abc"))
	assert.True(t, m.HasRule("z_rule"))
	assert.False(t, m.HasRule("not_there"))
}

func TestMasker_Isolation_TwoInstancesDontShareRegistry(t *testing.T) {
	t.Parallel()
	a := mask.New()
	b := mask.New()

	require.NoError(t, a.Register("only_on_a", reverse))
	assert.True(t, a.HasRule("only_on_a"))
	assert.False(t, b.HasRule("only_on_a"))

	// Registering the same name on b succeeds — registries are isolated.
	require.NoError(t, b.Register("only_on_a", reverse))
}

func TestRules_ReturnsSortedNames(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("charlie_rule", reverse))
	require.NoError(t, m.Register("alpha_rule", reverse))
	require.NoError(t, m.Register("bravo_rule", reverse))

	got := m.Rules()
	assert.GreaterOrEqual(t, len(got), 3)

	// Extract only the rules we registered (built-in rules will be appended in
	// later phases) and assert they appear in sorted order relative to one
	// another.
	var ours []string
	for _, name := range got {
		if strings.HasSuffix(name, "_rule") {
			ours = append(ours, name)
		}
	}
	assert.Equal(t, []string{"alpha_rule", "bravo_rule", "charlie_rule"}, ours)
}

func TestHasRule_TrueAndFalse(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("present", reverse))
	assert.True(t, m.HasRule("present"))
	assert.False(t, m.HasRule("absent"))
}

func TestDescribe_KnownAndUnknown(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("known", reverse))

	info, ok := m.Describe("known")
	assert.True(t, ok)
	assert.Equal(t, "known", info.Name)

	_, ok = m.Describe("unknown_rule")
	assert.False(t, ok)
}

// TestSetMaskChar_AppliesGlobally exercises the package-level SetMaskChar. It
// must not run in parallel with any test that touches global state and uses
// t.Cleanup to restore the default.
func TestSetMaskChar_AppliesGlobally(t *testing.T) {
	// Intentionally NOT calling t.Parallel — SetMaskChar mutates global state.
	t.Cleanup(func() {
		mask.SetMaskChar(mask.DefaultMaskChar)
	})

	mask.SetMaskChar('X')
	// No assertion on a concrete masked string yet (built-in rules land in a
	// later phase). This test ensures SetMaskChar does not panic, does not
	// corrupt the registry, and leaves Apply functional.
	assert.Equal(t, mask.FullRedactMarker, mask.Apply("definitely_not_a_real_rule", "value"))
}

func TestPackageLevel_RegisterApplyHasRuleDescribe(t *testing.T) {
	// Intentionally NOT calling t.Parallel — the package-level registry is
	// shared state; running serially keeps the naming stable across tests.
	// Unique suffix per invocation so -count=N reruns don't collide.
	name := "package_level_register_apply_rule_" +
		strconv.FormatUint(packageLevelTestSeq.Add(1), 10)
	require.NoError(t, mask.Register(name, reverse))

	assert.Equal(t, "cba", mask.Apply(name, "abc"))
	assert.True(t, mask.HasRule(name))

	info, ok := mask.Describe(name)
	assert.True(t, ok)
	assert.Equal(t, name, info.Name)

	names := mask.Rules()
	assert.Contains(t, names, name)
}

func TestConcurrent_Apply_IsSafe(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("concurrent_rule", reverse))

	const workers = 100
	const perWorker = 200

	// Start gate maximises contention: every goroutine blocks until the main
	// goroutine closes the channel, then all fire together.
	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-gate
			for j := 0; j < perWorker; j++ {
				_ = m.Apply("concurrent_rule", "abcdef")
				_ = m.HasRule("concurrent_rule")
				_ = m.Rules()
				_, _ = m.Describe("concurrent_rule")
			}
		}()
	}
	close(gate)
	wg.Wait()
}

// TestZeroValueMasker_ParallelFirstApply guards against a regression in
// the ensureInit race: initOnce stores an empty rule map BEFORE
// builtinsOnce registers the built-ins, so a parallel first-Apply
// reader that observed the pointer between the two Once calls used to
// see an empty registry and fall through to FullRedactMarker. Apply
// must call ensureInit on every entry so neither Once leaks a partly
// initialised state to readers.
func TestZeroValueMasker_ParallelFirstApply(t *testing.T) {
	t.Parallel()
	const (
		runs    = 20
		workers = 100
	)
	for run := 0; run < runs; run++ {
		var m mask.Masker // zero-value — neither Once has fired
		gate := make(chan struct{})
		results := make([]string, workers)
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				<-gate
				results[i] = m.Apply("email_address", "alice@example.com")
			}()
		}
		close(gate)
		wg.Wait()
		const want = "a****@example.com"
		for i, got := range results {
			require.Equalf(t, want, got, "run %d worker %d", run, i)
		}
	}
}

// TestZeroValueMasker_ParallelFirstHasRule is the symmetric regression
// for [Masker.loadRules] (and therefore [Masker.HasRule], [Masker.Rules],
// [Masker.Describe], [Masker.DescribeAll]). Same race as the Apply path:
// a parallel first reader between initOnce and builtinsOnce could see
// an empty registry. loadRules now calls ensureInit unconditionally.
func TestZeroValueMasker_ParallelFirstHasRule(t *testing.T) {
	t.Parallel()
	const (
		runs    = 20
		workers = 100
	)
	for run := 0; run < runs; run++ {
		var m mask.Masker // zero-value
		gate := make(chan struct{})
		results := make([]bool, workers)
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				<-gate
				results[i] = m.HasRule("email_address")
			}()
		}
		close(gate)
		wg.Wait()
		for i, ok := range results {
			require.Truef(t, ok, "run %d worker %d: HasRule returned false for a registered rule", run, i)
		}
	}
}

// TestConcurrent_MultipleInstances_AreIsolated exercises two Maskers in
// parallel to guard against accidentally shared state through the atomic
// pointer indirection.
func TestConcurrent_MultipleInstances_AreIsolated(t *testing.T) {
	t.Parallel()
	a := mask.New()
	b := mask.New()
	require.NoError(t, a.Register("shared_name", reverse))
	require.NoError(t, b.Register("shared_name", func(s string) string { return strings.ToUpper(s) }))

	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	aResult := make(chan string, 1)
	bResult := make(chan string, 1)
	go func() {
		defer wg.Done()
		<-gate
		var last string
		for i := 0; i < 500; i++ {
			last = a.Apply("shared_name", "abc")
		}
		aResult <- last
	}()
	go func() {
		defer wg.Done()
		<-gate
		var last string
		for i := 0; i < 500; i++ {
			last = b.Apply("shared_name", "abc")
		}
		bResult <- last
	}()
	close(gate)
	wg.Wait()

	assert.Equal(t, "cba", <-aResult)
	assert.Equal(t, "ABC", <-bResult)
}

// TestRules_ReturnsFreshSlice verifies the documented contract that the
// returned slice is freshly allocated and mutations do not leak into the
// registry.
func TestRules_ReturnsFreshSlice(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("fresh_a", reverse))
	require.NoError(t, m.Register("fresh_b", reverse))

	first := m.Rules()
	if len(first) > 0 {
		first[0] = "__mutated__"
	}
	second := m.Rules()
	assert.NotContains(t, second, "__mutated__")
}

// TestErrors_IncludeRuleName asserts the greppability requirement from issue
// #7: every error names the specific rule that failed.
func TestErrors_IncludeRuleName(t *testing.T) {
	t.Parallel()
	m := mask.New()
	require.NoError(t, m.Register("error_msg_test", reverse))

	dupErr := m.Register("error_msg_test", reverse)
	require.Error(t, dupErr)
	assert.True(t, errors.Is(dupErr, mask.ErrDuplicateRule))
	assert.Contains(t, dupErr.Error(), `"error_msg_test"`)

	invalidErr := m.Register("Bad Name", reverse)
	require.Error(t, invalidErr)
	assert.True(t, errors.Is(invalidErr, mask.ErrInvalidRule))
	assert.Contains(t, invalidErr.Error(), `"Bad Name"`)
}
