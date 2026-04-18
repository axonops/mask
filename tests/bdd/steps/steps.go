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

// Package steps contains godog step definitions for the mask library's BDD
// suite. Scenarios are written in consumer language; the step functions
// translate Gherkin into calls against the public API.
package steps

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/cucumber/godog"

	"github.com/axonops/mask"
)

// globalRuleSeq supplies a monotonic suffix for rules registered on
// the package-level registry inside scenarios. The registry has no
// Deregister method; without a unique suffix, `go test -count=N`
// reruns would collide on a fixed rule name.
var globalRuleSeq atomic.Uint64

// World holds per-scenario state shared across step implementations.
type World struct {
	maskers         map[string]*mask.Masker
	globalRuleNames map[string]string // Gherkin name → actual registered name
	lastResult      string
	lastResults     []string
	secondResult    string
	replaceResult   string
	replaceErr      error
	lastError       error
	lastRules       []string
	lastDescribe    mask.RuleInfo
	lastDescribeOK  bool
}

// newWorld returns a fresh scenario state.
func newWorld() *World {
	return &World{
		maskers:         map[string]*mask.Masker{},
		globalRuleNames: map[string]string{},
	}
}

// defaultKey is the key used when a scenario speaks of "the masker" without
// a name.
const defaultKey = "_default"

// Register wires all core-API step definitions into the supplied suite.
func Register(sc *godog.ScenarioContext) {
	w := newWorld()

	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		// World is constructed per-scenario by Register; do not re-assign
		// here. This hook exists only to reset global state that scenarios
		// may mutate. If a future change adds a package-level or BeforeAll
		// binding of the World, isolation will silently break — keep all
		// World construction inside Register.
		mask.SetMaskChar(mask.DefaultMaskChar)
		return ctx, nil
	})

	sc.Step(`^a fresh masker$`, w.aFreshMasker)
	sc.Step(`^a fresh masker with mask character "([^"]+)"$`, w.aFreshMaskerWithChar)
	sc.Step(`^the global mask character is set to "([^"]+)"$`, w.setGlobalMaskChar)
	sc.Step(`^two fresh maskers named "([^"]+)" and "([^"]+)"$`, w.twoFreshMaskers)
	sc.Step(`^I register a custom rule "([^"]+)" that reverses its input$`, w.registerReverseRule)
	sc.Step(`^I register a custom rule "([^"]+)" that reverses its input on the global registry$`, w.registerReverseRuleGlobal)
	sc.Step(`^I register "([^"]*)" a second time$`, w.registerNamedAgain)
	sc.Step(`^I register "([^"]*)" with a valid function$`, w.registerNameOnly)
	sc.Step(`^I register a "([^"]+)" rule on masker "([^"]+)"$`, w.registerRuleOnMasker)
	sc.Step(`^I mask "([^"]*)" with rule "([^"]+)"$`, w.maskWithRule)
	sc.Step(`^I mask "([^"]*)" with rule "([^"]+)" on the global registry$`, w.maskWithRuleGlobal)
	sc.Step(`^I describe rule "([^"]+)"$`, w.describeRule)
	sc.Step(`^I list rules$`, w.listRules)

	sc.Step(`^the result is "([^"]*)"$`, w.theResultIs)
	sc.Step(`^the result is exactly "([^"]*)"$`, w.theResultIs)
	sc.Step(`^the registration fails with error kind "([^"]+)"$`, w.registrationFailsWith)
	sc.Step(`^masker "([^"]+)" has rule "([^"]+)"$`, w.maskerHasRule)
	sc.Step(`^masker "([^"]+)" does not have rule "([^"]+)"$`, w.maskerDoesNotHaveRule)
	sc.Step(`^the describe result is present$`, w.describePresent)
	sc.Step(`^the describe result name is "([^"]+)"$`, w.describeName)
	sc.Step(`^the describe result category is "([^"]+)"$`, w.describeCategory)
	sc.Step(`^the describe result jurisdiction is "([^"]+)"$`, w.describeJurisdiction)
	sc.Step(`^the describe result description contains "([^"]+)"$`, w.describeDescriptionContains)
	sc.Step(`^the listed rules contain, in order, "([^"]+)", "([^"]+)", "([^"]+)"$`, w.listedRulesInOrder)

	// Primitives feature steps — share the World so "a fresh masker" and
	// "the result is" are defined exactly once for the whole suite.
	sc.Step(`^I apply "([^"]+)" to "([^"]*)"$`, w.applyRule)
	sc.Step(`^I apply "([^"]+)" to "([^"]*)" (\d+) times$`, w.applyRuleNTimes)
	sc.Step(`^I use KeepFirstN on "([^"]*)" with n (-?\d+) and char "([^"]+)"$`, w.useKeepFirstN)
	sc.Step(`^I use KeepLastN on "([^"]*)" with n (-?\d+) and char "([^"]+)"$`, w.useKeepLastN)
	sc.Step(`^I use KeepFirstLast on "([^"]*)" with first (-?\d+) last (-?\d+) and char "([^"]+)"$`, w.useKeepFirstLast)
	sc.Step(`^I use PreserveDelimiters on "([^"]*)" with delim "([^"]*)" and char "([^"]+)"$`, w.usePreserveDelimiters)
	sc.Step(`^I use ReplaceRegexFunc with pattern "([^"]*)" and replacement "([^"]*)" on "([^"]*)"$`, w.useReplaceRegexFunc)
	sc.Step(`^I use FixedReplacementFunc with replacement "([^"]*)" on "([^"]*)"$`, w.useFixedReplacement)
	sc.Step(`^I use ReducePrecision on "([^"]*)" with decimals (-?\d+) and char "([^"]+)"$`, w.useReducePrecision)
	sc.Step(`^I compute DeterministicHashWith on "([^"]*)" using algorithm "([^"]+)"$`, w.useDeterministicHashAlgo)
	sc.Step(`^I compute DeterministicHashWith on "([^"]*)" using algorithm "([^"]+)" and salt "([^"]*)" version "([^"]*)"$`, w.useDeterministicHashAlgoSaltVersion)
	sc.Step(`^I compute DeterministicHashWith on "([^"]*)" with salt "([^"]*)" version "([^"]*)"$`, w.useDeterministicHashSaltVersion)
	sc.Step(`^I also compute DeterministicHashWith on "([^"]*)" with salt "([^"]*)" version "([^"]*)"$`, w.useDeterministicHashSaltVersionSecond)

	sc.Step(`^every result is identical$`, w.everyResultIsIdentical)
	sc.Step(`^the result starts with "([^"]+)"$`, w.theResultStartsWith)
	sc.Step(`^the result has length (\d+)$`, w.theResultHasLength)
	sc.Step(`^the result does not contain "([^"]+)"$`, w.theResultDoesNotContain)
	sc.Step(`^the two results differ$`, w.theTwoResultsDiffer)
	sc.Step(`^the replace result is "([^"]*)" and the error is absent$`, w.replaceResultIsAndErrAbsent)
	sc.Step(`^the replace result is empty and the error is present$`, w.replaceResultEmptyAndErrPresent)

	RegisterDocumentationSteps(sc, w)
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func (w *World) getOrCreate(key string) *mask.Masker {
	if m, ok := w.maskers[key]; ok {
		return m
	}
	m := mask.New()
	w.maskers[key] = m
	return m
}

func (w *World) aFreshMasker() error {
	w.maskers[defaultKey] = mask.New()
	return nil
}

func (w *World) aFreshMaskerWithChar(ch string) error {
	r, err := singleRune(ch)
	if err != nil {
		return err
	}
	w.maskers[defaultKey] = mask.New(mask.WithMaskChar(r))
	return nil
}

func (w *World) setGlobalMaskChar(ch string) error {
	r, err := singleRune(ch)
	if err != nil {
		return err
	}
	mask.SetMaskChar(r)
	return nil
}

func singleRune(s string) (rune, error) {
	runes := []rune(s)
	if len(runes) != 1 {
		return 0, fmt.Errorf("expected a single-character mask character, got %q", s)
	}
	return runes[0], nil
}

func (w *World) twoFreshMaskers(a, b string) error {
	w.maskers[a] = mask.New()
	w.maskers[b] = mask.New()
	return nil
}

func (w *World) registerReverseRule(name string) error {
	m := w.getOrCreate(defaultKey)
	return m.Register(name, reverse)
}

func (w *World) registerReverseRuleGlobal(name string) error {
	// Mangle the caller's name with a process-wide monotonic suffix
	// so repeated scenario invocations (go test -count=N, or multiple
	// Before hooks inside a single run) do not collide on the
	// package-level registry, which has no Deregister by design.
	globalName := name + "_" + strconv.FormatUint(globalRuleSeq.Add(1), 10)
	w.globalRuleNames[name] = globalName
	w.lastError = mask.Register(globalName, reverse)
	return w.lastError
}

func (w *World) registerRuleOnMasker(ruleName, maskerName string) error {
	m := w.getOrCreate(maskerName)
	return m.Register(ruleName, reverse)
}

func (w *World) registerNamedAgain(name string) error {
	m := w.getOrCreate(defaultKey)
	w.lastError = m.Register(name, reverse)
	return nil
}

func (w *World) registerNameOnly(name string) error {
	m := w.getOrCreate(defaultKey)
	w.lastError = m.Register(name, reverse)
	return nil
}

func (w *World) maskWithRule(value, rule string) error {
	m := w.getOrCreate(defaultKey)
	w.lastResult = m.Apply(rule, value)
	return nil
}

func (w *World) maskWithRuleGlobal(value, rule string) error {
	// Translate the Gherkin-level rule name to its suffix-mangled
	// form registered by registerReverseRuleGlobal, so scenarios
	// survive `go test -count=N` against a shared registry.
	if actual, ok := w.globalRuleNames[rule]; ok {
		rule = actual
	}
	w.lastResult = mask.Apply(rule, value)
	return nil
}

func (w *World) theResultIs(expected string) error {
	if w.lastResult != expected {
		return fmt.Errorf("expected %q, got %q", expected, w.lastResult)
	}
	return nil
}

func (w *World) registrationFailsWith(kind string) error {
	if w.lastError == nil {
		return fmt.Errorf("expected registration error of kind %q, got nil", kind)
	}
	switch strings.ToLower(kind) {
	case "duplicate":
		if !errors.Is(w.lastError, mask.ErrDuplicateRule) {
			return fmt.Errorf("expected ErrDuplicateRule, got %v", w.lastError)
		}
	case "invalid":
		if !errors.Is(w.lastError, mask.ErrInvalidRule) {
			return fmt.Errorf("expected ErrInvalidRule, got %v", w.lastError)
		}
	default:
		return fmt.Errorf("unknown error kind %q", kind)
	}
	return nil
}

func (w *World) maskerHasRule(maskerKey, rule string) error {
	m, ok := w.maskers[maskerKey]
	if !ok {
		return fmt.Errorf("masker %q not declared", maskerKey)
	}
	if !m.HasRule(rule) {
		return fmt.Errorf("masker %q did not have rule %q", maskerKey, rule)
	}
	return nil
}

func (w *World) maskerDoesNotHaveRule(maskerKey, rule string) error {
	m, ok := w.maskers[maskerKey]
	if !ok {
		return fmt.Errorf("masker %q not declared", maskerKey)
	}
	if m.HasRule(rule) {
		return fmt.Errorf("masker %q unexpectedly had rule %q", maskerKey, rule)
	}
	return nil
}

func (w *World) describeRule(name string) error {
	m := w.getOrCreate(defaultKey)
	w.lastDescribe, w.lastDescribeOK = m.Describe(name)
	return nil
}

func (w *World) describePresent() error {
	if !w.lastDescribeOK {
		return fmt.Errorf("describe returned not found")
	}
	return nil
}

func (w *World) describeName(expected string) error {
	if w.lastDescribe.Name != expected {
		return fmt.Errorf("expected describe name %q, got %q", expected, w.lastDescribe.Name)
	}
	return nil
}

func (w *World) describeCategory(expected string) error {
	if w.lastDescribe.Category != expected {
		return fmt.Errorf("expected describe category %q, got %q", expected, w.lastDescribe.Category)
	}
	return nil
}

func (w *World) describeJurisdiction(expected string) error {
	if w.lastDescribe.Jurisdiction != expected {
		return fmt.Errorf("expected describe jurisdiction %q, got %q", expected, w.lastDescribe.Jurisdiction)
	}
	return nil
}

func (w *World) describeDescriptionContains(substr string) error {
	if !strings.Contains(w.lastDescribe.Description, substr) {
		return fmt.Errorf("expected describe description to contain %q, got %q", substr, w.lastDescribe.Description)
	}
	return nil
}

func (w *World) listRules() error {
	m := w.getOrCreate(defaultKey)
	w.lastRules = m.Rules()
	return nil
}

func (w *World) listedRulesInOrder(a, b, c string) error {
	idxA := slices.Index(w.lastRules, a)
	idxB := slices.Index(w.lastRules, b)
	idxC := slices.Index(w.lastRules, c)
	if idxA < 0 || idxB < 0 || idxC < 0 {
		return fmt.Errorf("one of %q %q %q not found in %v", a, b, c, w.lastRules)
	}
	if idxA >= idxB || idxB >= idxC {
		return fmt.Errorf("rules not in expected order: %v", w.lastRules)
	}
	return nil
}
