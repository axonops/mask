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
	"strings"

	"github.com/axonops/mask"
)

// toSingleRune returns the single rune of s or an error if s does not have
// exactly one rune.
func toSingleRune(s string) (rune, error) {
	rs := []rune(s)
	if len(rs) != 1 {
		return 0, fmt.Errorf("expected a single rune, got %q", s)
	}
	return rs[0], nil
}

func algoFromLabel(label string) (mask.HashAlgorithm, error) {
	switch label {
	case "SHA256":
		return mask.SHA256, nil
	case "SHA512":
		return mask.SHA512, nil
	case "SHA3_256":
		return mask.SHA3_256, nil
	case "SHA3_512":
		return mask.SHA3_512, nil
	default:
		return 0, fmt.Errorf("unknown HashAlgorithm label %q", label)
	}
}

func (w *World) applyRule(rule, value string) error {
	m := w.getOrCreate(defaultKey)
	w.lastResult = m.Apply(rule, value)
	return nil
}

func (w *World) applyRuleNTimes(rule, value string, n int) error {
	m := w.getOrCreate(defaultKey)
	w.lastResults = make([]string, 0, n)
	for i := 0; i < n; i++ {
		w.lastResults = append(w.lastResults, m.Apply(rule, value))
	}
	w.lastResult = w.lastResults[0]
	return nil
}

func (w *World) useKeepFirstN(v string, n int, ch string) error {
	r, err := toSingleRune(ch)
	if err != nil {
		return err
	}
	w.lastResult = mask.KeepFirstN(v, n, r)
	return nil
}

func (w *World) useKeepLastN(v string, n int, ch string) error {
	r, err := toSingleRune(ch)
	if err != nil {
		return err
	}
	w.lastResult = mask.KeepLastN(v, n, r)
	return nil
}

func (w *World) useKeepFirstLast(v string, first, last int, ch string) error {
	r, err := toSingleRune(ch)
	if err != nil {
		return err
	}
	w.lastResult = mask.KeepFirstLast(v, first, last, r)
	return nil
}

func (w *World) usePreserveDelimiters(v, delim, ch string) error {
	r, err := toSingleRune(ch)
	if err != nil {
		return err
	}
	w.lastResult = mask.PreserveDelimiters(v, delim, r)
	return nil
}

func (w *World) useTruncateVisible(v string, n int) error {
	w.lastResult = mask.TruncateVisible(v, n)
	return nil
}

func (w *World) useReplaceRegex(v, pattern, replacement string) error {
	w.replaceResult, w.replaceErr = mask.ReplaceRegex(v, pattern, replacement)
	return nil
}

func (w *World) useFixedReplacement(replacement, v string) error {
	r := mask.FixedReplacementFunc(replacement)
	w.lastResult = r(v)
	return nil
}

func (w *World) useReducePrecision(v string, decimals int, ch string) error {
	r, err := toSingleRune(ch)
	if err != nil {
		return err
	}
	w.lastResult = mask.ReducePrecision(v, decimals, r)
	return nil
}

func (w *World) useDeterministicHashAlgo(v, algoLabel string) error {
	algo, err := algoFromLabel(algoLabel)
	if err != nil {
		return err
	}
	w.lastResult = mask.DeterministicHashWith(v, mask.WithAlgorithm(algo))
	return nil
}

func (w *World) useDeterministicHashAlgoSalt(v, algoLabel, salt string) error {
	algo, err := algoFromLabel(algoLabel)
	if err != nil {
		return err
	}
	w.lastResult = mask.DeterministicHashWith(v, mask.WithAlgorithm(algo), mask.WithSalt(salt))
	return nil
}

func (w *World) useDeterministicHashSalt(v, salt string) error {
	w.lastResult = mask.DeterministicHashWith(v, mask.WithSalt(salt))
	return nil
}

func (w *World) useDeterministicHashSaltSecond(v, salt string) error {
	w.secondResult = mask.DeterministicHashWith(v, mask.WithSalt(salt))
	return nil
}

func (w *World) everyResultIsIdentical() error {
	if len(w.lastResults) == 0 {
		return fmt.Errorf("no results captured")
	}
	first := w.lastResults[0]
	for i, r := range w.lastResults {
		if r != first {
			return fmt.Errorf("result %d differs from first: %q vs %q", i, r, first)
		}
	}
	return nil
}

func (w *World) theResultStartsWith(prefix string) error {
	if !strings.HasPrefix(w.lastResult, prefix) {
		return fmt.Errorf("expected prefix %q, got %q", prefix, w.lastResult)
	}
	return nil
}

func (w *World) theResultHasLength(n int) error {
	if len(w.lastResult) != n {
		return fmt.Errorf("expected length %d, got %d (%q)", n, len(w.lastResult), w.lastResult)
	}
	return nil
}

func (w *World) theResultDoesNotContain(needle string) error {
	if strings.Contains(w.lastResult, needle) {
		return fmt.Errorf("result %q unexpectedly contains %q", w.lastResult, needle)
	}
	return nil
}

func (w *World) theTwoResultsDiffer() error {
	if w.lastResult == w.secondResult {
		return fmt.Errorf("expected different results, both were %q", w.lastResult)
	}
	return nil
}

func (w *World) replaceResultIsAndErrAbsent(expected string) error {
	if w.replaceErr != nil {
		return fmt.Errorf("expected no error, got %v", w.replaceErr)
	}
	if w.replaceResult != expected {
		return fmt.Errorf("expected %q, got %q", expected, w.replaceResult)
	}
	return nil
}

func (w *World) replaceResultEmptyAndErrPresent() error {
	if w.replaceErr == nil {
		return fmt.Errorf("expected an error, got nil")
	}
	if w.replaceResult != "" {
		return fmt.Errorf("expected empty result on error, got %q", w.replaceResult)
	}
	return nil
}
