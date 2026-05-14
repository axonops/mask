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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
)

// DefaultMaskChar is the mask rune used when no override is configured. It is
// the ASCII asterisk (U+002A).
const DefaultMaskChar = '*'

// FullRedactMarker is the constant string that [Apply] returns when a rule is
// unknown or when a rule explicitly opts for full redaction.
const FullRedactMarker = "[REDACTED]"

// Sentinel errors returned by [Register]. [Apply] never returns an error; it
// degrades to [FullRedactMarker] when a rule is unknown.
var (
	// ErrDuplicateRule is returned by [Register] when a rule name is already
	// registered on the target registry.
	ErrDuplicateRule = errors.New("mask: rule already registered")

	// ErrInvalidRule is returned by [Register] when a rule name does not match
	// ^[a-z][a-z0-9_]*$ or when the supplied RuleFunc is nil.
	ErrInvalidRule = errors.New("mask: rule is invalid")
)

// ruleNamePattern defines the accepted grammar for rule names: lowercase
// snake_case starting with a letter.
var ruleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// RuleFunc masks a single string value and returns the masked result.
//
// A RuleFunc MUST be a pure, deterministic function of its input. It MUST NOT
// panic, MUST NOT return the original unmasked value on parse failure (fail
// closed), and MUST be safe for concurrent use. All built-in rules satisfy
// these requirements.
type RuleFunc func(value string) string

// RuleInfo describes a registered rule. It is returned by [Masker.Describe]
// and the package-level [Describe].
type RuleInfo struct {
	// Name is the canonical label the rule is registered under.
	Name string
	// Category groups related rules. Built-in rules use one of:
	// "identity" (including country-specific identity rules),
	// "financial", "health", "technology", "telecom", "location", or
	// "utility". The field is a free-form string — future rules may
	// introduce additional categories — and is empty for user-registered
	// rules that omit it.
	Category string
	// Jurisdiction names the country or standard a rule applies to.
	// Built-in rules use full names: "global", "global (HIPAA)",
	// "global (PCI DSS)", "United States", "United Kingdom",
	// "Canada", "India", "Brazil", "Mexico", "Spain", "South Africa",
	// "China", "Singapore", "Australia". The field is free-form and
	// may be empty for user-registered rules.
	Jurisdiction string
	// Description is a human-readable sentence explaining what the rule does.
	// Built-in rules end their description with an "Example: input → output"
	// line. May be empty for user-registered rules.
	Description string
}

// Option configures a [Masker] at construction time. Use [WithMaskChar] and
// any future options via [New].
type Option func(*Masker)

// WithMaskChar sets the mask character for the Masker under construction.
// The default is [DefaultMaskChar]. Built-in rules use this character wherever
// they emit mask runes.
//
// The value should be a printable Unicode code point. Negative values, the
// zero rune, and unassigned code points are accepted by the setter but may
// produce unreadable output; this library does not validate the choice.
//
// Example:
//
//	m := mask.New(mask.WithMaskChar('X'))
//	m.Apply("us_ssn", "123-45-6789") // → "XXX-XX-6789"
func WithMaskChar(c rune) Option {
	return func(m *Masker) {
		m.setMaskChar(c)
	}
}

// Masker holds an isolated rule registry and a configured mask rune;
// use it when you need parallel registries that do not share state
// with the package-level API.
//
// The zero value is usable: on first call, built-in rules register themselves
// and the mask character defaults to [DefaultMaskChar]. Prefer [New] when you
// want to apply options at construction.
//
// A Masker MUST NOT be copied after first use. It contains
// synchronisation primitives and atomic fields; copying it is a
// programming error that go vet will flag.
//
// Thread-safety contract: [Masker.Register] MUST NOT be called concurrently
// with [Masker.Apply]. Call all [Masker.Register] invocations during program
// initialisation. After every [Masker.Register] call has returned, [Masker.Apply]
// is safe for concurrent use from any number of goroutines. This matches the
// contract used by database/sql.Register.
type Masker struct {
	initOnce       sync.Once
	builtinsOnce   sync.Once
	registerMu     sync.Mutex
	rules          atomic.Pointer[ruleMap]
	maskCharAtomic atomic.Int32
}

type ruleMap map[string]ruleEntry

type ruleEntry struct {
	fn   RuleFunc
	info RuleInfo
}

// builtinRegistrars collects functions that populate a [Masker] with built-in
// rules. Subsequent phases append to this slice from their own init
// functions; every append completes before the first call to [ensureInit],
// so no further synchronisation is needed around the slice itself.
//
// Each registrar MUST call [Masker.registerLocked] rather than the public
// [Masker.Register] or the internal [Masker.register] — those paths re-enter
// [Masker.ensureInit] and would deadlock against the in-flight builtinsOnce.
var builtinRegistrars []func(*Masker)

// New creates a [Masker] with built-in rules pre-registered and applies the
// supplied options. The returned Masker is isolated from the package-level
// registry: rules registered on one Masker are invisible to any other.
//
// Example:
//
//	m := mask.New(mask.WithMaskChar('#'))
//	m.Apply("email_address", "alice@example.com") // → "a####@example.com"
func New(opts ...Option) *Masker {
	m := &Masker{}
	m.ensureInit()
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// ensureInit lazily populates the registry on first use so the zero value of
// [Masker] is usable.
//
// Initialisation runs in two steps controlled by separate sync.Once values:
//
//  1. initOnce sets up the empty ruleMap and default mask character.
//  2. builtinsOnce invokes every registrar in builtinRegistrars.
//
// Splitting the work is deliberate. Built-in registrars call
// [Masker.registerLocked], which must see a non-nil rule map. If both
// steps shared a single Once, a registrar's nested use of the locked
// register path would still be safe, but any accidental use of
// [Masker.Register] from a registrar would re-enter the same Once and
// deadlock. Two Onces make the boundary explicit.
func (m *Masker) ensureInit() {
	m.initOnce.Do(func() {
		empty := ruleMap{}
		m.rules.Store(&empty)
		m.maskCharAtomic.Store(DefaultMaskChar)
	})
	m.builtinsOnce.Do(func() {
		for _, reg := range builtinRegistrars {
			reg(m)
		}
	})
}

// setMaskChar is the internal mask-character setter used by [WithMaskChar] and
// by the package-level [SetMaskChar].
func (m *Masker) setMaskChar(c rune) {
	m.ensureInit()
	m.maskCharAtomic.Store(c)
}

// maskChar returns the mask rune currently configured on this Masker.
// Built-in registrars close over the Masker and call maskChar inside the
// produced RuleFunc so that a later WithMaskChar or SetMaskChar call takes
// effect on every subsequent Apply without requiring re-registration.
func (m *Masker) maskChar() rune {
	return m.maskCharAtomic.Load()
}

// MaskChar reports which rune this Masker will substitute for hidden
// characters. The returned value reflects the most recent [WithMaskChar]
// applied at construction or [SetMaskChar] at runtime, defaulting to
// [DefaultMaskChar] if neither has been called.
//
// Custom rule authors who want their rule to honour per-instance
// mask-character configuration call this inside the registered closure:
//
//	m.Register("my_rule", func(v string) string {
//	    return mask.KeepFirstN(v, 4, m.MaskChar())
//	})
//
// Calling MaskChar on a zero-value Masker is safe; the returned rune is
// [DefaultMaskChar] until [SetMaskChar] or [WithMaskChar] changes it.
func (m *Masker) MaskChar() rune {
	m.ensureInit()
	return m.maskChar()
}

// Apply masks value using the named rule.
//
// If rule is not registered on this Masker, Apply returns [FullRedactMarker]
// — never the original value. Individual built-in rules fall back to a
// same-length mask when they cannot parse their input.
//
// Apply is safe for concurrent use by any number of goroutines provided all
// [Masker.Register] calls have completed before the first Apply call. See the
// thread-safety contract on [Masker].
//
// Example: m.Apply("email_address", "alice@example.com") → "a****@example.com".
func (m *Masker) Apply(rule, value string) string {
	// ensureInit must run on every Apply, not just when the rules
	// pointer is nil. initOnce stores an empty rule map BEFORE
	// builtinsOnce registers the built-ins, so a parallel reader
	// that observes the pointer between those two Once calls would
	// see an empty registry and fall through to FullRedactMarker.
	// sync.Once's fast path after first use is a single atomic
	// load + branch, so the cost is negligible.
	m.ensureInit()
	rm := m.rules.Load()
	e, ok := (*rm)[rule]
	if !ok {
		return FullRedactMarker
	}
	return e.fn(value)
}

// Register adds a custom masking rule to this Masker's registry.
//
// Register returns [ErrInvalidRule] wrapped with the offending name if name
// does not match ^[a-z][a-z0-9_]*$ or if fn is nil. It returns
// [ErrDuplicateRule] wrapped with the offending name if a rule with that name
// is already registered. Use [errors.Is] to discriminate.
//
// Register is O(N) in the number of existing rules — each call copies the
// rule map under a mutex. This is intentional: registration runs once at
// init time and keeps the hot-path [Apply] lock-free. Do not call Register
// on a latency-sensitive path.
//
// Register MUST NOT be called concurrently with [Masker.Apply]. See the
// thread-safety contract on [Masker].
//
// Example:
//
//	err := m.Register("my_token", mask.KeepFirstNFunc(4))
//	// m.Apply("my_token", "SensitiveToken") → "Sens**********".
func (m *Masker) Register(name string, fn RuleFunc) error {
	m.ensureInit()
	return m.registerLocked(name, fn, RuleInfo{Name: name})
}

// registerLocked is the lock-taking registration implementation. It does NOT
// call [Masker.ensureInit]; callers in the public API path do so first, while
// built-in registrars invoke this method from within [Masker.ensureInit]'s
// builtinsOnce closure where re-entering ensureInit would deadlock.
func (m *Masker) registerLocked(name string, fn RuleFunc, info RuleInfo) error {
	if !ruleNamePattern.MatchString(name) {
		return fmt.Errorf("%w: name %q must match ^[a-z][a-z0-9_]*$", ErrInvalidRule, name)
	}
	if fn == nil {
		return fmt.Errorf("%w: name %q has nil RuleFunc", ErrInvalidRule, name)
	}
	m.registerMu.Lock()
	defer m.registerMu.Unlock()

	current := m.rules.Load()
	if _, exists := (*current)[name]; exists {
		return fmt.Errorf("%w: name %q", ErrDuplicateRule, name)
	}
	next := make(ruleMap, len(*current)+1)
	for k, v := range *current {
		next[k] = v
	}
	if info.Name == "" {
		info.Name = name
	}
	next[name] = ruleEntry{fn: fn, info: info}
	m.rules.Store(&next)
	return nil
}

// mustRegisterBuiltin is a helper for built-in registrars. It panics on
// registration failure so programmer errors in the library surface at
// import time (the first call to [ensureInit]) rather than at first [Apply].
// Consumer code never calls this — use [Masker.Register] instead.
func (m *Masker) mustRegisterBuiltin(name string, fn RuleFunc, info RuleInfo) {
	if err := m.registerLocked(name, fn, info); err != nil {
		panic(fmt.Sprintf("mask: built-in registration failed: %v", err))
	}
}

// loadRules returns the current rule map, initialising the Masker lazily on
// first access. Callers treat the returned pointer as immutable.
func (m *Masker) loadRules() *ruleMap {
	rm := m.rules.Load()
	if rm == nil {
		m.ensureInit()
		rm = m.rules.Load()
	}
	return rm
}

// Rules lists every rule name registered on this Masker (built-in and
// custom), alphabetically sorted. Ordering is stable across calls on
// an unchanged registry, so callers can rely on it for deterministic
// output in generated documentation, tests, and snapshots. The slice
// is freshly allocated, so callers may mutate or sort it without
// affecting the registry.
//
// Example:
//
//	names := m.Rules()
//	// names == ["api_key", "bank_account_number", ..., "uuid"] (sorted)
func (m *Masker) Rules() []string {
	rm := m.loadRules()
	names := make([]string, 0, len(*rm))
	for k := range *rm {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// HasRule reports whether a rule with the given name is registered on this
// Masker. Use this to avoid triggering the [FullRedactMarker] fallback when a
// rule's presence is uncertain.
//
// Example:
//
//	m.HasRule("email_address") // → true
//	m.HasRule("not_a_rule")    // → false
func (m *Masker) HasRule(name string) bool {
	rm := m.loadRules()
	_, ok := (*rm)[name]
	return ok
}

// Describe returns the [RuleInfo] for a registered rule and a boolean
// indicating whether the rule was found. For rules registered via
// [Masker.Register] the Name field is populated and the other fields may be
// empty; built-in rules populate every field.
//
// Example:
//
//	info, ok := m.Describe("email_address")
//	// info.Category == "identity", info.Jurisdiction == "global"
func (m *Masker) Describe(name string) (RuleInfo, bool) {
	rm := m.loadRules()
	e, ok := (*rm)[name]
	if !ok {
		return RuleInfo{}, false
	}
	return e.info, true
}

// DescribeAll returns the [RuleInfo] for every rule registered on this
// Masker, sorted by [RuleInfo.Name]. Useful for dashboards, audit tools,
// and configuration UIs that enumerate the full catalogue in one pass.
//
// The returned slice is freshly allocated on every call — callers may
// mutate it freely. Calling DescribeAll is equivalent to iterating
// [Masker.Rules] and calling [Masker.Describe] for each name, but
// avoids the redundant guard clause on the always-present lookup.
//
// Example:
//
//	for _, info := range m.DescribeAll() {
//	    fmt.Printf("%s [%s] — %s\n", info.Name, info.Category, info.Description)
//	}
func (m *Masker) DescribeAll() []RuleInfo {
	rm := m.loadRules()
	infos := make([]RuleInfo, 0, len(*rm))
	for _, e := range *rm {
		infos = append(infos, e.info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})
	return infos
}

// defaultMasker backs the package-level API. It is intentionally not
// constructed via [New]; its initialisation is lazy so all package init
// functions (including those that append to builtinRegistrars) run first.
var defaultMasker = &Masker{}

// Apply masks value using the named rule from the package-level registry.
// See [Masker.Apply] for semantics.
//
// Example: mask.Apply("email_address", "alice@example.com") → "a****@example.com".
func Apply(rule, value string) string {
	return defaultMasker.Apply(rule, value)
}

// Register adds a custom masking rule to the package-level registry.
// See [Masker.Register] for the rule-name grammar and thread-safety contract.
//
// Example:
//
//	err := mask.Register("my_token", mask.KeepFirstNFunc(4))
//	// mask.Apply("my_token", "SensitiveToken") → "Sens**********".
func Register(name string, fn RuleFunc) error {
	return defaultMasker.Register(name, fn)
}

// SetMaskChar overrides the mask character used by the package-level registry
// and its built-in rules. The value should be a printable Unicode code point;
// see [WithMaskChar] for details.
//
// SetMaskChar MUST NOT be called concurrently with [Apply]. Per-instance
// control is available via [WithMaskChar].
//
// Example:
//
//	mask.SetMaskChar('#')
//	mask.Apply("us_ssn", "123-45-6789") // → "###-##-6789"
func SetMaskChar(c rune) {
	defaultMasker.setMaskChar(c)
}

// Rules returns the sorted list of rule names registered on the package-level
// registry. See [Masker.Rules].
func Rules() []string {
	return defaultMasker.Rules()
}

// HasRule reports whether a rule with the given name is registered on the
// package-level registry. See [Masker.HasRule].
func HasRule(name string) bool {
	return defaultMasker.HasRule(name)
}

// Describe returns the [RuleInfo] for a rule registered on the package-level
// registry. See [Masker.Describe].
func Describe(name string) (RuleInfo, bool) {
	return defaultMasker.Describe(name)
}

// DescribeAll returns the [RuleInfo] for every rule registered on the
// package-level registry, sorted by name. See [Masker.DescribeAll].
func DescribeAll() []RuleInfo {
	return defaultMasker.DescribeAll()
}

// MaskChar returns the mask rune currently configured on the package-level
// registry. See [Masker.MaskChar].
func MaskChar() rune {
	return defaultMasker.MaskChar()
}
