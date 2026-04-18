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

// Package mask is a pure-function string-masking library.
//
// The library provides composable utility primitives and a rich catalogue of
// built-in domain rules for redacting personally identifying information,
// payment card data, and protected health information from strings before
// they are logged, displayed, or persisted. It is stdlib-only at runtime.
//
// # Quick start
//
//	package main
//
//	import (
//		"fmt"
//
//		"github.com/axonops/mask"
//	)
//
//	func main() {
//		fmt.Println(mask.Apply("email_address", "alice@example.com"))
//		// Output: a****@example.com
//	}
//
// # Design principles
//
// Masking rules fail closed. When [Apply] is called with an unknown rule it
// returns [FullRedactMarker] — never the original value. When a built-in rule
// cannot parse its input it falls back to a same-length mask. This keeps the
// library predictable and safe by default.
//
// Primitives and domain rules are separate layers. Generic building blocks
// such as keep_first_n, same_length_mask and deterministic_hash are exposed
// both as registered rules and as Go helper functions; domain rules such as
// payment_card_pan, email_address and us_ssn are thin wrappers over the
// primitives with format-aware parsing.
//
// Rule names are lowercase snake_case. Country-specific identifiers are
// jurisdiction-qualified (us_ssn, uk_nino, in_aadhaar). The authoritative
// catalogue lives in docs/v0.9.0-requirements.md; use [Rules] and [Describe]
// to discover available rules at runtime.
//
// # Thread safety
//
// [Register] (both the package-level function and [Masker.Register]) MUST NOT
// be called concurrently with [Apply]. Call Register during program
// initialisation, before any goroutine starts calling Apply. After every
// Register call has returned, the registry is read-only and Apply is safe for
// concurrent use by any number of goroutines. This matches the contract used
// by database/sql.Register.
//
// Built-in rules are stateless pure functions and are safe for concurrent use
// once registered. Custom [RuleFunc] implementations MUST satisfy the same
// contract.
//
// # Mask character
//
// The default mask character is the ASCII asterisk. Override it globally with
// [SetMaskChar] or per instance with [WithMaskChar]. Built-in rules read the
// configured character at apply time so changes are picked up immediately.
//
// # Non-goals
//
// The API does not accept [context.Context]. Masking is pure compute with no
// I/O, no goroutines, and no blocking operations; a context would never be
// consulted and would mislead callers into expecting cancellation or deadline
// semantics that cannot be honoured. This mirrors the stdlib strings,
// strconv and encoding/* packages, which also do not accept context.
//
// If a future rule legitimately requires per-request metadata — for example
// a policy-driven rule that varies by tenant — that metadata belongs on a
// dedicated [Masker] instance constructed via [New], not smuggled through a
// context value. If a future built-in rule cannot be implemented without
// I/O (for example an HSM-backed tokeniser calling a remote KMS), the right
// move is a separate subpackage with its own context-aware interface —
// leaving the core [Apply] signature untouched.
//
// # Further reading
//
//   - The full rule catalogue lives in docs/v0.9.0-requirements.md.
//   - Contributing guidance is in CONTRIBUTING.md.
//   - Vulnerability disclosure policy is in SECURITY.md.
package mask
