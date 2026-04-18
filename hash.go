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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
)

// saltVersionPattern is the grammar a [WithKeyedSalt] version argument must match.
// The set is deliberately narrow:
//
//   - A-Z / a-z / 0-9: printable, unambiguous, no encoding issues
//   - `.`, `-`, `_`:   common version delimiters, all URL-safe, all unreserved
//     or sub-delim per RFC 3986
//   - 1-32 bytes:      bounds the on-the-wire prefix so an attacker-influenced
//     config cannot blow up output size
//
// The colon, whitespace, shell metacharacters, non-ASCII letters, and every
// other structural or ambiguous character are rejected — they would either
// confuse the `<algo>:<version>:<hex16>` wire format or tempt downstream
// consumers to parse the version as something other than an opaque label.
var saltVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// HashAlgorithm selects the cryptographic hash used by the deterministic-hash
// primitives. The zero value is [SHA256], the library default. MD5 and SHA-1
// are not supported and will never be added — they are cryptographically
// broken for collision resistance and have no place in a masking library.
type HashAlgorithm int

// SHA3_256 and SHA3_512 deliberately mirror the stdlib crypto.SHA3_256 /
// crypto.SHA3_512 naming so callers switching between the two packages do
// not have to remember which underscore rule applies. The revive var-naming
// rule is suppressed on those two lines for that reason.
const (
	// SHA256 is the default. Output prefix "sha256".
	SHA256 HashAlgorithm = iota
	// SHA512 uses SHA-512. Output prefix "sha512".
	SHA512
	// SHA3_256 uses SHA3-256. Output prefix "sha3-256".
	SHA3_256 //nolint:revive // matches stdlib crypto.SHA3_256
	// SHA3_512 uses SHA3-512. Output prefix "sha3-512".
	SHA3_512 //nolint:revive // matches stdlib crypto.SHA3_512

	// maxHashAlgorithm is the exclusive upper bound used for range checks.
	maxHashAlgorithm
)

// algoEntry pairs the on-the-wire prefix with the constructor used to build a
// fresh [hash.Hash]. The algoTable is the single source of truth for both the
// prefix reported by [HashAlgorithm.String] and the bytes emitted on the
// wire — diverging the two is a bug.
type algoEntry struct {
	prefix string
	ctor   func() hash.Hash
}

// sha3.New256/New512 return *sha3.SHA3, which satisfies hash.Hash but cannot
// be assigned to a func() hash.Hash directly; wrap them in adapter closures.
var algoTable = [maxHashAlgorithm]algoEntry{
	SHA256:   {"sha256", sha256.New},
	SHA512:   {"sha512", sha512.New},
	SHA3_256: {"sha3-256", func() hash.Hash { return sha3.New256() }},
	SHA3_512: {"sha3-512", func() hash.Hash { return sha3.New512() }},
}

// String returns the on-the-wire prefix for a. Out-of-range values
// return a "HashAlgorithm(N)" form mirroring stdlib [reflect.Kind.String]
// — a programmer error is surfaced rather than silently clamped.
func (a HashAlgorithm) String() string {
	if a < 0 || a >= maxHashAlgorithm {
		return fmt.Sprintf("HashAlgorithm(%d)", int(a))
	}
	return algoTable[a].prefix
}

// hashConfig is the effective configuration produced by applying zero
// or more [HashOption] values. The zero value corresponds to "unsalted
// SHA-256". When misconfigured is true every subsequent Apply emits
// [FullRedactMarker] — the only way the flag is set is via an option
// that fails its own validation (currently [WithKeyedSalt]).
type hashConfig struct {
	algo          HashAlgorithm
	salt          string // empty string means "no salt" — the unsalted path
	version       string // salt-version identifier; non-empty only when salt != ""
	misconfigured bool   // true when an option failed validation; hashApply emits FullRedactMarker
}

// HashOption configures the deterministic-hash primitives. Use with
// [DeterministicHashFunc]. Options apply in supplied order, last-wins
// for repeated options.
type HashOption func(*hashConfig)

// WithAlgorithm selects the hash algorithm. Values outside the four
// supported constants silently clamp to [SHA256] so RuleFunc never
// panics on a bad enum value — garbage in, safe default out.
//
// Supported algorithms and their output prefixes:
//
//   - SHA256   → "sha256"   (default)
//   - SHA512   → "sha512"
//   - SHA3_256 → "sha3-256"
//   - SHA3_512 → "sha3-512"
//
// MD5 and SHA-1 are explicitly unsupported.
//
// Example:
//
//	h := mask.DeterministicHashFunc(mask.WithAlgorithm(mask.SHA512))
//	h("alice@example.com") // → "sha512:<hex16>"
func WithAlgorithm(a HashAlgorithm) HashOption {
	if a < 0 || a >= maxHashAlgorithm {
		a = SHA256
	}
	return func(c *hashConfig) {
		c.algo = a
	}
}

// WithKeyedSalt configures keyed (HMAC) hashing in one atomic step.
// Both salt and version are required; calling with either empty, or a
// version that violates the version grammar, marks the configuration
// misconfigured and every subsequent Apply returns [FullRedactMarker]
// — failing closed rather than silently producing hashes that look
// unsalted or differ across deployments.
//
// Output shape when both are configured:
//
//	<algo>:<version>:<first-16-hex>
//
// For example, `DeterministicHashFunc(WithKeyedSalt("k", "v1"))`
// applied to `"alice@example.com"` emits `sha256:v1:<hex16>` where
// `<hex16>` is the first 16 hex chars of HMAC-SHA256("k", …).
//
// Version grammar: the version MUST match `^[A-Za-z0-9._-]{1,32}$`.
// Colons, whitespace, non-ASCII characters, other punctuation, and
// versions longer than 32 bytes are rejected as a misconfiguration.
//
// Salt-rotation identification: if the operator changes the salt, the
// version MUST change too. Downstream consumers comparing hashes
// across rotations should match on the (algorithm, version) tuple —
// hashes with different versions are not comparable even when the
// underlying value is identical.
//
// Operational notes: the salt itself is never logged, echoed in
// output, returned in error messages, or exposed via [Describe]. Salt
// values live in in-memory Go strings and may appear in process core
// dumps or goroutine stacks — protect the process, not the library.
//
// Example:
//
//	h := mask.DeterministicHashFunc(mask.WithKeyedSalt(os.Getenv("MASK_SALT"), "v1"))
//	h("alice@example.com") // → "sha256:v1:<hex16>"
func WithKeyedSalt(salt, version string) HashOption {
	return func(c *hashConfig) {
		if salt == "" || !saltVersionPattern.MatchString(version) {
			c.misconfigured = true
			c.salt = ""
			c.version = ""
			return
		}
		// Last-wins: a valid WithKeyedSalt clears any previous
		// misconfiguration set by an earlier option in the same slice.
		c.salt = salt
		c.version = version
		c.misconfigured = false
	}
}

// resolveAlgo returns a valid [HashAlgorithm] for the given config, clamping
// out-of-range values to [SHA256]. This is a defence-in-depth guard — the
// option constructor already clamps on apply, but a future change that sets
// hashConfig.algo directly should not be able to panic the dispatch path.
func resolveAlgo(a HashAlgorithm) HashAlgorithm {
	if a < 0 || a >= maxHashAlgorithm {
		return SHA256
	}
	return a
}

// hashApply is the single dispatch point for all deterministic-hash
// callers. The misconfigured guard is checked FIRST — before any
// hashing work — so a bad salt/version configuration cannot reach the
// HMAC machinery even as a no-op. On the misconfigured path the
// marker is returned verbatim: no prefix, no colon, no digest.
//
// When salted, the output is "<prefix>:<version>:<first-16-hex>".
// When unsalted, it is "<prefix>:<first-16-hex>".
//
// The unsalted path hashes inline with the fixed-size `crypto.SumNNN`
// helpers so the digest never escapes the stack. The salted path
// uses `hmac.New` + `Sum(nil)`, which unavoidably allocates the
// hash state and the output digest, but still only two allocations
// total on the hot path.
func hashApply(cfg hashConfig, v string) string {
	if cfg.misconfigured {
		return FullRedactMarker
	}
	algo := resolveAlgo(cfg.algo)
	prefix := algoTable[algo].prefix
	capacity := len(prefix) + 1 + 16
	if cfg.salt != "" {
		capacity += len(cfg.version) + 1
	}
	dst := make([]byte, 0, capacity)
	dst = append(dst, prefix...)
	dst = append(dst, ':')
	if cfg.salt != "" {
		dst = append(dst, cfg.version...)
		dst = append(dst, ':')
	}
	if cfg.salt == "" {
		// Unsalted fast path: the stack-allocated [N]byte array does
		// not escape because we immediately hex-encode the first 8
		// bytes rather than returning a slice. The switch is
		// exhaustive against resolveAlgo's output — any other value is
		// a compile-time bug.
		switch algo {
		case SHA256:
			sum := sha256.Sum256([]byte(v))
			dst = hex.AppendEncode(dst, sum[:8])
		case SHA512:
			sum := sha512.Sum512([]byte(v))
			dst = hex.AppendEncode(dst, sum[:8])
		case SHA3_256:
			sum := sha3.Sum256([]byte(v))
			dst = hex.AppendEncode(dst, sum[:8])
		case SHA3_512:
			sum := sha3.Sum512([]byte(v))
			dst = hex.AppendEncode(dst, sum[:8])
		}
		return string(dst)
	}
	h := hmac.New(algoTable[algo].ctor, []byte(cfg.salt))
	h.Write([]byte(v))
	sum := h.Sum(nil)
	dst = hex.AppendEncode(dst, sum[:8])
	return string(dst)
}

// buildConfig applies opts to a fresh hashConfig. Validation is
// atomic inside each option (see [WithKeyedSalt]) — there is no
// cross-option reconcile phase.
func buildConfig(opts []HashOption) hashConfig {
	var cfg hashConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// DeterministicHash replaces v with a truncated SHA-256 hex digest of the
// input, prefixed with the algorithm name. The output is 23 bytes:
// "sha256:" plus 16 hexadecimal characters encoding the first 8 bytes of the
// digest.
//
// This primitive performs **pseudonymisation, not anonymisation**. The same
// input always produces the same output, which is the point — it lets a
// consumer correlate records without seeing the original value. The flip
// side is that anyone with the original value can compute the same digest,
// and the truncation to 64 bits means collisions are expected on corpora
// above roughly 10^9 distinct values (birthday bound 2^32).
//
// The input is hashed as its raw UTF-8 byte sequence. No Unicode
// normalisation is performed, so the NFC and NFD forms of the same string
// produce different outputs. Callers handling multilingual data should
// normalise before hashing.
//
// For a keyed variant or a different algorithm, build a [RuleFunc] via
// [DeterministicHashFunc] and invoke it:
//
//	h := mask.DeterministicHashFunc(mask.WithKeyedSalt("secret", "v1"))("alice@example.com")
//
// Example: DeterministicHash("alice@example.com") → "sha256:ff8d9819fc0e12bf".
func DeterministicHash(v string) string {
	return hashApply(hashConfig{algo: SHA256}, v)
}

// DeterministicHashFunc builds a [RuleFunc] that hashes its input according
// to the supplied options. The returned function is safe for concurrent use
// and captures a frozen [hashConfig] at construction time — later edits to
// the supplied options slice do not affect it.
//
// Zero-option use is guaranteed to produce output byte-identical to
// [DeterministicHash]; this equivalence is how the built-in `deterministic_hash`
// rule is registered without duplicating the SHA-256 code path.
//
// Example:
//
//	_ = m.Register("hashed_email", mask.DeterministicHashFunc(
//	    mask.WithKeyedSalt(os.Getenv("MASK_SALT"), "v1"),
//	    mask.WithAlgorithm(mask.SHA3_256),
//	))
func DeterministicHashFunc(opts ...HashOption) RuleFunc {
	cfg := buildConfig(opts)
	return func(v string) string {
		return hashApply(cfg, v)
	}
}
