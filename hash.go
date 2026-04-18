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
	"hash"
	"regexp"
)

// saltVersionPattern is the grammar a WithSalt version string must match.
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

// String returns the on-the-wire prefix for a.
// Values outside the defined constants return the default "sha256".
func (a HashAlgorithm) String() string {
	if a < 0 || a >= maxHashAlgorithm {
		return algoTable[SHA256].prefix
	}
	return algoTable[a].prefix
}

// hashConfig is the effective configuration produced by applying zero or more
// [HashOption] values. The zero value corresponds to "unsalted SHA-256".
//
// misconfigured is a sticky, write-once flag: once set to true it cannot be
// cleared by a later option. Any caller who specifies a salt without a
// conforming version (or vice versa) misconfigures the rule once and every
// subsequent Apply emits [FullRedactMarker] verbatim. This prevents a
// pattern like `WithSalt("k","bad"), WithSalt("k","v1")` from silently
// re-enabling hashing with an earlier-specified invalid configuration.
type hashConfig struct {
	algo          HashAlgorithm
	salt          string // empty string means "no salt" — see WithSalt godoc
	version       string // salt version; required iff salt != ""
	saltSet       bool   // true once WithSalt has been applied at least once
	versionSet    bool   // true once WithSaltVersion has been applied at least once
	misconfigured bool   // sticky; once true, hashApply emits FullRedactMarker
}

// reconcile runs after either [WithSalt] or [WithSaltVersion] has been
// applied. It defers final validation until both halves have been set at
// least once in this factory call, then checks consistency. Any violation
// after both are set flags the sticky misconfigured state: the salt and
// version are cleared and every subsequent Apply emits [FullRedactMarker]
// until a fresh factory call rebuilds the config.
func (c *hashConfig) reconcile() {
	if !c.saltSet || !c.versionSet {
		return
	}
	if c.salt == "" {
		// Unsalted path — orphan version is ignored in the output.
		return
	}
	if !saltVersionPattern.MatchString(c.version) {
		c.misconfigured = true
		c.salt = ""
		c.version = ""
	}
}

// HashOption configures the deterministic-hash primitives. Use with
// [DeterministicHashFunc]. Options apply in supplied order, last-wins for
// repeated options.
type HashOption func(*hashConfig)

// WithAlgorithm selects the hash algorithm. Values outside the four
// supported constants silently clamp to [SHA256] so RuleFunc never panics on
// a bad enum value — garbage in, safe default out.
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

// WithSalt sets the HMAC salt for keyed hashing. Combine with
// [WithSaltVersion] to enable keyed output: a salted hash without
// a configured version (or with a version that violates the
// version grammar) is a misconfiguration and fails closed on every
// subsequent Apply — see the package documentation for the full
// policy.
//
// WithSalt("") is the unsalted path — the primitive emits
// `<algo>:<first-16-hex>` with no version segment.
//
// The salt itself is never logged, echoed in output, returned in
// error messages, or exposed via [Describe].
//
// Operational note: salt values live in in-memory Go strings and
// may appear in process core dumps or goroutine stacks. Protect
// the process, not the library.
//
// Example:
//
//	h := mask.DeterministicHashFunc(
//	    mask.WithSalt("my-secret-salt"),
//	    mask.WithSaltVersion("v1"),
//	)
//	h("alice@example.com") // → "sha256:v1:<hex16>"
func WithSalt(salt string) HashOption {
	return func(c *hashConfig) {
		if c.misconfigured {
			return // sticky; later options cannot clear a prior misconfiguration
		}
		c.salt = salt
		c.saltSet = true
		c.reconcile()
	}
}

// WithSaltVersion sets the salt-version identifier emitted on the
// wire alongside the hash so downstream consumers can identify
// which salt generation produced a given hash. Combine with
// [WithSalt] to enable keyed hashing.
//
// Output shape when both salt and version are configured:
//
//	<algo>:<version>:<first-16-hex>
//
// For example, `DeterministicHashFunc(WithSalt("k"), WithSaltVersion("v1"))`
// applied to "alice@example.com" emits `sha256:v1:<hex16>` where
// <hex16> is the first 16 hex chars of HMAC-SHA256("k", "alice@example.com").
//
// Version grammar: the version MUST match `^[A-Za-z0-9._-]{1,32}$`.
// Colons, whitespace, non-ASCII characters, other punctuation, and
// versions longer than 32 bytes are rejected. A misconfiguration
// (salt set without a conforming version, or a version set without
// a salt) sets a sticky flag on the hashConfig and every
// subsequent Apply emits [FullRedactMarker]. This fail-closed
// policy prevents an operator who typoed the version from
// silently producing hashes indistinguishable from the unsalted
// path.
//
// Salt-rotation identification: if the operator changes the salt
// in their process, the version MUST change too. Downstream
// consumers comparing hashes across salt rotations should match on
// the (algorithm, version) tuple — hashes with different versions
// are not comparable even when the underlying value is identical.
//
// Example:
//
//	h := mask.DeterministicHashFunc(
//	    mask.WithSalt("my-secret-salt"),
//	    mask.WithSaltVersion("v1"),
//	)
//	h("alice@example.com") // → "sha256:v1:<hex16>"
func WithSaltVersion(version string) HashOption {
	return func(c *hashConfig) {
		if c.misconfigured {
			return
		}
		c.version = version
		c.versionSet = true
		c.reconcile()
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

// hashSumUnsalted returns the raw digest of v using the selected algorithm.
// The unsalted path uses the fixed-size Sum* functions, which do not allocate
// a [hash.Hash] on the heap.
func hashSumUnsalted(algo HashAlgorithm, v string) []byte {
	switch algo {
	case SHA256:
		sum := sha256.Sum256([]byte(v))
		return sum[:]
	case SHA512:
		sum := sha512.Sum512([]byte(v))
		return sum[:]
	case SHA3_256:
		sum := sha3.Sum256([]byte(v))
		return sum[:]
	case SHA3_512:
		sum := sha3.Sum512([]byte(v))
		return sum[:]
	default:
		// Unreachable because callers pass resolveAlgo'd values. Fall back
		// safely.
		sum := sha256.Sum256([]byte(v))
		return sum[:]
	}
}

// hashSumSalted returns HMAC(salt, v) using the selected algorithm. The algo
// value is clamped to a valid entry by [resolveAlgo] on the calling path,
// but we clamp again here so any future direct caller can't panic on an
// out-of-range index — this mirrors the defensive fallback in
// [hashSumUnsalted].
func hashSumSalted(algo HashAlgorithm, salt, v string) []byte {
	algo = resolveAlgo(algo)
	h := hmac.New(algoTable[algo].ctor, []byte(salt))
	h.Write([]byte(v))
	return h.Sum(nil)
}

// hashApply is the single dispatch point for all deterministic-hash callers.
// The misconfigured guard is checked FIRST — before any hashing work — so
// a bad salt/version configuration cannot reach the HMAC machinery even
// as a no-op. On the misconfigured path the marker is returned verbatim:
// no prefix, no colon, no digest.
//
// When salted, the output is "<prefix>:<version>:<first-16-hex>".
// When unsalted, it is "<prefix>:<first-16-hex>".
func hashApply(cfg hashConfig, v string) string {
	if cfg.misconfigured {
		return FullRedactMarker
	}
	algo := resolveAlgo(cfg.algo)
	var sum []byte
	if cfg.salt == "" {
		sum = hashSumUnsalted(algo, v)
	} else {
		sum = hashSumSalted(algo, cfg.salt, v)
	}
	// Defence against a future algorithm with a shorter digest. Every
	// currently supported algorithm emits ≥ 32 bytes, so this branch
	// is unreachable with the present algoTable — it exists only so a
	// future addition of a shorter-digest algorithm cannot index out of
	// bounds at `sum[:8]`. If such an algorithm is ever added, update
	// this path to emit the versioned shape when salted.
	if len(sum) < 8 {
		return algoTable[algo].prefix + ":"
	}
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
	dst = hex.AppendEncode(dst, sum[:8])
	return string(dst)
}

// buildConfig applies opts to a fresh hashConfig and finalises the
// consistency check between salt and version. Options set salt and
// version independently so they can appear in any order; the final
// validate call after all options have been applied is what sets the
// sticky misconfigured flag if the combination is inconsistent.
func buildConfig(opts []HashOption) hashConfig {
	var cfg hashConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	// Final guard: a salt configured without ever pairing it with a
	// version is also a misconfiguration. reconcile() defers until
	// both halves are seen, so this case needs a terminal check.
	if !cfg.misconfigured && cfg.saltSet && cfg.salt != "" && !cfg.versionSet {
		cfg.misconfigured = true
		cfg.salt = ""
		cfg.version = ""
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
//	h := mask.DeterministicHashFunc(
//	    mask.WithSalt("secret"),
//	    mask.WithSaltVersion("v1"),
//	)("alice@example.com")
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
//	    mask.WithSalt(os.Getenv("MASK_SALT")),
//	    mask.WithSaltVersion("v1"),
//	    mask.WithAlgorithm(mask.SHA3_256),
//	))
func DeterministicHashFunc(opts ...HashOption) RuleFunc {
	cfg := buildConfig(opts)
	return func(v string) string {
		return hashApply(cfg, v)
	}
}
