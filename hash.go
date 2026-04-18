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
)

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
type hashConfig struct {
	algo HashAlgorithm
	salt string // empty string means "no salt" — see WithSalt godoc
}

// HashOption configures the deterministic-hash primitives. Use with
// [DeterministicHashWith] and [DeterministicHashFunc]. Options apply in
// supplied order, last-wins for repeated options.
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
func WithAlgorithm(a HashAlgorithm) HashOption {
	if a < 0 || a >= maxHashAlgorithm {
		a = SHA256
	}
	return func(c *hashConfig) {
		c.algo = a
	}
}

// WithSalt enables keyed hashing via HMAC. When a non-empty salt is supplied,
// the primitive emits HMAC(salt, value) using the selected algorithm.
//
// An empty salt string is treated as "no salt" and the primitive emits
// unsalted hash(value). This collapse is deliberate: HMAC with an empty key
// is technically valid but provides no keying material and would be a
// cryptographic footgun disguised as an intentional choice. If you truly
// want empty-key HMAC, use the crypto/hmac package directly.
//
// The salt MUST remain constant for the lifetime of the process. Rotating it
// breaks determinism, and therefore breaks the correlation properties that
// are the reason this primitive exists. Salt values are never logged, echoed
// in output, returned in error messages, or exposed via [Describe].
//
// Operational note: the salt is an in-memory Go string and may appear in
// process core dumps or goroutine stacks. Protect the process, not the
// library.
func WithSalt(salt string) HashOption {
	return func(c *hashConfig) {
		c.salt = salt
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
// It branches on whether a salt is present, runs the chosen primitive, and
// emits "<prefix>:<first-16-hex>".
func hashApply(cfg hashConfig, v string) string {
	algo := resolveAlgo(cfg.algo)
	var sum []byte
	if cfg.salt == "" {
		sum = hashSumUnsalted(algo, v)
	} else {
		sum = hashSumSalted(algo, cfg.salt, v)
	}
	// Defence against a future algorithm with a shorter digest. Every
	// currently supported algorithm produces ≥ 32 bytes.
	if len(sum) < 8 {
		return algoTable[algo].prefix + ":"
	}
	prefix := algoTable[algo].prefix
	dst := make([]byte, 0, len(prefix)+1+16)
	dst = append(dst, prefix...)
	dst = append(dst, ':')
	dst = hex.AppendEncode(dst, sum[:8])
	return string(dst)
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
// For a keyed variant or a different algorithm, use [DeterministicHashWith]
// or build a [RuleFunc] via [DeterministicHashFunc].
//
// Example: DeterministicHash("alice@example.com") → "sha256:559aead08264d592".
func DeterministicHash(v string) string {
	return hashApply(hashConfig{algo: SHA256}, v)
}

// DeterministicHashWith is the parametric direct-call variant of
// [DeterministicHash]. Options apply in supplied order, last-wins.
//
// This helper is for one-off ad-hoc use. Hot paths should construct a
// [RuleFunc] once via [DeterministicHashFunc] and reuse it — a `...HashOption`
// variadic is allocated on every call here.
//
// Example:
//
//	h := mask.DeterministicHashWith("alice", mask.WithAlgorithm(mask.SHA512))
//	// h == "sha512:..."
func DeterministicHashWith(v string, opts ...HashOption) string {
	var cfg hashConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return hashApply(cfg, v)
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
//	    mask.WithAlgorithm(mask.SHA3_256),
//	))
func DeterministicHashFunc(opts ...HashOption) RuleFunc {
	var cfg hashConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(v string) string {
		return hashApply(cfg, v)
	}
}
