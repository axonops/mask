#!/usr/bin/env bash
# gen-llms-full.sh — regenerate llms-full.txt from the canonical source
# files (llms.txt, README.md, doc.go, CONTRIBUTING.md, SECURITY.md,
# docs/rules.md, docs/extending.md, and the full godoc output) in a
# stable order.
#
# The script is idempotent: running it twice produces no diff.
# `llms-full.txt` is the single concatenated corpus an AI assistant can
# ingest to understand the library without crawling individual files.
# CI runs this script and fails the build if the committed
# `llms-full.txt` differs from the regenerated output.
#
# Source file order:
#   1. llms.txt
#   2. README.md
#   3. doc.go (package comment only)
#   4. CONTRIBUTING.md
#   5. SECURITY.md
#   6. docs/rules.md
#   7. docs/extending.md
#   8. go doc -all github.com/axonops/mask

set -euo pipefail

# Run from the repo root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

out="llms-full.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Deterministic header. We intentionally do NOT embed the current git
# SHA or a timestamp in the output — a CI diff check would fail on
# every run otherwise. The header is a stable banner; CI asserts
# byte-equality between the committed file and a freshly regenerated
# one.
cat > "$tmp" <<'HEADER'
# mask — full documentation bundle

This file is the concatenated corpus of every human-facing source of
truth for `github.com/axonops/mask`: the `llms.txt` summary, the
README, the package godoc, contributor and security guidance, the
authoritative rule-catalogue requirements, and the full generated
godoc reference. It exists so AI assistants (and humans ingesting
offline) can read the entire library's documentation in a single
file without crawling the repo.

Regenerate with `make llms-full`. CI fails the build if the
committed file is out of date relative to its sources.

HEADER

section() {
	local title="$1"
	local path="$2"
	printf '\n---\n\n# %s\n\n' "$title" >> "$tmp"
	if [[ "$path" == "godoc" ]]; then
		# Pull the full godoc for the package. We don't want the
		# tool's output to depend on where the user ran the script
		# from (it shouldn't, since we `cd` to repo root first), but
		# we still sanitise any absolute path references.
		go doc -all ./. >> "$tmp"
	elif [[ "$path" == "doc.go-comment" ]]; then
		# Emit only the package comment block from doc.go (skipping
		# the license header and the `package mask` line).
		awk '
			/^package mask/ { exit }
			/^\/\// { sub(/^\/\/ ?/, ""); print }
		' doc.go >> "$tmp"
	else
		cat "$path" >> "$tmp"
	fi
}

section "llms.txt" "llms.txt"
section "README.md" "README.md"
section "Package godoc (doc.go)" "doc.go-comment"
section "CONTRIBUTING.md" "CONTRIBUTING.md"
section "SECURITY.md" "SECURITY.md"
section "docs/rules.md" "docs/rules.md"
section "docs/extending.md" "docs/extending.md"
section "Full godoc reference (go doc -all)" "godoc"

# Ensure a single trailing newline.
printf '\n' >> "$tmp"

mv "$tmp" "$out"
trap - EXIT

echo "Wrote $out ($(wc -l < "$out") lines, $(wc -w < "$out") words)"
