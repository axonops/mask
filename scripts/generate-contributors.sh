#!/usr/bin/env bash
# generate-contributors.sh — turn signatures/version1/cla.json into a
# human-readable CONTRIBUTORS.md.
#
# The CLA Assistant workflow writes every signed CLA into the JSON
# file as an append-only list. This script regenerates the public
# list from that file, sorted deterministically so re-runs produce
# byte-identical output.
#
# Usage:
#   scripts/generate-contributors.sh [signatures-path] [output-path]
#
# Defaults:
#   signatures-path = signatures/version1/cla.json
#   output-path     = CONTRIBUTORS.md
#
# Exit codes:
#   0  success (wrote output-path)
#   2  signatures file missing or unreadable
#   3  jq not installed
#
# Called by .github/workflows/contributors.yml on pushes to main that
# touch the signatures file.

set -euo pipefail

signatures="${1:-signatures/version1/cla.json}"
output="${2:-CONTRIBUTORS.md}"

if ! command -v jq >/dev/null 2>&1; then
	echo "jq is required but not installed" >&2
	exit 3
fi

# An absent signatures file means no contributors have signed yet.
# We still emit a CONTRIBUTORS.md with the banner so the file exists
# from day one; the table is simply empty.
if [[ ! -f "$signatures" ]]; then
	signatures_empty=true
else
	signatures_empty=false
fi

{
	cat <<'HEADER'
# Contributors

Thank you to everyone who has signed the [Contributor License
Agreement](./CLA.md) and contributed to `github.com/axonops/mask`.

> This file is **auto-generated** from [`signatures/version1/cla.json`](./signatures/version1/cla.json)
> by `.github/workflows/contributors.yml` every time a new signature
> lands. Do not edit it by hand — edits are overwritten.

HEADER

	if [[ "$signatures_empty" == "true" ]]; then
		echo "_No contributors have signed yet. Be the first — open a pull request._"
		exit 0
	fi

	# Extract the signatures array; tolerate either shape CLA Assistant
	# Lite produces (`{signedContributors: [...]}` or bare array).
	entries=$(jq '
		if type == "object" and has("signedContributors") then .signedContributors
		elif type == "array" then .
		else []
		end' "$signatures")

	count=$(echo "$entries" | jq 'length')
	if [[ "$count" -eq 0 ]]; then
		echo "_No contributors have signed yet. Be the first — open a pull request._"
		exit 0
	fi

	echo "## Signatories"
	echo
	echo "| Contributor | GitHub | Signed (UTC) | First PR |"
	echo "|---|---|---|---|"

	# Sort by signed_at so the table has a stable, meaningful order
	# (oldest first). Unknown timestamps sort last.
	echo "$entries" | jq -r '
		map({
			name: (.name // .login // "unknown"),
			login: (.login // "unknown"),
			id: (.id // 0),
			signed: (.created_at // .signed_at // ""),
			pr: (.pull_request_no // .pullRequestNo // 0)
		})
		| sort_by(.signed)
		| .[]
		| "| \(.name) | [@\(.login)](https://github.com/\(.login)) | \(.signed[:10]) | [#\(.pr)](https://github.com/axonops/mask/pull/\(.pr)) |"
	'

	echo
	echo "---"
	echo
	echo "_${count} contributor$( [[ "$count" -eq 1 ]] || echo s ) so far. Full signature records live in [\`signatures/version1/cla.json\`](./signatures/version1/cla.json)._"
} > "$output"

echo "Wrote $output ($(wc -l < "$output") lines)"
