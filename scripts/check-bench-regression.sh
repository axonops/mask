#!/usr/bin/env bash
# check-bench-regression.sh — parse a benchstat report and fail on regressions.
#
# Invoked by `make bench-regression` and by the benchstat-regression-guard CI
# job. The input is benchstat's default human-readable report comparing
# `bench.txt` (committed baseline) to `current.txt` (this run).
#
# Fail criteria (issue #17 AC):
#   - Any `time/op` regression >= 10% at p <= 0.05
#   - Any `allocs/op` regression > 0% (allocation increases are blocking
#     regardless of statistical significance).
#
# Bytes-per-op is treated the same as time/op (10% + p<=0.05) since a bytes
# increase without a commensurate allocs increase usually indicates a
# structural change worth reviewing.
#
# Exit codes:
#   0  no regressions above threshold
#   1  one or more regressions found
#   2  usage error (missing arg or file)

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <benchstat-report>" >&2
	exit 2
fi
report="$1"
if [[ ! -r "$report" ]]; then
	echo "cannot read $report" >&2
	exit 2
fi

threshold_pct=10
alpha="0.05"

violations=0
current_section=""

# benchstat (golang.org/x/perf/cmd/benchstat v0.0.0-20240730-ish) emits
# three tables, each introduced by a TWO-line header that looks like:
#
#     │ old.txt │  new.txt            │
#     │  sec/op │  sec/op    vs base  │
#
# The metric name lives on the second header line between box-drawing
# pipes. We detect it and set the current section. Any subsequent line
# with a "+X.XX%" delta is a regression candidate for that metric.
#
# Sections identified:
#   sec/op     — time per op (threshold: >= 10% at p <= 0.05)
#   B/op       — bytes per op (same threshold as time)
#   allocs/op  — allocation count per op (ANY increase fails)

while IFS= read -r line; do
	if [[ "$line" =~ [[:space:]](sec/op|B/op|allocs/op)[[:space:]] ]]; then
		current_section="${BASH_REMATCH[1]}"
		continue
	fi

	# Data line with a positive (regression) delta: "+X.XX%".
	if [[ "$line" =~ [+]([0-9]+)\.[0-9]+% ]]; then
		pct="${BASH_REMATCH[1]}"

		# Extract the p-value. benchstat emits "(p=0.XXX ...)" when both
		# sides have at least 4 samples and the difference is significant;
		# missing p values are treated as p=1 (not significant).
		p="1"
		if [[ "$line" =~ p=([0-9]+\.[0-9]+) ]]; then
			p="${BASH_REMATCH[1]}"
		fi

		flag_regression=0
		case "$current_section" in
			sec/op|B/op)
				if (( pct >= threshold_pct )) && awk -v p="$p" -v a="$alpha" 'BEGIN {exit !(p+0 <= a+0)}'; then
					flag_regression=1
				fi
				;;
			allocs/op)
				# Any measurable allocs/op increase is a regression.
				flag_regression=1
				;;
		esac

		if (( flag_regression == 1 )); then
			echo "::error::regression ($current_section): $line"
			violations=$((violations + 1))
		fi
	fi
done < "$report"

if (( violations > 0 )); then
	echo "benchstat found $violations regression(s) above threshold (time/op >=${threshold_pct}% at p<=${alpha}, or any allocs/op increase)" >&2
	exit 1
fi
echo "No regressions above threshold."
