#!/usr/bin/env bash
# The release publisher refuses a tag unless every CI job it names passed on that commit.
# Every job in ci.yml must be in its REQUIRED list, or a failing job could ship.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# The first "name:" inside each job is its check name.
jobs=$(awk '/^jobs:/{j=1;next} j && /^  [a-z0-9_-]+:$/{want=1;next} want && /^    name: /{sub(/^    name: */,""); print; want=0}' "$root/.github/workflows/ci.yml")
required=$(awk '/REQUIRED: \|/{r=1;next} r && /^ {12}[^ ]/{sub(/^ +/,""); print; next} r{exit}' "$root/.github/workflows/release-image.yml")
missing=$(comm -23 <(sort <<<"$jobs") <(sort <<<"$required"))
[ -n "$jobs" ] && [ -n "$required" ] || { echo "could not read the job lists" >&2; exit 1; }
if [ -n "$missing" ]; then
  echo "CI jobs missing from release-image.yml REQUIRED:" >&2; echo "$missing" >&2; exit 1
fi
echo "release REQUIRED covers all $(wc -l <<<"$jobs") CI jobs"
