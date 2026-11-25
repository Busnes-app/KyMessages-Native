#!/usr/bin/env bash
# The kye2e build tag opens multi-tenant startup (internal/config/gate_kye2e.go), so it may
# appear only in the gate files and their test twins, e2e/ and these checks. Release build
# inputs carry no build tags at all: a TAGS or GOFLAGS argument could pass kye2e unnamed.
set -euo pipefail
cd "$(dirname "$0")/.."
allowed='^(internal/config/gate_(release|kye2e)(_test)?\.go|e2e/.*|scripts/check-(build-tags|release-build)\.sh|\.github/workflows/ci\.yml|.*\.md)$'
bad=$(git grep -l kye2e -- . | grep -Ev "$allowed" || true)
if [ -n "$bad" ]; then
  echo "kye2e outside the gate files and checks:" >&2; echo "$bad" >&2; exit 1
fi
mapfile -t release < <(git ls-files 'Dockerfile*' '*/Dockerfile*' Makefile 'docker-compose*.yml' .github/workflows/release-image.yml)
[ "${#release[@]}" -gt 0 ] || { echo "no release build inputs found" >&2; exit 1; }
if hits=$(git grep -nE -e '(^|[^[:alnum:]_-])--?tags|kye2e|GOFLAGS' -- "${release[@]}"); then
  echo "build tags in a release build input:" >&2; echo "$hits" >&2; exit 1
fi
echo "kye2e confined to the gate files and checks"
