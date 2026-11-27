#!/usr/bin/env bash
# Compile the pinned shared pqwasm command with the product's identity-format adapter. Stage
# upstream sources only during the build: never vendor crypto or commit generated WASM.
set -euo pipefail
cd "$(dirname "$0")/.."
# Select the exact upstream toolchain, including on hosts with a distro-patched Go build.
GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
export GOTOOLCHAIN
export GOEXPERIMENT=""
go mod download github.com/Busnes-app/ky-primitives
shared=$(go list -m -f '{{.Dir}}' github.com/Busnes-app/ky-primitives)
stage=$(mktemp -d "$PWD/web/.pqwasm-build.XXXXXX")
trap 'rm -rf "$stage"' EXIT
for source in "$shared"/cmd/pqwasm/*.go; do
  [[ "$source" == *_test.go ]] || cp "$source" "$stage/"
done
cp internal/e2eeid/pqwasm/identity.go "$stage/"
GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid=' -o web/src/pqc/pqc.wasm "$stage/"*.go
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/src/pqc/wasm_exec.js
chmod 0644 web/src/pqc/pqc.wasm web/src/pqc/wasm_exec.js
