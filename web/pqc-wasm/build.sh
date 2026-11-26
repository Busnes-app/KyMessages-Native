#!/usr/bin/env bash
# Builds web/src/pqc/pqc.wasm and copies the toolchain's wasm_exec.js beside it. The build is
# reproducible for one Go version (go.mod's toolchain line): CI rebuilds and diffs both files.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=web/src/pqc
GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$out/pqc.wasm" ./web/pqc-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$out/wasm_exec.js"
chmod 0644 "$out/pqc.wasm" "$out/wasm_exec.js"
