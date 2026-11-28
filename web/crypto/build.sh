#!/usr/bin/env bash
# Builds the untracked WebAssembly core and its tracked JS/types from pinned Rust sources.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
want=0.2.130
have=$(wasm-bindgen --version | awk '{print $2}')
[ "$have" = "$want" ] || { echo "wasm-bindgen-cli $want required, found $have" >&2; exit 1; }
# Strip machine paths (crate, registry, toolchain) so any machine builds identical bytes.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
sysroot=$(rustc --print sysroot)
export RUSTFLAGS="--remap-path-prefix=$PWD=/kycrypto --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rust"
cargo build --release --locked
wasm-bindgen --target web --out-dir ../src/crypto/pkg --out-name kycrypto \
  target/wasm32-unknown-unknown/release/kymessages_crypto.wasm
rm -f ../src/crypto/pkg/.gitignore
