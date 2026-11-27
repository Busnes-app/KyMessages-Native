#!/usr/bin/env bash
# Both browser cores are generated before tests, development and production builds.
set -euo pipefail
cd "$(dirname "$0")/.."
web/crypto/build.sh
bash scripts/build-pqwasm.sh
