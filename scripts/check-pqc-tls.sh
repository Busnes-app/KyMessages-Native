#!/usr/bin/env bash
# Keep Go's default hybrid post-quantum TLS key exchange (X25519MLKEM768) active:
# refuse classical CurvePreferences overrides in non-test Go code, refuse tlsmlkem
# overrides in non-test code / workflows / Dockerfiles / Compose, and prove the
# outbound TLS transport negotiates X25519MLKEM768 normally and under FIPS mode.
set -euo pipefail
cd "$(dirname "$0")/.."

if hits=$(git grep -n 'CurvePreferences' -- '*.go' ':!*_test.go'); then
  echo "CurvePreferences is forbidden in non-test Go code:" >&2
  echo "$hits" >&2
  exit 1
fi

if hits=$(git grep -ni 'tlsmlkem' -- . ':!*_test.go' ':!*.md' ':!scripts/check-pqc-tls.sh'); then
  echo "tlsmlkem override is forbidden outside tests and docs:" >&2
  echo "$hits" >&2
  exit 1
fi

PUSH_RELAY_URL="" APNS_RELAY_URL="" go test -count=1 -run '^TestOutboundPQTLS$' ./internal/push
PUSH_RELAY_URL="" APNS_RELAY_URL="" GODEBUG="${GODEBUG:+${GODEBUG},}fips140=on" go test -count=1 -run '^TestOutboundPQTLS$' ./internal/push

echo "PQC hybrid TLS guard passed"
