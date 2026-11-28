#!/usr/bin/env bash
# Fails unless IMAGE holds a release build: its binary's build info names no kye2e tag, and a
# complete multi-tenant configuration ends in the release refusal.
# Usage: scripts/check-release-build.sh IMAGE
set -euo pipefail
image=${1:?usage: check-release-build.sh IMAGE}
work=$(mktemp -d)
cid=$(docker create "$image")
trap 'docker rm -f "$cid" >/dev/null; rm -rf "$work"' EXIT
docker cp "$cid:/app/kymessages" "$work/kymessages"

info=$(go version -m "$work/kymessages")
grep -q $'^\tpath\t' <<<"$info" || { echo "no Go build info in $image" >&2; exit 1; }
if grep -E $'^\tbuild\t-tags=' <<<"$info" | grep -qw kye2e; then
  echo "$image was built with the kye2e tag:" >&2; grep -E $'^\tbuild\t-tags=' <<<"$info" >&2; exit 1
fi

# Everything multi mode requires, with a .test issuer, so only the release gate can refuse it.
printf '%s\n' "$(printf 'ef%.0s' {1..32})" >"$work/seal.key"
chmod 0600 "$work/seal.key" # keyfile wants it private and owned by the server's uid
want='KY_TENANCY_MODE=multi: multi-tenant mode is unavailable in this release'
set +e
out=$(docker run --rm --network none --user "$(id -u):$(id -g)" -v "$work/seal.key:/run/seal.key:ro,z" \
  -e KY_TENANCY_MODE=multi -e KY_DB_DRIVER=postgres -e KY_DB_DSN=postgres://ky@127.0.0.1/ky \
  -e KY_STAFF_ORG_ID=00000000-0000-4000-8000-000000000001 -e KY_CELLS=e2e-1 \
  -e KY_SESSION_SECRET=release-check-session-secret-0123456789 \
  -e KY_ENCRYPTION_KEY="$(printf 'ab%.0s' {1..32})" -e KY_PUSH_ENABLED=false -e PUSH_RELAY_URL= -e APNS_RELAY_URL= \
  -e KY_KYIDENTITY_ISSUER=https://id.e2e.test \
  -e KY_ATTACHMENTS_S3_ENDPOINT=https://objects.e2e.test -e KY_ATTACHMENTS_S3_REGION=us-east-2 \
  -e KY_ATTACHMENTS_S3_BUCKET=kymessages -e KY_ATTACHMENTS_S3_ACCESS_KEY=release-check \
  -e KY_ATTACHMENTS_S3_SECRET=release-check -e KY_ATTACHMENTS_S3_SEAL_KEY_FILE=/run/seal.key \
  "$image" 2>&1)
code=$?
set -e
if [ "$code" -eq 0 ] || ! grep -qF "$want" <<<"$out"; then
  echo "$image did not refuse multi mode (exit $code):" >&2; echo "$out" >&2; exit 1
fi
echo "$image: release build, refuses multi mode"
