# Post-quantum primitives

## Purpose
ky-primitives `xwing` (PR #83 @ cc038a1f) and `hybridsig` (PR #84 @ ead9d5da), vendored verbatim
with their tests and vectors until those PRs merge (PQC Stack Plan, Busnes-app/ky-primitives#80).

## Ownership
- `xwing/`: X-Wing keys from a 32-byte seed and `Seal(pub, info, aad, msg)` / `Open`: HPKE base
  mode, KEM 0x647A, HKDF-SHA256, AES-256-GCM; wire `version 1 ‖ enc (1120 B) ‖ ct`; info must
  start with a non-empty caller label.
- `hybridsig/`: ML-DSA-65 (empty context, hedged) and pure Ed25519 over
  SHA-256(label ‖ 0x00 ‖ msg); both halves required; keys and signatures tagged
  `"mldsa65+ed25519" 0x00 ‖ halves`.

## Local Contracts
- Never edit these files: replace them with a newer upstream copy, or delete the directory and
  import `github.com/Busnes-app/ky-primitives/{xwing,hybridsig}` once merged (an import change
  in `internal/e2eeid` and `internal/api` only). Only the tests' import paths and the draft
  vector's path (`xwing/testdata/xwing-vector.json`) differ from upstream.
- KyMessages statements live in `internal/e2eeid`. Both packages also build for `js/wasm`.

## Verification
- `go test ./internal/pqc/...` runs upstream's tests and `testdata/vectors.json`
  (`xwing/testdata/xwing-vector.json` is ky-primitives `recoverykey`'s draft-ietf-hpke-pq vector).
- `PATH="$(go env GOROOT)/lib/wasm:$PATH" GOOS=js GOARCH=wasm go test ./internal/pqc/...`

## Child DOX Index
None.
