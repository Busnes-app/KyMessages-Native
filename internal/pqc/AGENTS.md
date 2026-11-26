# Post-quantum primitives

## Purpose
Thin, vendored stand-ins for ky-primitives `xwing` and `hybridsig` (PQC Stack Plan,
Busnes-app/ky-primitives#80, "Shared code"), until those packages ship.

## Ownership
- `xwing/`: X-Wing keys from a 32-byte seed and `Seal(pub, info, aad, msg)` / `Open`: HPKE base
  mode, KEM 0x647A (`crypto/hpke.MLKEM768X25519`), HKDF-SHA256, AES-256-GCM; wire
  `version 1 ‖ enc (1120 B) ‖ ct`; public key 1216 B.
- `hybridsig/`: ML-DSA-65 (empty context, hedged) and pure Ed25519 over
  SHA-256(domain ‖ 0x00 ‖ msg); both halves required. kyguard-server `internal/pqcrypto/sig.go`'s
  construction. Seeds are 64 B (ML-DSA seed ‖ Ed25519 seed).

## Local Contracts
- Standard library only (Go 1.27 `crypto/hpke`, `crypto/mldsa`); no product logic here.
  KyMessages statements live in `internal/e2eeid`.
- Keep the APIs a subset of the ky-primitives plan, so swapping to
  `github.com/Busnes-app/ky-primitives/{xwing,hybridsig}` is an import change.
- Both packages also build for `js/wasm` (`web/pqc-wasm`).

## Verification
- `go test ./internal/pqc/...` (`xwing/testdata/xwing-vector.json` is the draft-ietf-hpke-pq
  vector copied from ky-primitives `recoverykey`, cross-checked against that package).
- `PATH="$(go env GOROOT)/lib/wasm:$PATH" GOOS=js GOARCH=wasm go test ./internal/pqc/...`

## Child DOX Index
None.
