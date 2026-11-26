# E2EE identity layer

## Purpose
KyMessages' post-quantum identity and recovery formats (E3,
`docs/superpowers/specs/2026-11-22-e2ee-design.md` §3.1): the statements the hybrid master key
signs, the fingerprint, the recovery key and its wraps, the synced pin set, the key backup seal
and the two-layer QR transfer.

## Ownership
- `e2eeid.go`: the formats, over `internal/pqc/xwing` and `internal/pqc/hybridsig`.
- `call.go`: `Call(name, args)`, the string API (unpadded base64; base64url for pairing IDs and
  QR text) that `web/pqc-wasm` exposes to the browser as `kyPQCCall`.

## Local Contracts
- The server and the browser run this same code; never re-implement an encoding in TypeScript.
- Every field list goes through `Fields` (uint32 length prefixes) and every use has its own
  versioned label. A changed byte is a new label version, never an edit in place.
- `testdata/vectors.json` is the shared contract: Go tests and `web/src/pqc/pqc.test.ts` run it.
  Regenerate only for an intended format change (`go test ./internal/e2eeid -run TestSharedVectors
  -update`), then rebuild the WebAssembly (`web/pqc-wasm/build.sh`).

## Verification
- `go test ./internal/e2eeid/`, and the same under `GOOS=js GOARCH=wasm` (CI job "PQC core").

## Child DOX Index
None.
