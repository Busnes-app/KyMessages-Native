# E2EE identity layer

## Purpose
KyMessages' post-quantum identity and recovery formats (E3,
`docs/superpowers/specs/2026-11-22-e2ee-design.md` §3.1): the statements the hybrid master key
signs, the fingerprint, the recovery key and its wraps, the synced pin set, the key backup seal
and the two-layer QR transfer.

## Ownership
- `e2eeid.go`: the formats, over `ky-primitives/xwing` and `ky-primitives/hybridsig`.
- Statements signed by the master key: `kymessages.master.v1`, `.device.v2`, `.backup-key.v1`,
  `.device-list.v1`, `.pins-write.v1` and `.backup-write.v1` (`BackupWrite` builds the last from
  API entries and the backup generation, so the server and the browser sign the same bytes).
  `DeviceListDigest` names a proposed list for its reservation (the browser's `hash` of the same
  fields), which the master key signs as `DeviceListReserveMessage` under
  `.device-list-reserve.v1`. `BotDevicesMessage` (`.bot-devices.v1`, E4) is an owner's signature over their bot's devices and keys at an epoch. `ComparisonCode` binds the joining device's ID as well as its ephemeral key.
- `call.go`: `Call(name, args)`, the string API (unpadded base64; base64url for pairing IDs and
  QR text) that the product adapter exposes to the browser as `kyPQCCall`.
- `pqwasm/identity.go`: product wire adapter compiled with the pinned `ky-primitives/cmd/pqwasm`
  sources by `scripts/build-pqwasm.sh`. The script stages upstream sources only during the build;
  the shared command owns primitive exports and runtime entry, the adapter owns `kyPQCReady`.
  The build selects go.mod's exact upstream `GOTOOLCHAIN` and clears host `GOEXPERIMENT`
  overrides so asset hashes match CI.

## Local Contracts
- The server and the browser run this same code; never re-implement an encoding in TypeScript.
- Every field list goes through `Fields` (uint32 length prefixes) and every use has its own
  versioned label. A changed byte is a new label version, never an edit in place.
- `testdata/vectors.json` is the shared contract: Go tests and `web/src/pqc/pqc.test.ts` run it.
  Regenerate only for an intended format change (`go test ./internal/e2eeid -run TestSharedVectors
  -update`), then rebuild the WebAssembly (`scripts/build-pqwasm.sh`).

## Verification
- `go test ./internal/e2eeid/`, and the same under `GOOS=js GOARCH=wasm` (CI job "PQC core").

## Child DOX Index
None.
