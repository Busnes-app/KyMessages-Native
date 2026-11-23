# Health

## Purpose
Probes KyMessages, its database, and optional LiveKit SFU once per request.

## Ownership
Owns `Check`, `NewHTTPClient`, and the `LiveKit` probe in `health.go`. `internal/api` builds the probe list.

## Local Contracts
- Probes run in parallel, each under its own timeout; `Check` returns in probe order and by the deadline even if a probe ignores its context (reported down, "timed out"). No history.
- Every probe must honour its context: one that ignores it keeps its goroutine running until it returns.
- `up` means the component answered its liveness check. A version that cannot be read is "up, version unknown".
- `NewHTTPClient` ignores proxy variables and follows no redirects. `Check` redacts every secret passed to it from error strings before clipping them.
- `LiveKit` probes the LiveKit HTTP endpoint (`ws`/`wss` rewritten to `http`/`https`) and reports status with version unknown.

## Verification
- `go test -race ./internal/health/...`
