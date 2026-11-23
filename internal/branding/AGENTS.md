# Branding

## Purpose
Pure checks behind the console's product name and logo.

## Ownership
Owns `branding.go`: `ValidateName` and `NormalizePNG`.
`internal/api` owns the routes, storage, and `/app-icon.png`.

## Local Contracts
- `ValidateName` trims, then accepts 1–64 runes (`MaxNameRunes`) of valid UTF-8 with no
  control (Cc), format (Cf: bidi overrides and isolates, zero-width characters, BOM) or
  line/paragraph separator (Zl, Zp) character. ZWJ emoji sequences are therefore refused.
- `NormalizePNG` accepts at most `MaxLogoBytes` (1 MiB) starting with the PNG signature, reads
  the dimensions with `png.DecodeConfig` and refuses zero or more than `MaxLogoSide` (1024)
  before decoding, then decodes and re-encodes, so no ancillary chunk (text, EXIF, ICC, APNG)
  survives. Every other format is refused (SVG can carry script); so is a re-encoding over
  `MaxLogoBytes`.
- No logging, store access or network.

## Verification
- `go test -race ./internal/branding/`

## Child DOX Index
None.
