# Agent skill

## Purpose
Ships the `kymessages` skill that chat agents (OpenClaw, Hermes Agent) load to connect to
KyMessages and behave in its rooms, and fills each runtime's config block for the console.

## Ownership
Owns `kymessages/` (the skill: `SKILL.md`, `references/<runtime>.md`, and the bot's encrypted
device `scripts/kybot.py` with `scripts/requirements.txt`), `skill.go` (`go:embed`, `Config`,
`Zip`) and `tests/` (kept out of the zip). The agent routes in `internal/api` serve both.

## Local Contracts
- One folder, the agentskills `SKILL.md` format both runtimes load. Frontmatter `name` stays
  `kymessages`, equal to the folder name: Hermes skips a skill whose name differs.
- The skill holds no secret and no install-specific value; it advises the agent, and nothing
  security-relevant depends on the agent following it (scope, lock, revoke and expiry are
  server-side).
- Each `references/<runtime>.md`'s first fenced block is that runtime's config block with the
  placeholders `<SERVER_URL>`, `<ACCESS_TOKEN>`, `<OWNER>`. `Config` fills them and is the only
  source of the console's config blocks; it refuses values holding quotes, whitespace, `#`,
  `\`, `` ` `` or `$`. `Runtimes` lists the runtimes with a reference file.
- Blocks authenticate with a `kybot_` bearer token and restrict instructions to the owner
  (`dm.allowFrom` and `groupAllowFrom` in OpenClaw; `KYMESSAGES_ALLOWED_USERS` in Hermes).

- `scripts/kybot.py` (E4) is the bot's end-to-end encrypted device: its keys live only in its
  0600 state file. It re-implements no format of its own: the identity statements, fingerprint
  and `hash` follow `internal/e2eeid` (checked against `internal/e2eeid/testdata/vectors.json`),
  files follow A256GCM-STREAM v1 (`web/src/crypto/attachments.test.ts` vectors), and the device
  code follows `engine.ts` `botDeviceCode` (one vector pinned on both sides). Its trust rules are
  the browser's: TOFU-pinned self-bound master keys, only cross-signed devices on the newest
  signed list (a bot only through its owner's `kymessages.bot-devices.v1` list), lists only move
  forward, room keys only from such devices, a changed identity waits for `accept` (even if the
  server goes back to the old key). It also pins its org and each bot's owner on first sight;
  room-key mail counts as shared only once delivered. A message that fails any check is that
  message's error alone; an E5 edit's files come from the first envelope it names (`ref`, count).
  One command runs at a time per state file (`<state>.lock`). Change both
  sides together.

## Verification
- `go test ./agent-skill/`
- `python3 -B -m unittest discover -s agent-skill/tests` with `scripts/requirements.txt` installed
  (CI step "Bot bundle (Python)", which also runs Olm/Megolm against `web/src/crypto/pkg` via
  `tests/interop.mjs`; `KYBOT_REQUIRE_INTEROP=1` fails rather than skips without it).
- `tests/live_e2e.py` against a throwaway server (`KYBOT_LIVE_URL`, `KYBOT_LIVE_ADMIN_PASSWORD`).

## Child DOX Index
None.
