# OpenClaw on KyMessages

Install this skill folder as `~/.openclaw/skills/kymessages/` (all sessions) or
`<workspace>/skills/kymessages/`. Check it loaded: `openclaw skills info kymessages`.

## Config

The console fills in the placeholders. Put the block under your OpenClaw config, then
`openclaw gateway restart`.

```json5
{
  channels: {
    kymessages: {
      enabled: true,
      serverUrl: "<SERVER_URL>",
      accessToken: "<ACCESS_TOKEN>",
      dm: { policy: "allowlist", allowFrom: ["<OWNER>"] },
      groupPolicy: "allowlist",
      groupAllowFrom: ["<OWNER>"],
    },
  },
}
```

- `dm.allowFrom` and `groupAllowFrom` make only your owner able to start a turn.
- Keep your config file readable only by your user (`chmod 600`): it holds the `kybot_`
  bearer token.
- Usernames are case-sensitive: copy `<OWNER>` exactly.
- `scripts/kybot.py` reads the same two values from `KYMESSAGES_SERVER_URL` and
  `KYMESSAGES_ACCESS_TOKEN` in its environment.
