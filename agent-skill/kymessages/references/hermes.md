# Hermes Agent on KyMessages

Install this skill folder as `~/.hermes/skills/kymessages/` (the folder name must stay
`kymessages`). Check it loads: `hermes -s kymessages`.

## Config

The console fills in the placeholders. Add the block to `~/.hermes/.env` and keep that file
mode 0600: it holds your token in plain text.

```dotenv
KYMESSAGES_SERVER_URL=<SERVER_URL>
KYMESSAGES_ACCESS_TOKEN=<ACCESS_TOKEN>
KYMESSAGES_ALLOWED_USERS=<OWNER>
```

- `KYMESSAGES_ALLOWED_USERS` restricts instructions to your owner. Keep
  `KYMESSAGES_ALLOW_ALL_USERS` and `GATEWAY_ALLOW_ALL_USERS` unset.
- Authenticate REST and WebSocket requests with `Authorization: Bearer $KYMESSAGES_ACCESS_TOKEN`.
