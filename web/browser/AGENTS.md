# Browser regressions

## Purpose

Exercise the built embedded frontend through Chromium and Firefox with the real Go server and CSP.

## Ownership

This directory owns test setup, disposable server launch and UI assertions. The parent owns Playwright configuration and CI wiring.

## Local Contracts

- Never reuse a development or production server. Launch the compiled `.browser/server` with a minimal environment and an owned temporary data directory; remove that directory on exit. `server.mjs [port] [captcha]` serves 5391 with captcha `none` for the main projects and 5392 with `pow` for the `captcha-pow` project (`captcha.spec.mjs`, Chromium), which `globalSetup` never touches.
- `captcha.spec.mjs` signs in through the real proof-of-work: one challenge fetch while idle, exactly one more after a wrong password, then the bootstrap password reaches "Change your password".
- Find sign-in fields by label (`getByLabel('Username')`, `getByLabel('Password')`), not placeholder. Sign-in lands in chat; `openSettings` waits for the Conversation region, opens the room list when a narrow screen hides the rail, then uses the rail's Settings gear. A reload returns to chat.
- Use loopback only, with `KY_APP_URL` matching the test origin. Bootstrap credentials are disposable test values, not deployment defaults.
- Test light/dark at 390px and 1280px on Chromium, plus Firefox at light/1280 and dark/390, using real authentication and API state. Do not disable service workers, relax CSP/CSRF, or substitute mocked responses.
- The backup flow pins the repository's synthetic public-key fixture and makes
  local sealed copies through the real API; no private recovery key or shares are
  present. Check the persisted result and layout at both widths/themes.
- Login allows 10 failed attempts per account and client per 15 minutes (successes do not count); only `dark-390` and `firefox-light-1280` try a wrong password. Do not relax the limiter; budget failures before adding projects.
- The suite also covers the Create channel modal (focus on its name field, fits, closes), Health, the Audit kind filter, Directory & SCIM reached from Audit by keyboard, and the Overview, at every project.
- `chat-pickers.spec.mjs` at every project: the chat modals keep Tab inside, lock the page behind (a test spacer makes it scrollable), close on Escape (also from a picker's box) with focus back on the opener and add no `<style>`; Create channel's teammates, New direct message and Search messages are driven by arrows and Enter from their box. Its teammates come from SCIM with the server's disposable `KY_SCIM_TOKEN` (409 means already there). It signs in once per project and reuses the session saved in `test-results/`: the server allows 20 sign-ins a minute per client, success or not. Its search messages are written through the composer, so the browser's WebAssembly core encrypts them under the production CSP; it checks the server stores only `e2ee_room_v1` envelopes and refuses a member's `plain_v1` with `e2ee_required`, and search finds the decrypted text.
- Settings Branding at every project: reset to defaults first (a failed project must not break the next on the shared server), a 64-character name typed by keyboard (the header wraps it), a PNG upload previewed by digest with `/app-icon.png` served `no-cache`, then both resets.
- `e2ee-device-reset.spec.mjs` exercises real shared devices in Chromium and Firefox: the server retires a device but refuses logout after its CSRF header is stripped. Another tab recovers without reload, including a stalled query aborted by the reset and a missed BroadcastChannel notification. The first browser sets up a fresh E3 identity through the real screens (or resets an earlier test's) and reads the recovery key off the screen; the separate peer verifies itself with it, then encrypts history and reads new messages; retained inbound keys, pins and replay records are checked, and a fresh engine decrypts the old ciphertext. Responses remain real server answers.
- `e2ee-store-signout.spec.mjs`: a started device asks for persistent storage (counted around the browser's own `persist()`); sign-out deletes the encryption store even while another tab holds it, and reports one it cannot delete.
- Screenshots and failure traces live in ignored `test-results/` and CI artifacts, not production assets.

## Work Guidance

Prefer browser-native behavior and assertions over screenshot-only checks. A passing suite covers these workflows, not every page or a complete accessibility audit.

## Verification

Run `npm run test:browser` from `web/` after rebuilding the embedded frontend and server as documented in the parent.

## Child DOX Index

None.
