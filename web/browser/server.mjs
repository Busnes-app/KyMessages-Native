import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

// Usage: node browser/server.mjs [port] [captcha provider]. Defaults: 5391, none.
const [port = '5391', captcha = 'none'] = process.argv.slice(2);

// Always own disposable data. Never reuse a running development/production server.
const dir = await mkdtemp(join(tmpdir(), 'ky-browser-'));
const server = spawn(fileURLToPath(new URL('../../.browser/server', import.meta.url)), [], {
  cwd: dir,
  env: {
    PATH: process.env.PATH,
    KY_APP_URL: `http://127.0.0.1:${port}`,
    KY_HOST: '127.0.0.1', KY_PORT: port, KY_DB_DRIVER: 'sqlite',
    KY_DATA_DIR: join(dir, 'data'), KY_BACKUP_DIR: join(dir, 'backups'),
    KY_ADMIN_PASSWORD: 'BrowserInitial123!', KY_CAPTCHA_PROVIDER: captcha,
    // Disposable, like the passwords: chat-pickers.spec.mjs adds teammates through SCIM.
    KY_SCIM_TOKEN: 'browser-regression-scim-token',
    // A throwaway server reaches no push relay, whatever the host shell sets.
    KY_PUSH_ENABLED: 'false', PUSH_RELAY_URL: '', APNS_RELAY_URL: '',
  },
  stdio: 'inherit',
});
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.kill('SIGTERM'));
server.on('error', async error => { console.error(error.message); await rm(dir, { recursive: true, force: true }); process.exit(1); });
server.on('exit', async code => { await rm(dir, { recursive: true, force: true }); process.exit(code ?? 1); });
