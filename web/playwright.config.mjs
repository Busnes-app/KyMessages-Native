import { defineConfig } from '@playwright/test';

// Separate concurrent suite runs before binding their disposable servers.
const port = Number(process.env.KY_BROWSER_PORT ?? 5391);
if (!Number.isInteger(port) || port < 1024 || port > 65534) {
  throw new Error('KY_BROWSER_PORT must be an integer from 1024 to 65534');
}

const server = (port, captcha) => ({
  command: `node browser/server.mjs ${port} ${captcha}`,
  url: `http://127.0.0.1:${port}`,
  reuseExistingServer: false,
  gracefulShutdown: { signal: 'SIGTERM', timeout: 10000 },
});

// KY_BROWSER_PORT moves both disposable servers (it and the next port), so two checkouts can
// run the suite at once.
const port = Number(process.env.KY_BROWSER_PORT || 5391);

export default defineConfig({
  testDir: './browser',
  testMatch: '*.spec.mjs',
  globalSetup: './browser/setup.mjs',
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 45000,
  use: { baseURL: `http://127.0.0.1:${port}`, trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  projects: [
    ...['light', 'dark'].flatMap(colorScheme => [390, 1280].map(width => ({
      name: `${colorScheme}-${width}`,
      testIgnore: 'captcha.spec.mjs',
      use: { browserName: 'chromium', colorScheme, viewport: { width, height: 900 } },
    }))),
    { name: 'firefox-light-1280', testIgnore: 'captcha.spec.mjs', use: { browserName: 'firefox', colorScheme: 'light', viewport: { width: 1280, height: 900 } } },
    { name: 'firefox-dark-390', testIgnore: 'captcha.spec.mjs', use: { browserName: 'firefox', colorScheme: 'dark', viewport: { width: 390, height: 900 } } },
    // Its own server with the shipped proof-of-work captcha; globalSetup never signs in there.
    { name: 'captcha-pow', testMatch: 'captcha.spec.mjs', use: { browserName: 'chromium', baseURL: `http://127.0.0.1:${port + 1}` } },
  ],
  webServer: [server(port, 'none'), server(port + 1, 'pow')],
});
