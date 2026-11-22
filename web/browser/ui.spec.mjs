import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

async function fits(page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}

// Everyone lands in chat; settings and the admin pages sit behind the gear in its rail,
// which a narrow screen keeps behind the room-list button.
async function openSettings(page) {
  // count() does not wait: let chat render before asking whether the rail is hidden.
  await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
  const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  if (await openList.count()) await openList.first().click();
  await page.getByRole('complementary', { name: 'Workspace and conversations' })
    .getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'System Settings & Architecture' })).toBeVisible();
}

test('production CSP, worker, themes, keyboard, dialog and responsive shell', async ({ page, context }, testInfo) => {
  const violations = [];
  page.on('console', message => {
    if (/Content Security Policy|violates.*directive/i.test(message.text())) violations.push(message.text());
  });
  const response = await page.goto('/');
  expect(response.headers()['content-security-policy']).toContain("script-src 'self'");
  expect(response.headers()['content-security-policy']).not.toContain("script-src 'self' 'unsafe-inline'");
  await expect.poll(() => page.evaluate(async () => (await navigator.serviceWorker.getRegistration())?.active?.state)).toBe('activated');
  await page.evaluate(async () => {
    const key = (await caches.keys())[0];
    await (await caches.open(key)).put('/', new Response('<h1>Stale shell</h1>', {
      headers: { 'Content-Type': 'text/html' },
    }));
  });
  // Online navigation must refresh the shell rather than pinning a previous deploy.
  await page.reload();
  await page.getByLabel('Username').fill('admin');
  // The server allows 10 attempts per account per 15 minutes; setup plus one login per
  // project leaves room for only two wrong passwords, one per theme, width and browser.
  if (['dark-390', 'firefox-light-1280'].includes(testInfo.project.name)) {
    await page.getByLabel('Password').fill('IncorrectPassword123!');
    await page.getByRole('button', { name: 'Sign In', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('Invalid credentials');
    await fits(page);
  }
  await page.getByLabel('Password').fill('BrowserUpdated456!');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
  await fits(page);
  // A chat modal opens focused on its first field, fits the screen and closes.
  const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  if (await openList.count()) await openList.first().click();
  await page.getByRole('complementary', { name: 'Workspace and conversations' })
    .getByRole('button', { name: 'New channel' }).click();
  const dialog = page.getByRole('dialog', { name: 'Create channel' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel('Channel name')).toBeFocused();
  await fits(page);
  await page.screenshot({ path: testInfo.outputPath('dialog.png'), fullPage: true });
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
  await page.reload();

  // Upload a real PNG image + text file, send them in chat, preview the image in the lightbox,
  // verify attachment download headers, and confirm both survive reload with zero CSP violations.
  await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
  const createGeneral = page.getByRole('button', { name: 'Create #general' });
  if (await createGeneral.isVisible().catch(() => false)) {
    await createGeneral.click();
  }
  const uploadInput = page.getByLabel('Upload files');
  await expect(uploadInput).toBeAttached();
  const suffix = testInfo.project.name;
  const pngName = `pixel-${suffix}.png`;
  const txtName = `report-${suffix}.txt`;
  const pngBytes = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    'base64',
  );
  const txtBody = `attachment-e2e-${suffix}`;
  await uploadInput.setInputFiles([
    { name: pngName, mimeType: 'image/png', buffer: pngBytes },
    { name: txtName, mimeType: 'text/plain', buffer: Buffer.from(txtBody) },
  ]);
  const stagedTray = page.getByRole('list', { name: 'Pending attachments' });
  await expect(stagedTray.getByText(pngName)).toBeVisible();
  await expect(stagedTray.getByText(txtName)).toBeVisible();
  const sendBtn = page.getByRole('button', { name: 'Send message' });
  await expect(sendBtn).toBeEnabled();
  await sendBtn.click();

  const inlineImg = page.getByRole('img', { name: pngName }).last();
  await expect(inlineImg).toBeVisible();
  await expect.poll(() => inlineImg.evaluate((el) => el.complete && el.naturalWidth > 0)).toBe(true);
  await page.getByRole('button', { name: `Preview ${pngName}` }).last().click();
  const lightbox = page.getByRole('dialog', { name: `Image preview: ${pngName}` });
  await expect(lightbox).toBeVisible();
  await fits(page);
  await page.keyboard.press('Escape');
  await expect(lightbox).toHaveCount(0);

  const fileLink = page.getByRole('link', { name: new RegExp(txtName) }).last();
  await expect(fileLink).toBeVisible();
  const fileHref = await fileLink.getAttribute('href');
  expect(fileHref).toMatch(/^\/api\/v1\/attachments\//);
  const dlResp = await page.request.get(fileHref);
  expect(dlResp.status()).toBe(200);
  expect(dlResp.headers()['content-disposition']).toContain('attachment');
  expect(dlResp.headers()['x-content-type-options']).toBe('nosniff');
  expect(await dlResp.text()).toBe(txtBody);

  await page.reload();
  await expect(page.getByRole('img', { name: pngName }).last()).toBeVisible();
  await expect(page.getByRole('link', { name: new RegExp(txtName) }).last()).toBeVisible();

  await openSettings(page);
  const nav = page.getByRole('navigation', { name: 'Settings and administration' });
  await expect(nav.getByRole('button', { name: 'Settings & DB' })).toHaveAttribute('aria-current', 'page');
  await fits(page);
  const theme = page.getByLabel('Color theme');
  await theme.selectOption('paper');
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(236, 239, 244)');
  await theme.selectOption('busnes-dark');
  await page.reload();
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(24, 35, 38)');
  const other = await context.newPage();
  await other.goto('/');
  await openSettings(other);
  await other.getByLabel('Color theme').selectOption('busnes-light');
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(248, 246, 240)');
  await other.close();
  await openSettings(page);
  await theme.selectOption('system');
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(24, 35, 38)');
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(248, 246, 240)');
  await page.emulateMedia({ colorScheme: testInfo.project.use.colorScheme });
  await nav.getByRole('button').first().focus();
  await page.keyboard.press('Tab');
  await expect(nav.getByRole('button').nth(1)).toBeFocused();
  await expect(nav.getByRole('button').nth(1)).toHaveCSS('outline-style', 'solid');
  await page.evaluate(() => fetch('/browser-regression-uncached'));
  const cachedDynamic = await page.evaluate(async () => {
    const keys = await caches.keys();
    for (const key of keys) for (const req of await (await caches.open(key)).keys()) {
      if (/^\/(api|scim|saml|browser-regression-uncached)(\/|$)/.test(new URL(req.url).pathname)) return true;
    }
    return false;
  });
  expect(cachedDynamic).toBe(false);
  expect(violations).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath('settings.png'), fullPage: true });
  // Branding, by keyboard, with a 64-character name that must wrap rather than widen the shell.
  // Matrix is off here: Settings has no KyIdentity sync panel. The sign-in above is recent, so
  // there is no step-up prompt. The projects share one server: start from the defaults (a failed
  // earlier project may have left a name or logo) and undo every change below.
  const branding = page.getByRole('region', { name: 'Branding' });
  await expect(branding).toBeVisible();
  await expect(page.getByRole('region', { name: 'KyIdentity sync' })).toHaveCount(0);
  await expect(branding.getByLabel('Product name')).toBeVisible();
  const resetName = branding.getByRole('button', { name: /^Use default/ });
  if (await resetName.isEnabled()) {
    await resetName.click();
    await expect(branding.getByRole('status')).toContainText('Name reset to KyMessages');
  }
  const resetLogo = branding.getByRole('button', { name: 'Reset logo' });
  if (await resetLogo.isEnabled()) {
    await resetLogo.click();
    await expect(branding.getByRole('status')).toContainText('Logo reset');
  }
  const brandName = `Browser-${testInfo.project.name}-`.padEnd(64, 'x');
  await branding.getByLabel('Product name').fill('');
  await page.keyboard.type(brandName);
  await page.keyboard.press('Enter');
  await expect(branding.getByRole('status')).toContainText('Name saved');
  await expect(page.locator('.app-brand')).toContainText(brandName);
  await fits(page);
  const icon = await readFile(new URL('../public/app-icon-192.png', import.meta.url));
  await branding.getByLabel(/^Logo/).setInputFiles({ name: 'logo.png', mimeType: 'image/png', buffer: icon });
  await branding.getByRole('button', { name: 'Upload logo' }).click();
  await expect(branding.getByRole('status')).toContainText('Logo saved');
  await expect(branding.getByAltText('Current logo')).toHaveAttribute('src', /^\/app-icon\.png\?v=[0-9a-f]{64}$/);
  expect(await page.evaluate(async () => (await fetch('/app-icon.png')).headers.get('cache-control'))).toBe('no-cache');
  await fits(page);
  await page.screenshot({ path: testInfo.outputPath('branding.png'), fullPage: true });
  await branding.getByRole('button', { name: 'Reset logo' }).click();
  await expect(branding.getByAltText('Current logo')).toHaveAttribute('src', '/app-icon.png?v=default');
  await branding.getByRole('button', { name: /^Use default/ }).focus();
  await page.keyboard.press('Enter');
  await expect(branding.getByRole('status')).toContainText('Name reset to KyMessages');
  await expect(page.locator('.app-brand')).toHaveText('KyMessages');
  expect(violations).toEqual([]);
  const fixture = JSON.parse(await readFile(new URL('../../internal/backup/testdata/pairing-v050.json', import.meta.url), 'utf8'));
  const pinned = await page.evaluate(async publicKey => {
    const csrf = document.cookie.split('; ').find(cookie => cookie.startsWith('ky_csrf='))?.slice('ky_csrf='.length);
    const response = await fetch('/api/backup/pin-key', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf ?? '' },
      body: JSON.stringify({ public_key: publicKey, threshold: 2, total_shares: 3 }),
    });
    return response.status;
  }, fixture.PublicKey);
  expect(pinned).toBe(200);
  await nav.getByRole('button', { name: 'Backup & recovery' }).click();
  await page.getByRole('button', { name: 'Back up now', exact: true }).click();
  await expect(page.getByText(/Last recorded backup attempt: Succeeded/)).toBeVisible();
  await fits(page);
  await page.screenshot({ path: testInfo.outputPath('backup.png'), fullPage: true });
  // Console pages: Health checks the app and its database (with the network check moved
  // from Settings), Audit lists the backup that just ran, then Directory by keyboard.
  await nav.getByRole('button', { name: 'Health', exact: true }).click();
  const components = page.getByRole('region', { name: 'Components' });
  await expect(components.getByText('Up', { exact: true })).toHaveCount(2);
  await expect(page.getByRole('heading', { name: 'Network path' })).toBeVisible();
  await fits(page);
  await page.screenshot({ path: testInfo.outputPath('health.png'), fullPage: true });
  await nav.getByRole('button', { name: 'Health', exact: true }).focus();
  await page.keyboard.press('Tab');
  await expect(nav.getByRole('button', { name: 'Audit', exact: true })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(nav.getByRole('button', { name: 'Audit', exact: true })).toHaveAttribute('aria-current', 'page');
  // Under All the sign-in rows are listed, so their absence after filtering is the filter.
  await expect(page.getByRole('cell', { name: 'auth.login', exact: true }).first()).toBeVisible();
  await page.getByLabel('Kind').selectOption('backup');
  await expect(page.getByRole('cell', { name: 'admin.backup_run', exact: true }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'auth.login', exact: true })).toHaveCount(0);
  await fits(page);
  await page.screenshot({ path: testInfo.outputPath('audit.png'), fullPage: true });
  await nav.getByRole('button', { name: 'Audit', exact: true }).focus();
  await page.keyboard.press('Tab');
  await expect(nav.getByRole('button', { name: 'Directory & SCIM', exact: true })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(nav.getByRole('button', { name: 'Directory & SCIM', exact: true })).toHaveAttribute('aria-current', 'page');
  await fits(page);
  await nav.getByRole('button', { name: 'Overview', exact: true }).click();
  await expect(page.getByText(/^Last backup: Succeeded/)).toBeVisible();
  await expect(page.getByText(/not set up yet/)).toHaveCount(0);
  await fits(page);
  expect(violations).toEqual([]);
  await context.setOffline(true);
  const offline = await page.reload();
  expect(offline.ok()).toBe(true);
  expect(await offline.text()).toContain('id="root"');
  await context.setOffline(false);
});
