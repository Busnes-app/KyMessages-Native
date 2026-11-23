import { test, expect } from '@playwright/test';

// Sign-out deletes this browser's encryption store (device keys, room sessions and their wrapping
// key) even while another tab holds it open, and says so when it cannot. Signs in on its own (it
// signs out), once per test.

const stores = (page) => page.evaluate(async () => (await indexedDB.databases()).map((d) => d.name).filter((n) => n?.startsWith('kymessages-crypto-')));

async function signInAndOpenChat(page, context) {
  await page.goto('/');
  // Every project shares the server's sign-in limit (20 a minute per client): wait it out.
  let login = await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'BrowserUpdated456!' } });
  for (let i = 0; i < 3 && login.status() === 429; i++) {
    await page.waitForTimeout(1000 * (Number(login.headers()['retry-after']) || 20));
    login = await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'BrowserUpdated456!' } });
  }
  expect(login.ok()).toBe(true);
  await page.goto('/');
  await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
  // The device starts with the chat; its store exists once the device is set up.
  await expect.poll(() => stores(page)).toHaveLength(1);
  return context;
}

async function signOut(page) {
  const button = page.getByRole('button', { name: 'Sign out' }).filter({ visible: true });
  if (!(await button.count())) {
    const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
    if (await openList.count()) await openList.first().click();
  }
  await button.first().click();
  await expect(page.locator('#login-username')).toBeVisible();
}

test('sign-out deletes the encryption store while another tab holds it open', async ({ page, context }) => {
  await signInAndOpenChat(page, context);
  // Tab B hears neither the WebSocket nor the other tab: only the store's own versionchange
  // handler can let the delete through.
  const other = await context.newPage();
  await other.routeWebSocket(/\/api\/v1\/ws/, () => {});
  await other.addInitScript(() => { delete window.BroadcastChannel; });
  await other.goto('/');
  await expect(other.getByRole('region', { name: 'Conversation' })).toBeVisible();

  await signOut(page);
  await expect(page.getByText('could not delete')).toHaveCount(0);
  await expect.poll(() => stores(page)).toEqual([]);
  await other.close();
});

test('sign-out reports a store it cannot delete, which goes once the holder lets go', async ({ page, context }) => {
  await signInAndOpenChat(page, context);
  const [name] = await stores(page);
  // A connection that never closes on versionchange, as an old tab's would. It is held in this
  // same foreground page, so no browser drops it or throttles the sign-out's timers.
  await page.evaluate((n) => new Promise((resolve) => {
    const r = indexedDB.open(n);
    r.onsuccess = () => { window.held = r.result; resolve(); };
  }), name);

  await signOut(page);
  await expect(page.getByText('could not delete all of its local message data')).toBeVisible({ timeout: 10_000 });
  expect(await stores(page)).toHaveLength(1);
  await page.evaluate(() => window.held.close());
  await expect.poll(() => stores(page)).toEqual([]);
});
