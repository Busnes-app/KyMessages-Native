import { test, expect } from '@playwright/test';

async function login(page) {
  await page.goto('/');
  let r = await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'BrowserUpdated456!' } });
  for (let i = 0; i < 3 && r.status() === 429; i++) {
    await page.waitForTimeout(1000 * (Number(r.headers()['retry-after']) || 20));
    r = await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'BrowserUpdated456!' } });
  }
  expect(r.ok()).toBe(true);
  await page.goto('/');
}

async function openRoom(page, name) {
  await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
  const list = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  if (!(await page.locator('aside.chat-rail.mobile-open').count()) && await list.count()) await list.first().click();
  await page.getByRole('complementary', { name: 'Workspace and conversations' }).locator('.chat-room-btn', { hasText: name }).first().click();
}

async function send(page, text) {
  const posted = page.waitForResponse((r) => /\/rooms\/[^/]+\/messages$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST', { timeout: 15_000 });
  await page.getByLabel('Message input').fill(text);
  await page.getByLabel('Message input').press('Enter');
  expect((await posted).status()).toBe(201);
}

async function snapshot(page) {
  return page.evaluate(async () => {
    const [db] = (await indexedDB.databases()).filter((d) => d.name?.startsWith('kymessages-crypto-'));
    if (!db) return null;
    const store = await new Promise((resolve, reject) => {
      const r = indexedDB.open(db.name);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    try {
      const kv = store.transaction('kv').objectStore('kv');
      const read = (r) => new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
      const [keys, values] = await Promise.all([read(kv.getAllKeys()), read(kv.getAll())]);
      const entries = Object.fromEntries(keys.map((k, i) => [k, values[i]]));
      return { device: entries.device, history: Object.fromEntries(Object.entries(entries).filter(([k]) => /^(in:|seen:|pin:)/.test(k))) };
    } finally { store.close(); }
  });
}

async function clickSignOut(page) {
  const button = page.getByRole('button', { name: 'Sign out' }).filter({ visible: true });
  const list = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  // A just-selected room can leave the closing rail briefly visible; use its open state.
  if (await list.count() && !(await page.locator('aside.chat-rail.mobile-open').count())) await list.first().click();
  await button.first().click();
}

for (const broadcast of [true, false]) {
  test(`a shared device reset recovers the other tab (${broadcast ? 'in-flight cancellation' : 'missed notification'})`, async ({ page, context, browser }, testInfo) => {
    test.skip(!['light-1280', 'firefox-dark-390'].includes(testInfo.project.name), 'Crypto concurrency needs both browser engines; responsive UI is covered separately.');
    test.setTimeout(90_000);
    await login(page);
    const headers = { 'X-CSRF-Token': (await context.cookies()).find((c) => c.name === 'ky_csrf').value };
    const name = `reset-${broadcast ? 'live' : 'missed'}-${testInfo.project.name}`;
    const created = await page.request.post('/api/v1/rooms', { headers, data: { kind: 'channel', name, member_ids: [] } });
    expect(created.ok()).toBe(true);
    await page.reload();
    await openRoom(page, name);
    // A separate profile supplies a genuine peer device and room key, under the same real account.
    const peerContext = await browser.newContext({ baseURL: new URL(page.url()).origin });
    const peer = await peerContext.newPage();
    const other = await context.newPage();
    let releaseQuery = () => {};
    try {
      await login(peer);
      await openRoom(peer, name);
      const history = `history-${name}`;
      await send(peer, history);
      await expect(page.getByRole('region', { name: 'Conversation' }).getByText(history, { exact: true })).toBeVisible();
      if (!broadcast) await other.addInitScript(() => { delete window.BroadcastChannel; });
      await other.goto('/');
      await openRoom(other, name);
      await expect(other.getByRole('region', { name: 'Conversation' }).getByText(history, { exact: true })).toBeVisible();
      const before = await snapshot(other);
      for (const prefix of ['in:', 'seen:', 'pin:']) expect(Object.keys(before.history).some((k) => k.startsWith(prefix))).toBe(true);
      let cancelled = false;
      let stalled = false;
      let pendingSend;
      if (broadcast) {
        const held = new Promise((resolve) => { releaseQuery = resolve; });
        other.on('requestfailed', (r) => { if (r.url().endsWith('/api/v1/keys/query')) cancelled = true; });
        await other.route('**/api/v1/keys/query', async (route) => {
          if (!stalled) { stalled = true; await held; }
          await route.continue().catch(() => {}); // the held request may already be aborted
        });
        pendingSend = send(other, `during-reset-${name}`);
        await expect.poll(() => stalled).toBe(true);
      }
      // The key server really retires the device; the real auth handler then refuses logout.
      // Remove only the CSRF header; do not replace the server's response.
      await page.route('**/api/auth/logout', (route) => {
        const h = { ...route.request().headers() };
        delete h['x-csrf-token'];
        return route.continue({ headers: h });
      });
      await clickSignOut(page);
      await expect(page.getByRole('alert').filter({ hasText: 'You are still signed in' }).first()).toBeVisible();
      await expect.poll(async () => {
        const d = (await snapshot(page))?.device;
        return d?.registered === true && d.device_id !== before.device.device_id;
      }).toBe(true);
      if (broadcast) {
        await expect.poll(() => cancelled).toBe(true);
        await pendingSend; // still without releasing the old response
      }
      const sent = `after-reset-${name}`;
      await send(other, sent); // tab B never reloads or reconnects
      await expect(peer.getByRole('region', { name: 'Conversation' }).getByText(sent, { exact: true })).toBeVisible();
      const after = await snapshot(other);
      expect(after.device.device_id).not.toBe(before.device.device_id);
      for (const [k, v] of Object.entries(before.history)) expect(after.history[k]).toEqual(v);
      // A fresh engine must actually decrypt the old peer ciphertext with the retained inbound key.
      await page.reload();
      await openRoom(page, name);
      await expect(page.getByRole('region', { name: 'Conversation' }).getByText(history, { exact: true })).toBeVisible();
      releaseQuery();
      await page.unroute('**/api/auth/logout');
      await clickSignOut(page);
      await expect(page.locator('#login-username')).toBeVisible();
      await clickSignOut(peer);
      await expect(peer.locator('#login-username')).toBeVisible();
    } finally {
      releaseQuery();
      await other.close();
      await peerContext.close();
    }
  });
}
