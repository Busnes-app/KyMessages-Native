import { test, expect } from '@playwright/test';

// Sign-out deletes the on-device search index in every tab, even a tab whose WebSocket never
// hears the revocation: on a shared browser, nothing readable may stay behind. This test signs
// in on its own (it signs out), once per project.

const indexes = (page) => page.evaluate(async () => (await indexedDB.databases()).map((d) => d.name).filter((n) => n?.startsWith('kymessages-search-')));

async function openRoom(page, name) {
  await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
  const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  if (!(await page.locator('aside.chat-rail.mobile-open').count()) && await openList.count()) await openList.first().click();
  await page.getByRole('complementary', { name: 'Workspace and conversations' }).locator('.chat-room-btn', { hasText: name }).first().click();
}

test('signing out in one tab deletes the search index in another tab that missed the revocation', async ({ page, context }, testInfo) => {
  await page.goto('/');
  const login = await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'BrowserUpdated456!' } });
  expect(login.ok()).toBe(true);
  const csrf = (await context.cookies()).find((c) => c.name === 'ky_csrf').value;
  const headers = { 'X-CSRF-Token': csrf };
  const name = `signout-${testInfo.project.name}`;
  const word = `shared${testInfo.project.name.replace(/\W/g, '')}`;
  const created = await page.request.post('/api/v1/rooms', { headers, data: { kind: 'channel', name, topic: '', is_private: false, member_ids: [] } });
  expect(created.ok()).toBe(true);
  const room = (await created.json()).room;
  const key = `${word}-${Date.now()}`;
  expect((await page.request.post(`/api/v1/rooms/${room.id}/messages`, { headers: { ...headers, 'Idempotency-Key': key }, data: { body: `${word} browser note`, idempotency_key: key } })).ok()).toBe(true);

  // Tab B never connects its WebSocket, so it cannot hear the server's revocation.
  const other = await context.newPage();
  await other.routeWebSocket(/\/api\/v1\/ws/, () => {});
  for (const tab of [page, other]) {
    await tab.goto('/');
    await openRoom(tab, name);
    await expect(tab.getByRole('region', { name: 'Conversation' }).getByText(`${word} browser note`)).toBeVisible();
    await expect.poll(() => indexes(tab)).toHaveLength(1);
  }

  // Tab A signs out.
  const signOut = page.getByRole('button', { name: 'Sign out' }).filter({ visible: true });
  if (!(await signOut.count())) {
    const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
    if (await openList.count()) await openList.first().click();
  }
  await signOut.first().click();
  await expect(page.locator('#login-username')).toBeVisible();

  // Tab B is signed out too, and the browser holds no search index at all.
  await expect(other.locator('#login-username')).toBeVisible();
  await expect.poll(() => indexes(other)).toEqual([]);
  await expect.poll(() => indexes(page)).toEqual([]);
  await other.close();
});
