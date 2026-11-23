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

async function run({ page, context }, testInfo, { broadcast }) {
  await page.goto('/');
  const login = await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'BrowserUpdated456!' } });
  expect(login.ok()).toBe(true);
  const csrf = (await context.cookies()).find((c) => c.name === 'ky_csrf').value;
  const headers = { 'X-CSRF-Token': csrf };
  const name = `signout-${broadcast ? 'b' : 'v'}-${testInfo.project.name}`;
  const word = `shared${testInfo.project.name.replace(/\W/g, '')}`;
  const created = await page.request.post('/api/v1/rooms', { headers, data: { kind: 'channel', name, topic: '', is_private: false, member_ids: [] } });
  expect(created.ok()).toBe(true);
  const room = (await created.json()).room;
  // Rooms are end-to-end encrypted: tab A writes the message through its composer.
  await page.goto('/');
  await openRoom(page, name);
  const composer = page.getByLabel('Message input');
  await expect(composer).toHaveAttribute('placeholder', `Message #${room.name}`);
  await composer.fill(`${word} browser note`);
  await composer.press('Enter');
  await expect(page.getByRole('region', { name: 'Conversation' }).getByText(`${word} browser note`)).toBeVisible();
  await expect.poll(() => indexes(page)).toHaveLength(1);

  // Tab B never connects its WebSocket, so it cannot hear the server's revocation. It opens the
  // room and searches, so it holds the index open while tab A signs out.
  const other = await context.newPage();
  await other.routeWebSocket(/\/api\/v1\/ws/, () => {});
  // Without BroadcastChannel, only the index's own versionchange handler can let the delete through.
  if (!broadcast) await other.addInitScript(() => { delete window.BroadcastChannel; });
  await other.goto('/');
  await openRoom(other, name);
  const openList = other.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  if (!(await other.locator('aside.chat-rail.mobile-open').count()) && await openList.count()) await openList.first().click();
  await other.getByRole('complementary', { name: 'Workspace and conversations' }).locator('.chat-search-trigger').click();
  await other.getByRole('combobox', { name: 'Search messages' }).fill(word);
  await other.waitForTimeout(400);

  // Tab A signs out.
  const signOut = page.getByRole('button', { name: 'Sign out' }).filter({ visible: true });
  if (!(await signOut.count())) {
    const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
    if (await openList.count()) await openList.first().click();
  }
  await signOut.first().click();
  await expect(page.locator('#login-username')).toBeVisible();

  if (broadcast) {
    // Tab B is signed out too, and the browser holds no search index at all.
    await expect(other.locator('#login-username')).toBeVisible();
    await expect.poll(() => indexes(other)).toEqual([]);
    await expect.poll(() => indexes(page)).toEqual([]);
  } else {
    // Tab B heard nothing, but its connection let go: the sign-out deleted the index (tab A shows
    // no failure notice), and B can no longer find the message it had read.
    await expect(page.getByText('could not delete')).toHaveCount(0);
    const box = other.getByRole('combobox', { name: 'Search messages' });
    await box.fill('');
    await box.fill(word);
    await expect(other.getByText('No matching messages found.')).toBeVisible();
  }
  await other.close();
}

test('signing out in one tab deletes the search index in another tab that missed the revocation', ({ page, context }, testInfo) => run({ page, context }, testInfo, { broadcast: true }));

test('the index is deleted even when the other tab cannot hear the sign-out at all', ({ page, context }, testInfo) => run({ page, context }, testInfo, { broadcast: false }));
