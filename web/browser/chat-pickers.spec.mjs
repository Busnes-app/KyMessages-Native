import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { test, expect } from '@playwright/test';

// The chat modals (Base UI Dialog) and their teammate and search pickers (Base UI Combobox and
// Autocomplete): keyboard from the search box, focus kept in and returned to the opener, the
// page behind locked, and no injected <style>. Teammates come from SCIM with the harness's
// disposable token; every project shares one server, so names carry the project.
const scim = { Authorization: 'Bearer browser-regression-scim-token', 'Content-Type': 'application/scim+json' };
const teammates = [['pick-ana', 'Ana Lima'], ['pick-ben', 'Ben Okafor'], ['pick-chen', 'Chen Wu']];

// The server allows 20 sign-ins a minute per client, success or not, and every project shares
// it: each project signs in once and its tests reuse the saved session.
async function signIn(page, playwright, baseURL) {
  await page.goto('/');
  const sessionFile = `test-results/chat-pickers-session-${test.info().project.name}.json`;
  const saved = await readFile(sessionFile, 'utf8').then(JSON.parse, () => null);
  if (saved) await page.context().addCookies(saved);
  if (!saved || !(await page.request.get('/api/auth/me')).ok()) {
    const login = await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'BrowserUpdated456!' } });
    expect(login.ok()).toBe(true);
    await mkdir('test-results', { recursive: true });
    await writeFile(sessionFile, JSON.stringify(await page.context().cookies()));
  }
  const csrf = (await page.context().cookies()).find(c => c.name === 'ky_csrf').value;
  // SCIM is its own client: no session cookie, so no CSRF check.
  const directory = await playwright.request.newContext({ baseURL });
  for (const [userName, displayName] of teammates) {
    const res = await directory.post('/scim/v2/Users', {
      headers: scim,
      data: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName, displayName, active: true, emails: [{ value: `${userName}@example.test`, primary: true }] },
    });
    expect([201, 409], await res.text()).toContain(res.status());
  }
  await directory.dispose();
  return { 'X-CSRF-Token': csrf };
}

// Opens a chat rail action, first opening the room list where a narrow screen hides the rail.
async function railButton(page, name) {
  await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
  const rail = page.getByRole('complementary', { name: 'Workspace and conversations' });
  const button = name === 'Search' ? rail.locator('.chat-search-trigger') : rail.getByRole('button', { name, exact: true });
  const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  if (!(await page.locator('aside.chat-rail.mobile-open').count()) && await openList.count()) await openList.first().click();
  await expect(button).toBeVisible();
  return button;
}

async function activeOption(box) {
  const id = await box.getAttribute('aria-activedescendant');
  return id ? box.page().locator(`[id="${id}"]`).textContent() : null;
}

test('chat modals keep focus in, return it to the opener, lock the page and inject no style', async ({ page, playwright, baseURL }) => {
  await signIn(page, playwright, baseURL);
  await page.goto('/');
  const styles = await page.locator('style').count();
  // The chat shell fits the window; make the page behind taller so a lock has something to
  // hold, and show that the wheel scrolls it while no dialog is open.
  await page.evaluate(() => {
    const spacer = document.createElement('div');
    spacer.id = 'scroll-spacer';
    spacer.style.height = '3000px';
    document.body.append(spacer);
  });
  await page.mouse.move(5, 5);
  await page.mouse.wheel(0, 400);
  await expect.poll(() => page.evaluate(() => scrollY)).toBeGreaterThan(0);
  await page.evaluate(() => scrollTo(0, 0));

  const opener = await railButton(page, 'New channel');
  await opener.click();
  const dialog = page.getByRole('dialog', { name: 'Create channel' });
  await expect(dialog).toBeVisible();
  // autoFocus is respected: the name field, not the first control, has focus.
  await expect(dialog.getByLabel('Channel name')).toBeFocused();
  // The page behind does not scroll while the dialog is open (clicking the opener may have
  // scrolled it into view first, so compare with where it stands now).
  const held = await page.evaluate(() => scrollY);
  await page.mouse.move(5, 5);
  await page.mouse.wheel(0, 400);
  await page.keyboard.press('PageDown');
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => scrollY)).toBe(held);

  // Tab and Shift+Tab never leave the dialog: past either end, Base UI's focus guard hands
  // focus to the other end (a frame later, hence the poll).
  const inside = () => dialog.evaluate(d => d.contains(document.activeElement) && document.activeElement !== d);
  const seen = new Set();
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press('Tab');
    await expect.poll(inside).toBe(true);
    seen.add(await page.evaluate(() => document.activeElement.outerHTML));
  }
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press('Shift+Tab');
    await expect.poll(inside).toBe(true);
  }
  // Twelve presses wrapped round: Close, name, topic, private, teammates, Cancel.
  expect(seen.size).toBe(6);

  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(opener).toBeFocused();
  await page.evaluate(() => document.getElementById('scroll-spacer').remove());

  // Escape from inside a picker's box closes its dialog and returns focus too.
  const dm = await railButton(page, 'New direct message');
  await dm.click();
  const dmDialog = page.getByRole('dialog', { name: 'New direct message' });
  await expect(dmDialog.getByRole('combobox', { name: 'Filter teammates' })).toBeFocused();
  await page.keyboard.type('pick');
  await page.keyboard.press('Escape');
  await expect(dmDialog).toHaveCount(0);
  await expect(dm).toBeFocused();

  expect(await page.locator('style').count()).toBe(styles);
});

test('create channel: teammates are picked with the arrows and Enter from the search box', async ({ page, playwright, baseURL }, testInfo) => {
  await signIn(page, playwright, baseURL);
  await page.goto('/');
  const name = `pickers-${testInfo.project.name}`;
  await (await railButton(page, 'New channel')).click();
  const dialog = page.getByRole('dialog', { name: 'Create channel' });
  await dialog.getByLabel('Channel name').fill(name);

  const box = dialog.getByRole('combobox', { name: 'Add teammates' });
  const list = dialog.getByRole('listbox', { name: 'Teammates' });
  await expect(list).toHaveAttribute('aria-multiselectable', 'true');
  await box.focus();
  await page.keyboard.type('pick-');
  await expect(list.getByRole('option')).toHaveCount(3);
  await page.keyboard.press('ArrowDown');
  await expect(box).toBeFocused();
  expect(await activeOption(box)).toMatch(/@pick-/);
  const first = await activeOption(box);
  await page.keyboard.press('Enter');
  await expect(list.getByRole('option', { name: first })).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('ArrowDown');
  const second = await activeOption(box);
  expect(second).not.toBe(first);
  await page.keyboard.press('Enter');
  await expect(list.getByRole('option', { name: second })).toHaveAttribute('aria-selected', 'true');
  // Enter again on the same teammate removes them, and Enter never submits the form.
  await page.keyboard.press('Enter');
  await expect(list.getByRole('option', { name: second })).toHaveAttribute('aria-selected', 'false');
  await page.keyboard.press('Enter');
  await expect(list.getByRole('option', { name: second })).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Control+a');
  await page.keyboard.type('nobody-matches');
  await expect(dialog.getByText('No matching teammates.')).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(dialog).toBeVisible();

  const created = page.waitForResponse(r => r.url().endsWith('/api/v1/rooms') && r.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Create channel' }).click();
  const room = await (await created).json();
  await expect(dialog).toHaveCount(0);
  const users = (await (await page.request.get('/api/v1/users')).json()).users;
  const picked = [first, second].map(label => users.find(u => label.includes(`@${u.username}`)).id);
  const members = (await (await page.request.get(`/api/v1/rooms/${room.room.id}`)).json()).members.map(m => m.user_id);
  expect(members).toEqual(expect.arrayContaining(picked));
  expect(members).toHaveLength(3);
});

test('new DM and search: arrows move through options from the box and Enter picks', async ({ page, playwright, baseURL }, testInfo) => {
  const headers = await signIn(page, playwright, baseURL);
  const word = `kbpick${testInfo.project.name.replace(/\W/g, '')}`;
  const created = await page.request.post('/api/v1/rooms', { headers, data: { kind: 'channel', name: `search-${testInfo.project.name}`, topic: '', is_private: false, member_ids: [] } });
  expect(created.ok()).toBe(true);
  const room = (await created.json()).room;
  // Rooms are end-to-end encrypted, so the messages are written through the composer: this
  // browser's WebAssembly core (allowed by the CSP's 'wasm-unsafe-eval') seals them.
  await page.goto('/');
  const conversation = page.getByRole('region', { name: 'Conversation' });
  await expect(conversation).toBeVisible();
  const openList = page.getByRole('button', { name: 'Open room list' }).filter({ visible: true });
  if (!(await page.locator('aside.chat-rail.mobile-open').count()) && await openList.count()) await openList.first().click();
  await page.getByRole('complementary', { name: 'Workspace and conversations' }).locator('.chat-room-btn', { hasText: room.name }).first().click();
  const composer = page.getByLabel('Message input');
  await expect(composer).toHaveAttribute('placeholder', `Message #${room.name}`);
  for (const body of [`first ${word} note`, `second ${word} note`]) {
    await composer.fill(body);
    await composer.press('Enter');
    await expect(conversation.getByText(body)).toBeVisible();
  }
  // The server holds envelopes it cannot read; search below finds the text this device decrypted.
  // Poll: a grouped row shows no "Sending…", so the second send may still be in flight.
  const listStored = async () => (await (await page.request.get(`/api/v1/rooms/${room.id}/messages`)).json()).messages;
  await expect.poll(async () => (await listStored()).length).toBe(2);
  const stored = await listStored();
  for (const m of stored) {
    expect(m.encoding).toBe('e2ee_room_v1');
    expect(m.body).not.toContain(word);
    expect(JSON.parse(m.body)).toMatchObject({ alg: 'megolm.v1' });
  }
  // A member's plaintext is refused with a clear code.
  const plain = await page.request.post(`/api/v1/rooms/${room.id}/messages`, { headers, data: { body: `plain ${word}` } });
  expect(plain.status()).toBe(400);
  expect((await plain.json()).code).toBe('e2ee_required');

  await (await railButton(page, 'New direct message')).click();
  const dm = page.getByRole('dialog', { name: 'New direct message' });
  const who = dm.getByRole('combobox', { name: 'Filter teammates' });
  await expect(who).toBeFocused();
  await page.keyboard.type('pick-');
  const people = dm.getByRole('listbox', { name: 'Teammates' }).getByRole('option');
  await expect(people).toHaveCount(3);
  // The first teammate starts highlighted, as before; the arrows move from the box.
  await expect(who).toHaveAttribute('aria-activedescendant', await people.nth(0).getAttribute('id'));
  await page.keyboard.press('ArrowDown');
  await expect(who).toHaveAttribute('aria-activedescendant', await people.nth(1).getAttribute('id'));
  await expect(who).toBeFocused();
  const target = (await people.nth(1).textContent()).replace(/@.*/, '');
  await page.keyboard.press('Enter');
  await expect(dm).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Conversation' }).getByText(target).first()).toBeVisible();

  await (await railButton(page, 'Search')).click();
  const search = page.getByRole('dialog', { name: 'Search messages' });
  const box = search.getByRole('combobox', { name: 'Search messages' });
  await expect(box).toBeFocused();
  await page.keyboard.type(word);
  const hits = search.getByRole('listbox', { name: 'Search results' }).getByRole('option');
  await expect(hits).toHaveCount(2);
  await expect(box).toHaveAttribute('aria-activedescendant', await hits.nth(0).getAttribute('id'));
  await page.keyboard.press('ArrowDown');
  await expect(box).toHaveAttribute('aria-activedescendant', await hits.nth(1).getAttribute('id'));
  await page.keyboard.press('ArrowUp');
  await expect(box).toHaveAttribute('aria-activedescendant', await hits.nth(0).getAttribute('id'));
  await page.keyboard.press('Enter');
  await expect(search).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Conversation' }).getByText(`${word} note`).first()).toBeVisible();
});
