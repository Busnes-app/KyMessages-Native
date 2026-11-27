// The E3 identity steps the browser specs share, through the real screens. An encrypted send
// needs a verified device (an unverified one shares a room key with no one, so it is refused).
import { expect, test } from '@playwright/test';

const banner = (page) => page.getByRole('status').filter({ hasText: /Set up encryption|Verify this device/ });

/**
 * Sets up a fresh identity (resetting an earlier test's: the account is shared, and its key is
 * unknown here) and answers the recovery key read off the screen.
 */
export async function newIdentity(page) {
  // The specs share one account, whose key routes have a per-minute budget: a busy minute
  // answers 429, which the screen shows. Wait and try again, as login does.
  let key;
  for (let attempt = 0; ; attempt++) {
    await banner(page).getByRole('button').click();
    const dialog = page.getByRole('dialog');
    if (await dialog.getByRole('heading', { name: 'Verify this device' }).isVisible()) {
      await dialog.getByRole('button', { name: 'I lost my recovery key and every other device' }).click();
    }
    const limited = dialog.getByRole('alert').filter({ hasText: /Too many/ });
    const shown = page.getByTestId('recovery-key');
    await expect(shown.or(limited).first()).toBeVisible({ timeout: 15_000 });
    if (await shown.count()) {
      key = (await shown.textContent()).trim();
      break;
    }
    if (attempt >= 3) throw new Error('The key routes stayed rate limited');
    await dialog.getByRole('button', { name: 'Not now' }).click();
    test.info().setTimeout(test.info().timeout + 25_000); // the wait is not the test's fault
    await page.waitForTimeout(20_000);
  }
  await page.getByRole('checkbox', { name: /I saved my recovery key/ }).check();
  await page.getByRole('button', { name: 'Continue' }).click();
  // The open dialog hides the banner from the accessibility tree: wait for it to close first.
  await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 15_000 });
  await expect(banner(page)).toHaveCount(0);
  return key;
}

/** Makes this browser's device verified, setting up an identity when it is not. */
export async function ensureEncryption(page) {
  const verified = page.getByRole('button', { name: 'Verify a device' }).filter({ visible: true });
  await expect(banner(page).or(verified).first()).toBeVisible({ timeout: 15_000 });
  if (await banner(page).count()) await newIdentity(page);
}
