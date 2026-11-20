import { expect, it } from 'vitest';
import { navItemsFor } from './AppHeader';

it('member gets only chat navigation and no admin pages', () => {
  expect(navItemsFor('user').map(i => i.id)).toEqual(['chat']);
  expect(navItemsFor('manager').map(i => i.id)).toEqual(['chat']);
});
it('admin sees chat and the admin pages', () => {
  expect(navItemsFor('admin').map(i => i.id)).toEqual(['chat', 'dashboard', 'users', 'agents', 'rooms', 'health', 'audit', 'scim', 'backup', 'settings']);
});
