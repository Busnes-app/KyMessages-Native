import { expect, it } from 'vitest';
import { navItemsFor } from './AppHeader';

it('member gets only preferences in settings and no admin pages', () => {
  expect(navItemsFor('user').map(i => i.id)).toEqual(['settings']);
  expect(navItemsFor('manager').map(i => i.id)).toEqual(['settings']);
});

it('admin sees only native settings and admin pages behind the settings gear', () => {
  expect(navItemsFor('admin').map(i => i.id)).toEqual([
    'settings',
    'dashboard',
    'health',
    'audit',
    'scim',
    'agents',
    'backup',
  ]);
});
