import { afterEach, expect, it } from 'vitest';
import { THEME_OPTIONS, applyTheme } from './theme';
import { THEME_PALETTES } from './ky-ui/themes';

const root = document.documentElement;
afterEach(() => { applyTheme('system'); localStorage.clear(); });

it('offers Nord Dark and Nord Light under the suite IDs', () => {
  expect(THEME_OPTIONS).toContainEqual({ id: 'nord', label: 'Nord Dark' });
  expect(THEME_OPTIONS).toContainEqual({ id: 'paper', label: 'Nord Light' });
});

it.each([['nord', 'dark'], ['paper', 'light']] as const)('%s applies the ky-ui palette as %s', (id, scheme) => {
  applyTheme(id, true);
  expect(root.dataset.theme).toBe(id);
  expect(root.style.colorScheme).toBe(scheme);
  expect(root.style.getPropertyValue('--bg')).toBe(THEME_PALETTES[id].bg);
  expect(root.style.getPropertyValue('--ink-strong')).toBe(THEME_PALETTES[id].inkStrong);
  expect(localStorage.getItem('ky_theme')).toBe(id);
});

it('leaving Nord clears its inline palette so local themes apply', () => {
  applyTheme('nord');
  applyTheme('patina');
  expect(root.dataset.theme).toBe('patina');
  expect(root.style.getPropertyValue('--bg')).toBe('');
  expect(root.style.colorScheme).toBe('dark');
});
