import { readChoice, saveChoice, watchChoice } from './ky-ui/theme';
import { applyThemeVariables } from './ky-ui/themes';
// Busnes.app defaults; explicit choices are local to this browser.
export const THEME_OPTIONS = [{"id": "system", "label": "System (Busnes)"}, {"id": "busnes-light", "label": "Busnes Light"}, {"id": "busnes-dark", "label": "Busnes Dark"}, {"id": "patina", "label": "Patina Ky"}, {"id": "cyber", "label": "Cyber Dark"}, {"id": "nord", "label": "Nord Dark"}, {"id": "paper", "label": "Nord Light"}, {"id": "oled", "label": "OLED Black"}];
const SUITE_THEMES = ['nord', 'paper'];
export function storedTheme(): string {
  try { const value = readChoice('ky_theme'); return THEME_OPTIONS.find(t => t.id === value)?.id ?? 'system'; }
  catch { return 'system'; }
}
let current = storedTheme();
const media = window.matchMedia?.('(prefers-color-scheme: dark)');
export function applyTheme(theme: string, persist = false) {
  if (!THEME_OPTIONS.some(t => t.id === theme)) return;
  current = theme;
  const resolved = theme === 'system' ? (media?.matches ? 'busnes-dark' : 'busnes-light') : theme;
  const root = document.documentElement;
  // Nord Dark/Light are the suite palettes, set inline by ky-ui; other themes are local CSS.
  const suite = applyThemeVariables(SUITE_THEMES.includes(resolved) ? resolved : 'system', root);
  root.dataset.theme = resolved;
  root.style.colorScheme = suite ?? (resolved === 'busnes-light' ? 'light' : 'dark');
  if (persist) try { saveChoice('ky_theme', theme); } catch { /* Storage is optional. */ }
}
applyTheme(current);
watchChoice('ky_theme', () => applyTheme(storedTheme()), () => current !== 'system');
