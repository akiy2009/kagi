/* kagi — apply the saved colour theme before first paint.
 *
 * This file deliberately runs synchronously from <head> so an explicit
 * light/dark preference never flashes the system theme first. It is a
 * separate self-hosted script because the CSP forbids inline script.
 */
(() => {
  'use strict';
  const KEY = 'kagi-theme';
  let mode = 'auto';
  try {
    const saved = window.localStorage.getItem(KEY);
    if (saved === 'light' || saved === 'dark') mode = saved;
  } catch (_) {
    /* private mode or storage disabled: stay on the system theme */
  }
  const root = document.documentElement;
  if (mode === 'auto') {
    delete root.dataset.theme;
  } else {
    root.dataset.theme = mode;
  }
})();
