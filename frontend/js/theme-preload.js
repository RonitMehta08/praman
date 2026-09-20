/**
 * Theme, applied before first paint.
 *
 * `initTheme()` in shell.js does the same thing, but main.js is a module and
 * therefore deferred, so a dark-mode operator would get a full-page white flash
 * first. Same storage key, same fallback.
 *
 * A classic script rather than a module, and loaded without `defer`, because both
 * of those would postpone it past the first paint and defeat the point.
 *
 * This lives in a file rather than inline in `index.html` so the deployed
 * Content-Security-Policy can be `script-src 'self'` with no hash list and no
 * `unsafe-inline` — see deploy/nginx/praman.conf. An inline script would have
 * forced one of those, and a hash list is a trap: it goes stale the first time
 * somebody edits the script and the page then fails with the theme silently
 * reverting.
 */

try {
  var stored = localStorage.getItem('praman.theme');
  var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.dataset.theme = stored || (dark ? 'dark' : 'light');
} catch (e) {
  // Private-browsing modes throw on localStorage access. The light default in
  // the markup already applies; there is nothing to recover from.
}
