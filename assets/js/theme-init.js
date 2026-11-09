/*
 * Applies the saved console theme before first paint so there is no
 * dark/light flash. Loaded synchronously in <head>, ahead of the stylesheets.
 * External file (not inline) because the dashboard also runs as an MV3
 * extension page, where inline scripts are blocked by CSP.
 */
(function () {
  var theme = 'dark';
  try {
    var saved = localStorage.getItem('sentinel_theme');
    if (saved === 'light' || saved === 'dark') theme = saved;
  } catch (e) {}
  document.documentElement.setAttribute('data-theme', theme);
})();
