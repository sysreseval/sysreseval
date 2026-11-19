// The sub-path the site is served under (base_path of web.toml: '/sre', or '' at the root of
// the host name), given by every page in <body data-base-path>.
//
// One convention: the paths the modules name ('/projects', '/api/...') and those the portal
// sends (data-api-base, the url of a focus or presentation push, a join_url) are the paths of
// the application, the same with or without a sub-path.  The sub-path is added here, where a
// URL is handed to the browser: api.js does it for every request and WebSocket, siteUrl() for a
// navigation, an href or a src; appPath() takes it away from the location of the page.

// Read at each call: the modules tested outside a browser have no document.
export function basePath() {
  const body = typeof document === 'undefined' ? null : document.body;
  return (body && body.dataset.basePath) || '';
}

// The URL of an application path on this site.
export function siteUrl(path) {
  return basePath() + path;
}

// The application path of a location path (of this page by default): '/sre/projects' is
// '/projects' under '/sre'.
export function appPath(pathname) {
  const path = pathname === undefined ? window.location.pathname : pathname;
  const base = basePath();
  if (base && (path === base || path.startsWith(base + '/'))) {
    return path.slice(base.length) || '/';
  }
  return path;
}
