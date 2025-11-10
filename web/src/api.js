// web/src/api.js

// Point to your API. Prefer env, fall back to Render URL.
const API_BASE =
  (import.meta && import.meta.env && import.meta.env.VITE_API_BASE) ||
  window.__API_BASE__ ||
  'https://estamp-api.onrender.com';

// Apply sane defaults to every fetch
function withDefaults(opts = {}) {
  const o = { credentials: 'include', ...opts };

  // Only auto-add JSON headers when not sending FormData
  const isForm = (o.body instanceof FormData);
  const headers = new Headers(o.headers || {});
  if (!isForm) {
    if (!headers.has('Accept')) headers.set('Accept', 'application/json');
    // Leave Content-Type to caller; for JSON calls App.jsx sets it explicitly.
  }
  o.headers = headers;
  return o;
}

const api = {
  base: API_BASE,

  get: (path, opts = {}) =>
    fetch(API_BASE + path, withDefaults({ method: 'GET', ...opts })),

  post: (path, opts = {}) =>
    fetch(API_BASE + path, withDefaults({ method: 'POST', ...opts })),

  put: (path, opts = {}) =>
    fetch(API_BASE + path, withDefaults({ method: 'PUT', ...opts })),

  del: (path, opts = {}) =>
    fetch(API_BASE + path, withDefaults({ method: 'DELETE', ...opts })),
};

// Export both named and default to avoid import mismatches
export { api };
export default api;
