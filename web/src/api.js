// web/src/api.js
const API_BASE =
  (import.meta?.env?.VITE_API_BASE) ||
  window.__API_BASE__ ||
  'https://estamp-api.onrender.com';

function bearer() {
  // try localStorage keys we use
  return (
    localStorage.getItem('access_token') ||
    localStorage.getItem('token') ||
    ''
  );
}

function withDefaults(opts = {}) {
  const o = { credentials: 'include', ...opts };
  const headers = new Headers(o.headers || {});

  // Attach Authorization if we have one
  const tk =
  localStorage.getItem('access_token') ||
  localStorage.getItem('token') || '';

if (tk && !headers.has('Authorization')) {
  headers.set('Authorization', `Bearer ${tk}`);
}

  // Don’t force Content-Type for FormData
  const isForm = (o.body instanceof FormData);
  if (!isForm) {
    if (!headers.has('Accept')) headers.set('Accept', 'application/json');
  }

  o.headers = headers;
  return o;
}

const api = {
  base: API_BASE,
  get: (p, o = {})  => fetch(API_BASE + p, withDefaults({ method: 'GET', ...o })),
  post: (p, o = {}) => fetch(API_BASE + p, withDefaults({ method: 'POST', ...o })),
  put: (p, o = {})  => fetch(API_BASE + p, withDefaults({ method: 'PUT', ...o })),
  del: (p, o = {})  => fetch(API_BASE + p, withDefaults({ method: 'DELETE', ...o })),
};

export { api };
export default api;
