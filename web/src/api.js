import axios from 'axios';

const baseURL = import.meta.env.VITE_API || 'https://estamp-api.onrender.com';

// ensure the axios/fetch client is created with { withCredentials: true }
export async function fetchAudit(limit = 50, skip = 0) {
  const r = await api.get(`/audit?limit=${limit}&skip=${skip}`);
  return r.data.items ?? [];
}

const api = axios.create({
  baseURL,
  withCredentials: true,     // critical for the httpOnly cookie
  timeout: 15000,
});

// Send bearer if we have one (after refresh/login)
api.interceptors.request.use((cfg) => {
  const t = localStorage.getItem('access_token') || localStorage.getItem('token');
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  return cfg;
});

let refreshing = null;

// On 401, try refresh once, then retry original request
api.interceptors.response.use(
  (r) => r,
  async (err) => {
    const { response, config } = err || {};
    if (response?.status === 401 && !config._retry) {
      try {
        config._retry = true;
        refreshing = refreshing || api.post('/auth/refresh'); // sets new cookie & token
        const { data } = await refreshing;
        refreshing = null;

        if (data?.token) {
          localStorage.setItem('access_token', data.token);
          config.headers = config.headers || {};
          config.headers.Authorization = `Bearer ${data.token}`;
          return api.request(config);
        }
      } catch {
        refreshing = null;
      }
    }
    throw err;
  }
);

export default api;
