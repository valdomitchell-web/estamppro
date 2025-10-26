import axios from 'axios';

const API = import.meta.env.VITE_API || 'http://localhost:4000';

const api = axios.create({
  baseURL: API,
  withCredentials: true, // needed so refresh cookie is sent on /auth/refresh
});

// Attach access token if we have one
api.interceptors.request.use((config) => {
  const t = localStorage.getItem('access_token') || localStorage.getItem('token');
  if (t) config.headers.Authorization = `Bearer ${t}`;
  return config;
});

let refreshing = null;
// On 401, try a refresh once, then retry the original request
api.interceptors.response.use(
  (r) => r,
  async (err) => {
    const original = err.config || {};
    if (err.response?.status === 401 && !original._retry) {
      try {
        original._retry = true;
        refreshing = refreshing || api.post('/auth/refresh');
        const { data } = await refreshing;
        refreshing = null;

        if (data?.token) {
          localStorage.setItem('access_token', data.token);
          original.headers = original.headers || {};
          original.headers.Authorization = `Bearer ${data.token}`;
          return api.request(original);
        }
      } catch {
        refreshing = null;
      }
    }
    return Promise.reject(err);
  }
);

export default api;
