// web/src/api.js
import axios from "axios";

const API_BASE =
  (import.meta.env.VITE_API_BASE?.trim()) ||
  "https://estamp-api.onrender.com";

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  timeout: 20000,
});

// Attach Bearer from localStorage when present
api.interceptors.request.use((cfg) => {
  const t =
    localStorage.getItem("access_token") ||
    localStorage.getItem("token") ||
    "";
  if (t) {
    cfg.headers = cfg.headers || {};
    cfg.headers.Authorization = `Bearer ${t}`;
  }
  return cfg;
});

// ---- Auto-refresh on 401 using /auth/refresh ----
let refreshing = null;

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const status = error?.response?.status;
    const original = error.config || {};
    if (status === 401 && !original._retry && !original.url?.includes("/auth/refresh")) {
      original._retry = true;
      try {
        if (!refreshing) {
          refreshing = api
            .post("/auth/refresh")
            .then((r) => {
              const t = r.data?.token;
              if (t) {
                localStorage.setItem("access_token", t);
              }
              return t;
            })
            .finally(() => {
              refreshing = null;
            });
        }
        const newToken = await refreshing;
        if (!newToken) throw error;
        original.headers = original.headers || {};
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      } catch (e) {
        // refresh failed → clear token and let caller see 401
        localStorage.removeItem("access_token");
        localStorage.removeItem("token");
      }
    }
    return Promise.reject(error);
  }
);
