// web/src/api.js
import axios from "axios";

const API_BASE =
  (import.meta.env.VITE_API_BASE?.trim()) ||
  "https://estamp-api.onrender.com";

// One axios instance for the whole app
export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true, // send/receive cookies too
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

