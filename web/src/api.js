// web/src/api.js
import axios from "axios";

const API_BASE =
  import.meta.env.VITE_API_BASE?.trim() ||
  "https://estamp-api.onrender.com";

// Single axios instance used everywhere
export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true, // send cookies (rf refresh cookie)
  timeout: 20000,
});

// Attach Bearer token from localStorage if present
api.interceptors.request.use((cfg) => {
  const t =
    localStorage.getItem("access_token") ||
    localStorage.getItem("token") ||
    "";
  if (t && !cfg.headers?.Authorization) {
    cfg.headers = cfg.headers || {};
    cfg.headers.Authorization = `Bearer ${t}`;
  }
  return cfg;
});

