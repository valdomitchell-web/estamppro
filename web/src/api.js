// web/src/api.js

import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL;

export const api = axios.create({
  baseURL: API_URL,
  withCredentials: true, // 🔑 REQUIRED for auth cookies
});

// Optional: helpful for debugging
api.interceptors.response.use(
  (res) => res,
  (err) => {
    console.error(
      "API error:",
      err?.response?.status,
      err?.response?.data
    );
    return Promise.reject(err);
  }
);

export default api;
