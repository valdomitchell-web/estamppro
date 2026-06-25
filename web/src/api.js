import axios from "axios";

const API_BASE =
  (import.meta.env.VITE_API_URL?.trim()) ||
  (import.meta.env.VITE_API_BASE?.trim()) ||
  "https://api.estamppro.com";

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  timeout: 45000,
});

api.interceptors.request.use(
  (config) => {
    const token =
      localStorage.getItem("access_token") ||
      localStorage.getItem("token") ||
      "";

    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

let refreshPromise = null;

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error?.config || {};
    const status = error?.response?.status;

    console.error("API error:", status, error?.response?.data || error?.message);

    if (
      status === 401 &&
      !originalRequest._retry &&
      !String(originalRequest.url || "").includes("/auth/refresh")
    ) {
      originalRequest._retry = true;

      try {
        if (!refreshPromise) {
          refreshPromise = api
            .post("/auth/refresh")
            .then((res) => {
              const newToken = res?.data?.token;
              if (newToken) {
                localStorage.setItem("access_token", newToken);
              }
              return newToken;
            })
            .finally(() => {
              refreshPromise = null;
            });
        }

        const newToken = await refreshPromise;

        if (!newToken) throw new Error("No refreshed token returned");

        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers.Authorization = `Bearer ${newToken}`;

        return api(originalRequest);
      } catch (refreshErr) {
        console.error("Token refresh failed:", refreshErr);
        localStorage.removeItem("access_token");
        localStorage.removeItem("token");
      }
    }

    return Promise.reject(error);
  }
);

export default api;