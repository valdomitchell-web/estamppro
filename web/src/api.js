import axios from "axios";

const API_BASE =
  import.meta.env.VITE_API_URL?.trim() ||
  import.meta.env.VITE_API_BASE?.trim() ||
  "https://api.estamppro.com";

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  timeout: 45000,
});

let refreshPromise = null;

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error?.config || {};
    const status = error?.response?.status;
    const requestUrl = String(originalRequest.url || "");

    console.error(
      "API error:",
      status,
      error?.response?.data || error?.message
    );

    if (
      status === 401 &&
      !originalRequest._retry &&
      !requestUrl.includes("/auth/refresh")
    ) {
      originalRequest._retry = true;

      try {
        if (!refreshPromise) {
          refreshPromise = api
            .post("/auth/refresh")
            .then((res) => res)
            .finally(() => {
              refreshPromise = null;
            });
        }

        await refreshPromise;

        return api(originalRequest);
      } catch (refreshErr) {
        console.error("Token refresh failed:", refreshErr);
      }
    }

    return Promise.reject(error);
  }
);

export default api;