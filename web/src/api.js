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

api.interceptors.request.use(
  (config) => {

    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => {

    return response;
  },

  async (error) => {
    const originalRequest = error?.config;
    const status = error?.response?.status;
    const requestUrl = String(originalRequest?.url || "");

    if (!originalRequest) {
      return Promise.reject(error);
    }

    const skipRefreshPaths = [
  "/auth/refresh",
  "/auth/login",
  "/auth/register",
  "/auth/logout",
  "/auth/forgot-password",
  "/auth/reset-password",
];

const shouldSkipRefresh = skipRefreshPaths.some((path) =>
  requestUrl.includes(path)
);

   if (
  status === 401 &&
  !originalRequest._retry &&
  !shouldSkipRefresh
) {
      originalRequest._retry = true;

      try {
        if (!refreshPromise) {
          refreshPromise = api
            .post("/auth/refresh")
            .then((response) => {
             
              return response;
            })
            .finally(() => {
              refreshPromise = null;
            });
        } else {
         
        }

        await refreshPromise;


        return api(originalRequest);
      } catch (refreshError) {
        console.error("[API REFRESH FAILED]", {
          status: refreshError?.response?.status,
          data: refreshError?.response?.data,
          message: refreshError?.message,
        });

       window.dispatchEvent(new CustomEvent("auth-expired"));
return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;