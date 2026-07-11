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

console.log("[API MODULE LOADED]", {
  baseURL: API_BASE,
  withCredentials: api.defaults.withCredentials,
});

let refreshPromise = null;

api.interceptors.request.use(
  (config) => {
    console.log("[API REQUEST]", {
      method: config.method,
      url: config.url,
      baseURL: config.baseURL,
      withCredentials: config.withCredentials,
    });

    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => {
    console.log("[API RESPONSE]", {
      status: response.status,
      url: response.config?.url,
    });

    return response;
  },

  async (error) => {
    const originalRequest = error?.config;
    const status = error?.response?.status;
    const requestUrl = String(originalRequest?.url || "");

    console.log("[API RESPONSE ERROR]", {
      status,
      url: requestUrl,
      hasConfig: Boolean(originalRequest),
      alreadyRetried: Boolean(originalRequest?._retry),
      responseData: error?.response?.data,
    });

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

      console.log("[API REFRESH START]", {
        failedUrl: requestUrl,
      });

      try {
        if (!refreshPromise) {
          refreshPromise = api
            .post("/auth/refresh")
            .then((response) => {
              console.log("[API REFRESH SUCCESS]", {
                status: response.status,
              });

              return response;
            })
            .finally(() => {
              refreshPromise = null;
            });
        } else {
          console.log("[API REFRESH WAITING FOR EXISTING REQUEST]");
        }

        await refreshPromise;

        console.log("[API RETRY]", {
          method: originalRequest.method,
          url: originalRequest.url,
        });

        return api(originalRequest);
      } catch (refreshError) {
        console.error("[API REFRESH FAILED]", {
          status: refreshError?.response?.status,
          data: refreshError?.response?.data,
          message: refreshError?.message,
        });

        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;