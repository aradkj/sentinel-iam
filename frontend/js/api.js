/**
 * Enterprise IAM Platform — Centralized API v1 Client & Token Manager
 *
 * Security Note:
 * Access tokens (15m TTL) and refresh tokens are stored in sessionStorage by default
 * (or localStorage when "Remember session" is checked) to support cross-origin / standalone
 * SPA deployment without CSRF token state, while immediate server-side revocation is enforced
 * via Redis JWT blacklisting (blacklist:{jti}) and database session tracking.
 */

const API_V1_PREFIX = "/api/v1";

const IAMStorage = {
  TOKEN_KEYS: {
    ACCESS: "iam_access_token",
    REFRESH: "iam_refresh_token",
    REMEMBER: "iam_remember_session",
    USER: "iam_cached_user",
  },

  setTokens(accessToken, refreshToken, remember = false) {
    localStorage.setItem(this.TOKEN_KEYS.REMEMBER, remember ? "true" : "false");
    const store = remember ? localStorage : sessionStorage;
    const other = remember ? sessionStorage : localStorage;
    other.removeItem(this.TOKEN_KEYS.ACCESS);
    other.removeItem(this.TOKEN_KEYS.REFRESH);

    if (accessToken) store.setItem(this.TOKEN_KEYS.ACCESS, accessToken);
    if (refreshToken) store.setItem(this.TOKEN_KEYS.REFRESH, refreshToken);
  },

  getAccessToken() {
    return (
      sessionStorage.getItem(this.TOKEN_KEYS.ACCESS) ||
      localStorage.getItem(this.TOKEN_KEYS.ACCESS)
    );
  },

  getRefreshToken() {
    return (
      sessionStorage.getItem(this.TOKEN_KEYS.REFRESH) ||
      localStorage.getItem(this.TOKEN_KEYS.REFRESH)
    );
  },

  clearTokens() {
    [localStorage, sessionStorage].forEach((s) => {
      s.removeItem(this.TOKEN_KEYS.ACCESS);
      s.removeItem(this.TOKEN_KEYS.REFRESH);
      s.removeItem(this.TOKEN_KEYS.USER);
    });
  },
};

function normalizeVersionedEndpoint(endpoint) {
  if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
    return endpoint;
  }
  if (endpoint.startsWith(API_V1_PREFIX) || endpoint.startsWith("/health")) {
    return endpoint;
  }
  const clean = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${API_V1_PREFIX}${clean}`;
}

function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 4200);
}

function showAlert(elementId, message, type = "error") {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = `alert alert-${type} show`;
  el.innerHTML = message;
}

function hideAlert(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = "alert";
  el.textContent = "";
}

async function apiRequest(endpoint, options = {}, retry = true) {
  const url = normalizeVersionedEndpoint(endpoint);
  const headers = Object.assign(
    { "Content-Type": "application/json", Accept: "application/json" },
    options.headers || {}
  );

  const accessToken = IAMStorage.getAccessToken();
  if (accessToken && !options.skipAuth) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  const fetchOptions = Object.assign({}, options, { headers });
  if (fetchOptions.body && typeof fetchOptions.body === "object") {
    fetchOptions.body = JSON.stringify(fetchOptions.body);
  }

  const response = await fetch(url, fetchOptions);

  if (response.status === 401 && retry && !options.skipAuth) {
    const refreshToken = IAMStorage.getRefreshToken();
    if (
      refreshToken &&
      !url.includes("/api/v1/auth/login") &&
      !url.includes("/api/v1/auth/refresh")
    ) {
      const refreshed = await tryRefreshTokens(refreshToken);
      if (refreshed) {
        return apiRequest(url, options, false);
      }
    }
  }

  let data = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = { detail: await response.text() };
  }

  if (!response.ok) {
    const detail =
      (data && (data.detail || data.message)) ||
      `Request failed with status ${response.status}`;
    const err = new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    err.status = response.status;
    err.payload = data;
    throw err;
  }

  return data;
}

async function tryRefreshTokens(refreshToken) {
  try {
    const res = await fetch(`${API_V1_PREFIX}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) {
      IAMStorage.clearTokens();
      return false;
    }
    const tokens = await res.json();
    const remember = localStorage.getItem(IAMStorage.TOKEN_KEYS.REMEMBER) === "true";
    IAMStorage.setTokens(tokens.access_token, tokens.refresh_token, remember);
    return true;
  } catch (_err) {
    IAMStorage.clearTokens();
    return false;
  }
}

window.API_V1_PREFIX = API_V1_PREFIX;
window.IAMStorage = IAMStorage;
window.apiRequest = apiRequest;
window.showToast = showToast;
window.showAlert = showAlert;
window.hideAlert = hideAlert;
