/**
 * Enterprise IAM Platform — Authentication Workflows (/api/v1/auth/*)
 */

let pendingTemp2FAToken = null;

function initAuthPages() {
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", handleLoginSubmit);
  }

  const otpForm = document.getElementById("otp-form");
  if (otpForm) {
    otpForm.addEventListener("submit", handleOtpSubmit);
  }

  const registerForm = document.getElementById("register-form");
  if (registerForm) {
    registerForm.addEventListener("submit", handleRegisterSubmit);
  }

  const googleBtn = document.getElementById("btn-google-oauth");
  if (googleBtn) {
    googleBtn.addEventListener("click", () => handleOAuthLogin("google"));
  }

  const githubBtn = document.getElementById("btn-github-oauth");
  if (githubBtn) {
    githubBtn.addEventListener("click", () => handleOAuthLogin("github"));
  }

  const logoutBtns = document.querySelectorAll("[data-action='logout']");
  logoutBtns.forEach((btn) => {
    btn.addEventListener("click", handleLogout);
  });
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  hideAlert("auth-alert");

  const emailInput = document.getElementById("email").value.trim();
  const passwordInput = document.getElementById("password").value;
  const rememberSession = document.getElementById("remember-session")
    ? document.getElementById("remember-session").checked
    : false;
  const submitBtn = document.getElementById("login-submit-btn");

  submitBtn.disabled = true;
  submitBtn.textContent = "Authenticating...";

  try {
    const payload = emailInput.includes("@")
      ? { email: emailInput, password: passwordInput }
      : { username: emailInput, password: passwordInput };

    const data = await apiRequest("/api/v1/auth/login", {
      method: "POST",
      body: payload,
      skipAuth: true,
    });

    if (data.requires_2fa && data.temp_token) {
      pendingTemp2FAToken = data.temp_token;
      localStorage.setItem(IAMStorage.TOKEN_KEYS.REMEMBER, rememberSession ? "true" : "false");
      document.getElementById("login-form").classList.add("hidden");
      document.getElementById("otp-form").classList.remove("hidden");
      showAlert(
        "auth-alert",
        "Two-Factor Authentication is enabled. Enter your 6-digit authenticator code.",
        "info"
      );
      return;
    }

    IAMStorage.setTokens(data.access_token, data.refresh_token, rememberSession);
    showToast("Authentication successful! Redirecting...", "success");
    window.location.href = "/dashboard.html";
  } catch (err) {
    showAlert("auth-alert", err.message, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Sign In";
  }
}

async function handleOtpSubmit(event) {
  event.preventDefault();
  hideAlert("auth-alert");

  const otpCode = document.getElementById("otp-code").value.trim();
  const submitBtn = document.getElementById("otp-submit-btn");
  submitBtn.disabled = true;
  submitBtn.textContent = "Verifying OTP...";

  try {
    const data = await apiRequest("/api/v1/auth/verify-otp", {
      method: "POST",
      body: { temp_token: pendingTemp2FAToken, otp_code: otpCode },
      skipAuth: true,
    });
    const remember = localStorage.getItem(IAMStorage.TOKEN_KEYS.REMEMBER) === "true";
    IAMStorage.setTokens(data.access_token, data.refresh_token, remember);
    window.location.href = "/dashboard.html";
  } catch (err) {
    showAlert("auth-alert", err.message, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Verify & Sign In";
  }
}

async function handleRegisterSubmit(event) {
  event.preventDefault();
  hideAlert("auth-alert");

  const payload = {
    email: document.getElementById("email").value.trim(),
    username: document.getElementById("username").value.trim(),
    first_name: document.getElementById("first_name").value.trim(),
    last_name: document.getElementById("last_name").value.trim(),
    password: document.getElementById("password").value,
  };

  const submitBtn = document.getElementById("register-submit-btn");
  submitBtn.disabled = true;
  submitBtn.textContent = "Creating Account...";

  try {
    const user = await apiRequest("/api/v1/auth/register", {
      method: "POST",
      body: payload,
      skipAuth: true,
    });

    let verifyNotice = "<strong>Account created! Please verify your email.</strong>";
    if (user.verification_token) {
      verifyNotice += `<div class="mt-xs">Development Quick-Verify: <a href="#" id="quick-verify-link" class="underline-link">Click here to verify ${user.email} now</a></div>`;
    }
    showAlert("auth-alert", verifyNotice, "success");
    document.getElementById("register-form").reset();

    const quickLink = document.getElementById("quick-verify-link");
    if (quickLink && user.verification_token) {
      quickLink.addEventListener("click", async (e) => {
        e.preventDefault();
        try {
          await apiRequest(`/api/v1/auth/verify-email/${user.verification_token}`, {
            method: "GET",
            skipAuth: true,
          });
          showAlert(
            "auth-alert",
            "<strong>Email verified successfully!</strong> You can now <a href='/login.html'>Sign In</a>.",
            "success"
          );
        } catch (verifyErr) {
          showAlert("auth-alert", verifyErr.message, "error");
        }
      });
    }
  } catch (err) {
    showAlert("auth-alert", err.message, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Create Account";
  }
}

function handleOAuthLogin(provider) {
  hideAlert("auth-alert");
  window.location.href = `/api/v1/auth/${provider}/login`;
}

async function handleLogout(event) {
  if (event) event.preventDefault();
  try {
    const refreshToken = IAMStorage.getRefreshToken();
    await apiRequest("/api/v1/auth/logout", {
      method: "POST",
      body: { refresh_token: refreshToken },
    });
  } catch (_err) {
    // Proceed with local token cleanup even if token was already expired
  } finally {
    IAMStorage.clearTokens();
    window.location.href = "/login.html";
  }
}

document.addEventListener("DOMContentLoaded", initAuthPages);
