/**
 * Enterprise IAM Platform — Dashboard, Profile, and Session Management Controller (/api/v1/*)
 */

let currentUserProfile = null;

async function initProtectedPage() {
  if (!IAMStorage.getAccessToken()) {
    window.location.href = "/login.html";
    return;
  }

  try {
    currentUserProfile = await apiRequest("/api/v1/users/me");
    renderSidebarIdentity(currentUserProfile);

    if (document.getElementById("dashboard-view")) {
      await loadDashboardMetrics(currentUserProfile);
    }
    if (document.getElementById("profile-view")) {
      initProfilePage(currentUserProfile);
    }
    if (document.getElementById("sessions-view")) {
      await initSessionsPage();
    }
  } catch (err) {
    showToast("Session expired. Please sign in again.", "error");
    IAMStorage.clearTokens();
    window.location.href = "/login.html";
  }
}

function renderSidebarIdentity(user) {
  const userSlot = document.getElementById("sidebar-username");
  if (userSlot) userSlot.textContent = `${user.first_name} ${user.last_name} (@${user.username})`;

  const roleSlot = document.getElementById("sidebar-role");
  const primaryRole = (user.roles && user.roles[0]) || "user";
  if (roleSlot) roleSlot.textContent = primaryRole.toUpperCase();

  const adminNavItem = document.getElementById("nav-admin-item");
  if (adminNavItem) {
    if (user.roles && user.roles.includes("admin")) {
      adminNavItem.classList.remove("hidden");
    } else {
      adminNavItem.classList.add("hidden");
    }
  }
}

async function loadDashboardMetrics(user) {
  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setText("user-username", user.username);
  setText("user-email", user.email);
  setText("user-fullname", `${user.first_name} ${user.last_name}`);
  setText("user-role", (user.roles || ["user"]).join(", ").toUpperCase());

  const statusCard = document.getElementById("card-account-status");
  if (statusCard) {
    statusCard.innerHTML = user.is_active
      ? `<span class="badge badge-success">Active</span> ${
          user.is_verified
            ? '<span class="badge badge-info">Email Verified</span>'
            : '<span class="badge badge-warning">Unverified Email</span>'
        }`
      : `<span class="badge badge-danger">Disabled</span>`;
  }

  const twoFaCard = document.getElementById("card-2fa-status");
  if (twoFaCard) {
    twoFaCard.innerHTML = user.two_factor_enabled
      ? `<span class="badge badge-success">Enabled (TOTP)</span>`
      : `<span class="badge badge-warning">Disabled</span>`;
  }

  const permList = document.getElementById("user-permissions-list");
  if (permList) {
    if (user.permissions && user.permissions.length > 0) {
      permList.innerHTML = user.permissions
        .map((p) => `<span class="badge badge-info mr-xs">${p}</span>`)
        .join("");
    } else {
      permList.innerHTML = `<span class="badge badge-warning">Standard User Scope</span>`;
    }
  }

  try {
    const sessions = await apiRequest("/api/v1/sessions");
    setText("card-active-sessions", String(sessions.length));
  } catch (_e) {
    setText("card-active-sessions", "1");
  }
}

function initProfilePage(user) {
  const emailEl = document.getElementById("profile-email");
  const usernameEl = document.getElementById("profile-username");
  const roleEl = document.getElementById("profile-role");
  if (emailEl) emailEl.value = user.email;
  if (usernameEl) usernameEl.value = user.username;
  if (roleEl) roleEl.value = (user.roles || ["user"]).join(", ");

  update2FAUI(user.two_factor_enabled);

  const pwForm = document.getElementById("change-password-form");
  if (pwForm) {
    pwForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAlert("profile-alert");
      const current_password = document.getElementById("current_password").value;
      const new_password = document.getElementById("new_password").value;
      try {
        await apiRequest("/api/v1/auth/change-password", {
          method: "POST",
          body: { current_password, new_password },
        });
        pwForm.reset();
        showAlert("profile-alert", "Password updated successfully!", "success");
        showToast("Password changed.", "success");
      } catch (err) {
        showAlert("profile-alert", err.message, "error");
      }
    });
  }

  const enable2faBtn = document.getElementById("btn-enable-2fa");
  if (enable2faBtn) {
    enable2faBtn.addEventListener("click", async () => {
      try {
        const res = await apiRequest("/api/v1/users/enable-2fa", { method: "POST" });
        const box = document.getElementById("totp-secret-container");
        if (box) {
          box.classList.remove("hidden");
          document.getElementById("totp-secret-code").textContent = res.secret;
          document.getElementById("totp-uri-code").textContent = res.otpauth_url;
        }
        update2FAUI(true);
        showToast("Two-Factor Authentication enabled!", "success");
      } catch (err) {
        showAlert("profile-alert", err.message, "error");
      }
    });
  }

  const disable2faBtn = document.getElementById("btn-disable-2fa");
  if (disable2faBtn) {
    disable2faBtn.addEventListener("click", async () => {
      try {
        await apiRequest("/api/v1/users/disable-2fa", { method: "POST" });
        const box = document.getElementById("totp-secret-container");
        if (box) box.classList.add("hidden");
        update2FAUI(false);
        showToast("Two-Factor Authentication disabled.", "info");
      } catch (err) {
        showAlert("profile-alert", err.message, "error");
      }
    });
  }
}

function update2FAUI(enabled) {
  const badge = document.getElementById("profile-2fa-badge");
  const enableBtn = document.getElementById("btn-enable-2fa");
  const disableBtn = document.getElementById("btn-disable-2fa");

  if (badge) {
    badge.className = enabled ? "badge badge-success" : "badge badge-warning";
    badge.textContent = enabled ? "2FA Active (TOTP)" : "2FA Disabled";
  }
  if (enableBtn) enableBtn.classList.toggle("hidden", enabled);
  if (disableBtn) disableBtn.classList.toggle("hidden", !enabled);
}

async function initSessionsPage() {
  await renderSessionsTable();

  const revokeAllBtn = document.getElementById("btn-revoke-all-sessions");
  if (revokeAllBtn) {
    revokeAllBtn.addEventListener("click", async () => {
      try {
        await apiRequest("/api/v1/sessions/revoke-all", { method: "POST" });
        showToast("All device sessions revoked. Signing out...", "info");
        IAMStorage.clearTokens();
        setTimeout(() => {
          window.location.href = "/login.html";
        }, 900);
      } catch (err) {
        showAlert("sessions-alert", err.message, "error");
      }
    });
  }
}

async function renderSessionsTable() {
  const tbody = document.getElementById("sessions-table-body");
  if (!tbody) return;

  try {
    const sessions = await apiRequest("/api/v1/sessions");
    if (!sessions || sessions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="table-empty-cell">No active sessions found.</td></tr>`;
      return;
    }

    tbody.innerHTML = sessions
      .map(
        (s) => `
      <tr>
        <td>#${s.id}</td>
        <td>
          <strong>${s.device || s.device_name}</strong>
          ${s.is_current ? '<span class="badge badge-success ml-xs">Current Device</span>' : ""}
        </td>
        <td><code>${s.ip || s.ip_address}</code></td>
        <td>${s.last_activity}</td>
        <td>
          <button class="btn btn-danger btn-sm" data-revoke-session="${s.id}" data-is-current="${Boolean(s.is_current)}">
            Logout session
          </button>
        </td>
      </tr>
    `
      )
      .join("");

    tbody.querySelectorAll("[data-revoke-session]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const sessionId = Number(btn.getAttribute("data-revoke-session"));
        const isCurrent = btn.getAttribute("data-is-current") === "true";
        window.revokeSingleSession(sessionId, isCurrent);
      });
    });
  } catch (err) {
    showAlert("sessions-alert", err.message, "error");
  }
}

window.revokeSingleSession = async function (sessionId, isCurrent) {
  try {
    await apiRequest(`/api/v1/sessions/${sessionId}`, { method: "DELETE" });
    showToast(`Session #${sessionId} revoked.`, "success");
    if (isCurrent) {
      IAMStorage.clearTokens();
      window.location.href = "/login.html";
      return;
    }
    await renderSessionsTable();
  } catch (err) {
    showAlert("sessions-alert", err.message, "error");
  }
};

document.addEventListener("DOMContentLoaded", () => {
  if (
    document.getElementById("dashboard-view") ||
    document.getElementById("profile-view") ||
    document.getElementById("sessions-view")
  ) {
    initProtectedPage();
  }
});
