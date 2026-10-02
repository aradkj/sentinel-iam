/**
 * Enterprise IAM Platform — Admin Console Controller (/api/v1/admin/*)
 */

async function initAdminDashboard() {
  if (!IAMStorage.getAccessToken()) {
    window.location.href = "/login.html";
    return;
  }

  try {
    const me = await apiRequest("/api/v1/users/me");
    const userSlot = document.getElementById("sidebar-username");
    if (userSlot) userSlot.textContent = `${me.first_name} ${me.last_name} (@${me.username})`;
    const roleSlot = document.getElementById("sidebar-role");
    if (roleSlot) roleSlot.textContent = (me.roles[0] || "user").toUpperCase();

    if (!me.roles || !me.roles.includes("admin")) {
      showAlert(
        "admin-alert",
        "Access Denied: Administrator privileges are required to view this console.",
        "error"
      );
      document.getElementById("admin-content-area").classList.add("hidden");
      return;
    }

    await Promise.all([loadAdminUsers(), loadAdminRoles(), loadAdminAuditLogs()]);

    const createRoleForm = document.getElementById("create-role-form");
    if (createRoleForm) {
      createRoleForm.addEventListener("submit", handleCreateRole);
    }

    const assignPermForm = document.getElementById("assign-perm-form");
    if (assignPermForm) {
      assignPermForm.addEventListener("submit", handleAssignPermission);
    }
  } catch (err) {
    showAlert("admin-alert", err.message, "error");
  }
}

async function loadAdminUsers() {
  const tbody = document.getElementById("admin-users-tbody");
  if (!tbody) return;

  const users = await apiRequest("/api/v1/admin/users");
  tbody.innerHTML = users
    .map(
      (u) => `
    <tr>
      <td>#${u.id}</td>
      <td><strong>${u.username}</strong></td>
      <td>${u.email}</td>
      <td>
        ${
          u.is_active
            ? '<span class="badge badge-success">Active</span>'
            : '<span class="badge badge-danger">Disabled</span>'
        }
        ${
          u.locked_until
            ? '<span class="badge badge-warning">Locked</span>'
            : ""
        }
      </td>
      <td>
        ${(u.roles || ["user"])
          .map((r) => `<span class="badge badge-info">${r}</span>`)
          .join(" ")}
      </td>
      <td class="table-actions-cell">
        ${
          u.is_active
            ? `<button class="btn btn-secondary btn-sm" data-toggle-user="${u.id}" data-active="false">Disable user</button>`
            : `<button class="btn btn-success btn-sm" data-toggle-user="${u.id}" data-active="true">Activate user</button>`
        }
        <button class="btn btn-danger btn-sm" data-delete-user="${u.id}">Delete user</button>
      </td>
    </tr>
  `
    )
    .join("");

  tbody.querySelectorAll("[data-toggle-user]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const userId = Number(btn.getAttribute("data-toggle-user"));
      const isActive = btn.getAttribute("data-active") === "true";
      window.toggleUserStatus(userId, isActive);
    });
  });

  tbody.querySelectorAll("[data-delete-user]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const userId = Number(btn.getAttribute("data-delete-user"));
      window.deleteAdminUser(userId);
    });
  });
}

window.toggleUserStatus = async function (userId, isActive) {
  try {
    await apiRequest(`/api/v1/admin/users/${userId}/status`, {
      method: "PATCH",
      body: { is_active: isActive, unlock_account: true },
    });
    showToast(`User #${userId} ${isActive ? "activated" : "disabled"}.`, "success");
    await Promise.all([loadAdminUsers(), loadAdminAuditLogs()]);
  } catch (err) {
    showAlert("admin-alert", err.message, "error");
  }
};

window.deleteAdminUser = async function (userId) {
  try {
    await apiRequest(`/api/v1/admin/users/${userId}`, { method: "DELETE" });
    showToast(`User #${userId} deleted.`, "success");
    await Promise.all([loadAdminUsers(), loadAdminAuditLogs()]);
  } catch (err) {
    showAlert("admin-alert", err.message, "error");
  }
};

async function loadAdminRoles() {
  const roles = await apiRequest("/api/v1/roles");
  const tbody = document.getElementById("admin-roles-tbody");
  const roleSelect = document.getElementById("perm-role-id");

  if (tbody) {
    tbody.innerHTML = roles
      .map(
        (r) => `
      <tr>
        <td>#${r.id}</td>
        <td><strong>${r.name}</strong></td>
        <td>${r.description || "-"}</td>
        <td>
          ${
            r.permissions && r.permissions.length > 0
              ? r.permissions.map((p) => `<span class="badge badge-info">${p}</span>`).join(" ")
              : '<span class="badge badge-warning">No permissions</span>'
          }
        </td>
      </tr>
    `
      )
      .join("");
  }

  if (roleSelect) {
    roleSelect.innerHTML = roles
      .map((r) => `<option value="${r.id}">${r.name} (#${r.id})</option>`)
      .join("");
  }
}

async function handleCreateRole(event) {
  event.preventDefault();
  const name = document.getElementById("role-name").value.trim();
  const description = document.getElementById("role-description").value.trim();
  const rawPerms = document.getElementById("role-permissions").value.trim();
  const permissions = rawPerms
    ? rawPerms.split(",").map((p) => p.trim()).filter(Boolean)
    : [];

  try {
    await apiRequest("/api/v1/admin/roles", {
      method: "POST",
      body: { name, description, permissions },
    });
    document.getElementById("create-role-form").reset();
    showToast(`Role '${name}' created!`, "success");
    await Promise.all([loadAdminRoles(), loadAdminAuditLogs()]);
  } catch (err) {
    showAlert("admin-alert", err.message, "error");
  }
}

async function handleAssignPermission(event) {
  event.preventDefault();
  const roleId = document.getElementById("perm-role-id").value;
  const permissionName = document.getElementById("perm-name").value.trim();

  try {
    try {
      await apiRequest("/api/v1/admin/permissions", {
        method: "POST",
        body: { name: permissionName, description: `Custom permission ${permissionName}` },
      });
    } catch (_e) {
      // Permission may already exist
    }

    await apiRequest(`/api/v1/admin/roles/${roleId}/permissions`, {
      method: "POST",
      body: { permission_name: permissionName },
    });
    document.getElementById("perm-name").value = "";
    showToast(`Permission '${permissionName}' assigned!`, "success");
    await Promise.all([loadAdminRoles(), loadAdminAuditLogs()]);
  } catch (err) {
    showAlert("admin-alert", err.message, "error");
  }
}

async function loadAdminAuditLogs() {
  const tbody = document.getElementById("admin-audit-tbody");
  if (!tbody) return;

  const logs = await apiRequest("/api/v1/admin/audit-logs?limit=50");
  tbody.innerHTML = logs
    .map(
      (log) => `
    <tr>
      <td>#${log.id}</td>
      <td><span class="badge badge-info">${log.event_type || log.action}</span></td>
      <td>${log.user_id !== null ? `User #${log.user_id}` : "Anonymous"}</td>
      <td>${log.description || log.details || "-"}</td>
      <td><code>${log.ip_address || "-"}</code></td>
      <td>${new Date(log.created_at).toLocaleString()}</td>
    </tr>
  `
    )
    .join("");
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("admin-view")) {
    initAdminDashboard();
  }
});
