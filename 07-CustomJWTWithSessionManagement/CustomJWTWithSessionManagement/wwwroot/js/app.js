let accessToken = null;
let refreshToken = null;
let sessionToken = null;

function showLogin() {
  document.getElementById("login-form").classList.remove("hidden");
  document.getElementById("register-form").classList.add("hidden");
  document.getElementById("2fa-form").classList.add("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("error").classList.add("hidden");
}

function showRegister() {
  document.getElementById("login-form").classList.add("hidden");
  document.getElementById("register-form").classList.remove("hidden");
  document.getElementById("2fa-form").classList.add("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("error").classList.add("hidden");
}

function show2FA(username, sessionToken) {
  document.getElementById("login-form").classList.add("hidden");
  document.getElementById("register-form").classList.add("hidden");
  document.getElementById("2fa-form").classList.remove("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("2fa-username").value = username;
  document.getElementById("2fa-session-token").value = sessionToken;
  document.getElementById("error").classList.add("hidden");
}

async function register() {
  const username = document.getElementById("register-username").value;
  const password = document.getElementById("register-password").value;
  const role = document.getElementById("register-role").value;

  try {
    const response = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    if (response.ok) {
      showLogin();
    } else {
      const error = await response.text();
      showError(error || "Registration failed");
    }
  } catch (err) {
    showError("Registration failed");
  }
}

async function login() {
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json();
    if (response.ok) {
      if (data.requires2FA) {
        show2FA(data.username, data.sessionToken);
      } else {
        accessToken = data.accessToken;
        refreshToken = data.refreshToken;
        sessionToken = data.sessionToken;
        showDashboard(data.username);
      }
    } else {
      showError(data || "Login failed");
    }
  } catch (err) {
    showError("Login failed");
  }
}

async function verify2FA() {
  try {
    let username = document.getElementById("2fa-username").value;
    let code = document.getElementById("2fa-code").value;
    let sessionToken = document.getElementById("2fa-session-token").value;
    const response = await fetch("/api/auth/verify-2fa", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, code, sessionToken }),
    });
    const data = await response.json();
    if (response.ok) {
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
      sessionToken = data.sessionToken;
      showDashboard(username);
    } else {
      showError("Invalid 2FA code");
    }
  } catch (err) {
    showError("2FA verification failed");
  }
}

async function showDashboard(username) {
  document.getElementById("auth-section").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");
  document.getElementById("username").textContent = username;

  try {
    const response = await fetch("/api/auth/setup-2fa", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.ok) {
      const data = await response.json();
      document.getElementById("2fa-status").textContent = "2FA is enabled";
      document.getElementById("toggle-2fa").textContent = "Disable 2FA";
      document.getElementById("2fa-setup").classList.remove("hidden");
      // document.getElementById("qrcode").classList.add("hidden");
      document.getElementById("manual-code").textContent = data.manualCode;
    } else {
      document.getElementById("2fa-status").textContent = "2FA is disabled";
      document.getElementById("toggle-2fa").textContent = "Enable 2FA";
      document.getElementById("2fa-setup").classList.add("hidden");
    }
  } catch (err) {
    document.getElementById("2fa-status").textContent = "2FA is disabled";
    document.getElementById("toggle-2fa").textContent = "Enable 2FA";
    document.getElementById("2fa-setup").classList.add("hidden");
  }

  await loadSessions();
}

async function toggle2FA() {
  const isEnabled =
    document.getElementById("2fa-status").textContent === "2FA is enabled";
  const endpoint = isEnabled ? "/api/auth/disable-2fa" : "/api/auth/setup-2fa";

  try {
    console.log(`Calling ${endpoint} with token: ${accessToken}`);
    const response = await fetch(endpoint, {
      method: isEnabled ? "POST" : "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });
    if (response.ok) {
      const contentType = response.headers.get("content-type");
      let data;
      if (contentType && contentType.includes("application/json")) {
        data = await response.json();
      } else {
        data = { message: await response.text() };
      }
      if (!isEnabled) {
        document.getElementById("2fa-status").textContent = "2FA is enabled";
        document.getElementById("toggle-2fa").textContent = "Disable 2FA";
        document.getElementById("2fa-setup").classList.remove("hidden");
        document.getElementById("qrcode").classList.remove("hidden");
        document.getElementById("manual-code").classList.remove("hidden");
        document.getElementById(
          "qrcode"
        ).src = `data:image/png;base64,${data.qrCode}`;
        document.getElementById("manual-code").textContent = data.manualCode;
      } else {
        document.getElementById("2fa-status").textContent = "2FA is disabled";
        document.getElementById("toggle-2fa").textContent = "Enable 2FA";
        document.getElementById("2fa-setup").classList.add("hidden");
      }
    } else {
      const error = await response.text();
      showError(`Failed to toggle 2FA: ${error || response.statusText}`);
    }
  } catch (err) {
    console.error("Toggle2FA error:", err);
    showError("Failed to toggle 2FA");
  }
}

async function loadSessions() {
  try {
    const response = await fetch("/api/auth/sessions", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.ok) {
      const sessions = await response.json();
      const sessionsList = document.getElementById("sessions-list");
      sessionsList.innerHTML = "";
      sessions.forEach((session) => {
        const li = document.createElement("li");
        li.className = "border p-2 rounded flex justify-between items-center";
        li.innerHTML = `
                    <div>
                        <p><strong>Login:</strong> ${new Date(
                          session.loginTimestamp
                        ).toLocaleString()}</p>
                        <p><strong>IP:</strong> ${session.ipAddress}</p>
                        <p><strong>Device:</strong> ${session.userAgent}</p>
                        <p><strong>Active:</strong> ${session.isActive}</p>
                        <p><strong>Fingerprint:</strong> ${
                          session.deviceFingerprint
                        }</p>
                        <p><strong>Refresh Token:</strong> ${
                          session.refreshTokenStatus
                        }</p>
                    </div>
                    ${
                      session.isActive && session.sessionToken !== sessionToken
                        ? `<button onclick="revokeSession('${session.sessionToken}')" class="bg-red-500 text-white p-1 rounded hover:bg-red-600">Revoke</button>`
                        : ""
                    }
                `;
        sessionsList.appendChild(li);
      });
    } else {
      showError("Failed to load sessions");
    }
  } catch (err) {
    showError("Failed to load sessions");
  }
}

async function revokeSession(sessionToken) {
  try {
    const response = await fetch("/api/auth/revoke", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sessionToken }),
    });
    if (response.ok) {
      await loadSessions();
    } else {
      showError("Failed to revoke session");
    }
  } catch (err) {
    showError("Failed to revoke session");
  }
}

async function revokeAllOtherSessions() {
  try {
    const response = await fetch("/api/auth/revoke-all-others", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });
    if (response.ok) {
      await loadSessions();
    } else {
      showError("Failed to revoke other sessions");
    }
  } catch (err) {
    showError("Failed to revoke other sessions");
  }
}

async function getAssets() {
  try {
    const response = await fetch("/api/assets", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.ok) {
      const data = await response.text();
      alert(data);
    } else if (response.status === 401) {
      await refreshTokenAndRetry();
    } else {
      showError("Failed to fetch assets");
    }
  } catch (err) {
    showError("Failed to fetch assets");
  }
}

async function refreshTokenAndRetry() {
  try {
    const response = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accessToken, refreshToken }),
    });
    if (response.ok) {
      const data = await response.json();
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
      sessionToken = data.sessionToken;
      await getAssets();
    } else {
      showError("Session expired. Please log in again.");
      showLogin();
    }
  } catch (err) {
    showError("Session expired. Please log in again.");
    showLogin();
  }
}

function logout() {
  accessToken = null;
  refreshToken = null;
  sessionToken = null;
  showLogin();
}

function showError(message) {
  const error = document.getElementById("error");
  error.textContent = message;
  error.classList.remove("hidden");
}
