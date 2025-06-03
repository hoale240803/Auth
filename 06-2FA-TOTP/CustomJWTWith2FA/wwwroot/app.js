let accessToken = null;
let refreshToken = null;

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

function show2FA(username) {
  document.getElementById("login-form").classList.add("hidden");
  document.getElementById("register-form").classList.add("hidden");
  document.getElementById("2fa-form").classList.remove("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("2fa-username").value = username;
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
      showError(error);
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
        show2FA(data.username);
      } else {
        accessToken = data.accessToken;
        refreshToken = data.refreshToken;
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
  const username = document.getElementById("2fa-username").value;
  const code = document.getElementById("2fa-code").value;

  try {
    const response = await fetch("/api/auth/verify-2fa", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, code }),
    });
    const data = await response.json();
    if (response.ok) {
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
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
    const data = await response.json();
    if (response.ok && data.qrCode) {
      document.getElementById("2fa-status").textContent = "2FA is enabled";
      document.getElementById("toggle-2fa").textContent = "Disable 2FA";
      document.getElementById("2fa-setup").classList.remove("hidden");
      document.getElementById(
        "qrcode"
      ).src = `data:image/png;base64,${data.qrCode}`;
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
}

async function toggle2FA() {
  const isEnabled =
    document.getElementById("2fa-status").textContent === "2FA is enabled";
  const endpoint = isEnabled ? "/api/auth/disable-2fa" : "/api/auth/setup-2fa";

  try {
    const response = await fetch(endpoint, {
      method: isEnabled ? "POST" : "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
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
      showError("Failed to toggle 2FA");
    }
  } catch (err) {
    showError("Failed to toggle 2FA");
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
  showLogin();
}

function showError(message) {
  const error = document.getElementById("error");
  error.textContent = message;
  error.classList.remove("hidden");
}
