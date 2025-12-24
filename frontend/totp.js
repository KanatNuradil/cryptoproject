// TOTP Setup Page Frontend
const API_BASE = "http://127.0.0.1:8000/api";

// Prevent multiple API calls - use sessionStorage to persist across reloads
const initKey = 'totp_initialized';
let totpData = null;

function showToast(message, isError = false) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.remove("hidden", "error");
  if (isError) toast.classList.add("error");
  setTimeout(() => toast.classList.add("hidden"), 5000);
}

async function api(path, { method = "GET", body, credentials = "include" } = {}) {
  const headers = { "Content-Type": "application/json" };
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      credentials,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let errorMessage = "Request failed";
      try {
        const detail = await res.json();
        errorMessage = detail.detail || detail.message || `HTTP ${res.status}: ${res.statusText}`;
      } catch {
        errorMessage = `HTTP ${res.status}: ${res.statusText}`;
      }
      throw new Error(errorMessage);
    }
    return res.json();
  } catch (error) {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      throw new Error("Cannot connect to server. Please make sure the server is running.");
    }
    throw error;
  }
}

async function logout() {
  try {
    await api("/logout", { method: "POST" });
  } catch (error) {
    console.warn(error);
  }
  window.location.href = 'index.html';
}

// DOM elements
const sessionUser = document.getElementById('session-user');
const logoutBtn = document.getElementById('logout-btn');
const totpSetupDoneBtn = document.getElementById('totp-setup-done-btn');

// Initialize - only run once using sessionStorage
async function init() {
  // Check if already initialized in this session
  if (sessionStorage.getItem(initKey) === 'true') {
    console.log('TOTP already initialized, skipping');
    return;
  }

  try {
    // Check if user is authenticated
    const users = await api("/users");
    sessionUser.textContent = `Setting up 2FA`;

    // Only call TOTP setup API once and cache the result
    if (!totpData) {
      totpData = await api("/totp/setup", { method: "POST" });
      // Store in sessionStorage to prevent reloads
      sessionStorage.setItem('totp_data', JSON.stringify(totpData));
    }

    // Set QR code and secret from cached data
    document.getElementById("totp-qr-code").src = totpData.qr_code;
    document.getElementById("totp-secret").textContent = totpData.secret;

    // Mark as initialized
    sessionStorage.setItem(initKey, 'true');

  } catch (error) {
    showToast("Please log in first to set up TOTP", "error");
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 2000);
  }
}

// Try to load cached data first
function loadCachedData() {
  const cachedData = sessionStorage.getItem('totp_data');
  if (cachedData) {
    try {
      totpData = JSON.parse(cachedData);
      // Set QR code and secret from cached data
      document.getElementById("totp-qr-code").src = totpData.qr_code;
      document.getElementById("totp-secret").textContent = totpData.secret;
      sessionUser.textContent = `Setting up 2FA`;
      return true;
    } catch (e) {
      console.log('Failed to load cached TOTP data');
    }
  }
  return false;
}

// Event listeners
logoutBtn.addEventListener('click', logout);

totpSetupDoneBtn.addEventListener('click', () => {
  showToast("TOTP setup complete! You'll be asked for a code on next login.");
  setTimeout(() => {
    window.location.href = 'index.html';
  }, 2000);
});

// Start the app - try cached data first, then init if needed
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    if (!loadCachedData()) {
      init();
    }
  });
} else {
  if (!loadCachedData()) {
    init();
  }
}
