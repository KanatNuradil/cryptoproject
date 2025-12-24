// File Encryption System Frontend
const API_BASE = "http://127.0.0.1:8000/api";

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

const apiRequest = api;

async function checkAuth() {
  try {
    const users = await api("/users");
    // If we get here, we're authenticated
    return { username: "current" }; // Simplified, since we don't have username here
  } catch {
    return null;
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
const encryptTab = document.getElementById('encrypt-tab');
const decryptTab = document.getElementById('decrypt-tab');
const encryptPanel = document.getElementById('encrypt-panel');
const decryptPanel = document.getElementById('decrypt-panel');
const encryptForm = document.getElementById('encrypt-form');
const decryptForm = document.getElementById('decrypt-form');
const encryptResult = document.getElementById('encrypt-result');
const decryptResult = document.getElementById('decrypt-result');

// Tab switching
encryptTab.addEventListener('click', () => {
  encryptTab.classList.add('active');
  decryptTab.classList.remove('active');
  encryptPanel.classList.add('active');
  encryptPanel.classList.remove('hidden');
  decryptPanel.classList.remove('active');
  decryptPanel.classList.add('hidden');
  encryptResult.classList.add('hidden');
});

decryptTab.addEventListener('click', () => {
  decryptTab.classList.add('active');
  encryptTab.classList.remove('active');
  decryptPanel.classList.add('active');
  decryptPanel.classList.remove('hidden');
  encryptPanel.classList.remove('active');
  encryptPanel.classList.add('hidden');
  decryptResult.classList.add('hidden');
});

// Initialize
async function init() {
  // Allow access without login for file encryption/decryption
  sessionUser.textContent = `File Encryption System`;
  logoutBtn.style.display = 'none'; // Hide logout if not logged in
}

// Encryption form handler
encryptForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const fileInput = document.getElementById('encrypt-file-input');
  const password = document.getElementById('encrypt-password').value;

  if (!fileInput.files[0]) {
    showToast('Please select a file to encrypt', 'error');
    return;
  }

  if (!password) {
    showToast('Please enter an encryption password', 'error');
    return;
  }

  const file = fileInput.files[0];

  // Show loading
  const submitBtn = encryptForm.querySelector('button[type="submit"]');
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.textContent = 'Encrypting...';

  try {
    // Create FormData for file upload
    const formData = new FormData();
    formData.append('file', file);
    formData.append('password', password);

    const response = await fetch(`${API_BASE}/files/encrypt`, {
      method: 'POST',
      body: formData
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.detail || 'Encryption failed');
    }

    // Show result
    document.getElementById('encrypted-filename').textContent = result.original_filename + '.enc';
    document.getElementById('original-size').textContent = result.file_size;

    // Store encrypted data for download
    encryptResult.dataset.encryptedData = result.encrypted_file;
    encryptResult.dataset.filename = result.original_filename + '.enc';

    encryptResult.classList.remove('hidden');
    showToast('File encrypted successfully!', 'success');

  } catch (error) {
    console.error('Encryption error:', error);
    showToast(error.message || 'Encryption failed', 'error');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Download encrypted file
document.getElementById('download-encrypted').addEventListener('click', () => {
  const encryptedData = encryptResult.dataset.encryptedData;
  const filename = encryptResult.dataset.filename;

  if (!encryptedData || !filename) {
    showToast('No encrypted file available', 'error');
    return;
  }

  // Convert base64 to blob
  const blob = base64ToBlob(encryptedData, 'application/octet-stream');
  downloadBlob(blob, filename);
});

// Decryption form handler
decryptForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const fileInput = document.getElementById('decrypt-file-input');
  const password = document.getElementById('decrypt-password').value;

  if (!fileInput.files[0]) {
    showToast('Please select an encrypted file to decrypt', 'error');
    return;
  }

  if (!password) {
    showToast('Please enter the decryption password', 'error');
    return;
  }

  const file = fileInput.files[0];

  // Show loading
  const submitBtn = decryptForm.querySelector('button[type="submit"]');
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.textContent = 'Decrypting...';

  try {
    // Read encrypted file as base64
    const encryptedData = await fileToBase64(file);

    console.log('File info:', {
      name: file.name,
      size: file.size,
      type: file.type,
      encryptedDataLength: encryptedData.length,
      encryptedDataPreview: encryptedData.substring(0, 100) + '...'
    });

    console.log('Sending decrypt request:', {
      encrypted_file_b64: encryptedData.substring(0, 100) + '...',
      password: password ? '[REDACTED]' : 'empty'
    });

    const requestData = {
      encrypted_file_b64: encryptedData,
      password: password
    };

    console.log('Request data to send:', {
      encrypted_file_b64: encryptedData.substring(0, 100) + '...',
      password: password ? '[REDACTED]' : 'empty'
    });

    const response = await apiRequest('/files/decrypt', {
      method: 'POST',
      body: requestData
    });

    // Show result
    document.getElementById('decrypted-filename').textContent = response.original_filename;
    document.getElementById('decrypted-size').textContent = response.file_size;

    // Store decrypted data for download
    decryptResult.dataset.decryptedData = response.decrypted_file;
    decryptResult.dataset.filename = response.original_filename;

    decryptResult.classList.remove('hidden');
    showToast('File decrypted successfully!', 'success');

  } catch (error) {
    console.error('Decryption error:', error);
    console.error('Error details:', {
      message: error.message,
      name: error.name,
      stack: error.stack
    });

    // Try to get more specific error from response if available
    let errorMsg = 'Decryption failed';
    if (typeof error.message === 'string') {
      errorMsg = error.message;
    } else if (error.message && typeof error.message === 'object') {
      errorMsg = JSON.stringify(error.message);
    }

    showToast(errorMsg, 'error');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Download decrypted file
document.getElementById('download-decrypted').addEventListener('click', () => {
  const decryptedData = decryptResult.dataset.decryptedData;
  const filename = decryptResult.dataset.filename;

  if (!decryptedData || !filename) {
    showToast('No decrypted file available', 'error');
    return;
  }

  // Convert base64 to blob
  const blob = base64ToBlob(decryptedData, 'application/octet-stream');
  downloadBlob(blob, filename);
});

// Utility functions
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      // Remove data URL prefix (data:application/octet-stream;base64,)
      const base64 = reader.result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function base64ToBlob(base64, mimeType = '') {
  const byteCharacters = atob(base64);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  return new Blob([byteArray], { type: mimeType });
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Start the app
init();
