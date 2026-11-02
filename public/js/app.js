// State management
let currentUser = null;
let currentView = 'documents';
let currentDocIdForAction = null;
let currentLoadedDocs = [];

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  checkAuth();
  verifyChainStatus();
});

// Event Listeners
function initEventListeners() {
  // Navigation
  document.querySelectorAll('.rail-link').forEach((link) => {
    link.addEventListener('click', (e) => {
      const view = link.getAttribute('data-view');
      navigateTo(view);
    });
  });

  // Search & Filter
  document.getElementById('searchBtn')?.addEventListener('click', () => loadDocuments());
  document.getElementById('searchInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') loadDocuments();
  });
  document.getElementById('categoryFilter')?.addEventListener('change', () => loadDocuments());

  // Ingest Dropzone
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');

  dropzone?.addEventListener('click', () => fileInput?.click());
  dropzone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files?.length) {
      fileInput.files = e.dataTransfer.files;
      updateSelectedFileName();
    }
  });
  fileInput?.addEventListener('change', updateSelectedFileName);

  document.getElementById('submitUploadBtn')?.addEventListener('click', handleDocumentUpload);
  document.getElementById('submitVersionBtn')?.addEventListener('click', handleVersionUpload);
  document.getElementById('submitRenameBtn')?.addEventListener('click', handleRenameDocument);
  document.getElementById('grantShareBtn')?.addEventListener('click', handleGrantShare);
  document.getElementById('manualVerifyBtn')?.addEventListener('click', verifyFullChain);
  document.getElementById('logoutBtn')?.addEventListener('click', handleLogout);
  document.getElementById('authLoginBtn')?.addEventListener('click', handleLogin);

  // Global Event Delegation for all data-action controls (Strict CSP Compliance: No inline onclick)
  document.addEventListener('click', (e) => {
    const target = e.target.closest('[data-action]');
    if (!target) return;

    const action = target.getAttribute('data-action');
    switch (action) {
      case 'switch-persona': {
        const persona = target.getAttribute('data-persona');
        if (persona) switchPersona(persona);
        break;
      }
      case 'quick-fill': {
        const persona = target.getAttribute('data-persona');
        if (persona) quickFillAuth(persona);
        break;
      }
      case 'navigate': {
        const view = target.getAttribute('data-target');
        if (view) navigateTo(view);
        break;
      }
      case 'close-modal': {
        const modalId = target.getAttribute('data-target');
        if (modalId) closeModal(modalId);
        break;
      }
      case 'verify-chain': {
        verifyFullChain();
        break;
      }
      case 'open-versions': {
        const docId = target.getAttribute('data-id');
        if (docId) openVersionsModal(docId);
        break;
      }
      case 'open-share': {
        const docId = target.getAttribute('data-id');
        if (docId) openShareModal(docId);
        break;
      }
      case 'open-rename': {
        const docId = target.getAttribute('data-id');
        if (docId) openRenameModal(docId);
        break;
      }
      case 'open-doc-audit': {
        const docId = target.getAttribute('data-id');
        if (docId) openDocAuditModal(docId);
        break;
      }
      case 'soft-delete': {
        const docId = target.getAttribute('data-id');
        if (docId) softDeleteDoc(docId);
        break;
      }
      case 'restore-doc': {
        const docId = target.getAttribute('data-id');
        if (docId) restoreDoc(docId);
        break;
      }
      case 'purge-doc': {
        const docId = target.getAttribute('data-id');
        if (docId) purgeDoc(docId);
        break;
      }
      case 'instant-revoke': {
        const docId = target.getAttribute('data-doc-id');
        const userId = target.getAttribute('data-user-id');
        if (docId && userId) instantRevoke(docId, userId);
        break;
      }
      case 'toggle-user-status': {
        const userId = target.getAttribute('data-user-id');
        const makeActive = target.getAttribute('data-status') === 'true';
        if (userId) toggleUserStatus(userId, makeActive);
        break;
      }
    }
  });
}

function updateSelectedFileName() {
  const fileInput = document.getElementById('fileInput');
  const display = document.getElementById('selectedFileName');
  if (fileInput?.files?.length) {
    display.textContent = `SELECTED: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
  }
}

// Authentication Check
async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
      renderUserHeader();
      navigateTo('documents');
    } else {
      showModal('authModal');
    }
  } catch (err) {
    showModal('authModal');
  }
}

function renderUserHeader() {
  if (!currentUser) return;
  document.getElementById('currentEmailDisplay').textContent = currentUser.email;
  document.getElementById('currentRoleDisplay').textContent = currentUser.role;

  // Reveal Admin-only navigation
  const railUsers = document.getElementById('railLinkUsers');
  if (railUsers) {
    railUsers.style.display = currentUser.role === 'ADMIN' ? 'flex' : 'none';
  }

  // Hide Audit link for Viewers
  const railAudit = document.getElementById('railLinkAudit');
  if (railAudit) {
    railAudit.style.display = currentUser.role === 'VIEWER' ? 'none' : 'flex';
  }

  // Hide upload button if Viewer
  const uploadBtn = document.querySelector('#viewDocuments .btn-primary');
  if (uploadBtn) {
    uploadBtn.style.display = currentUser.role === 'VIEWER' ? 'none' : 'inline-flex';
  }
}

async function handleLogin() {
  const email = document.getElementById('authEmailInput').value.trim();
  const password = document.getElementById('authPasswordInput').value;
  const errorMsg = document.getElementById('authErrorMsg');

  errorMsg.style.display = 'none';

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();
    if (res.ok) {
      currentUser = data.user;
      closeModal('authModal');
      renderUserHeader();
      verifyChainStatus();
      navigateTo('documents');
    } else {
      errorMsg.textContent = data.error || 'Authentication failed';
      errorMsg.style.display = 'block';
    }
  } catch (err) {
    errorMsg.textContent = 'Server connection error';
    errorMsg.style.display = 'block';
  }
}

function quickFillAuth(email) {
  document.getElementById('authEmailInput').value = email;
  document.getElementById('authPasswordInput').value = 'VaultPassword2026!';
  handleLogin();
}

async function switchPersona(email) {
  quickFillAuth(email);
}

async function handleLogout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  currentUser = null;
  showModal('authModal');
}

// Navigation Router
function navigateTo(viewName) {
  currentView = viewName;

  document.querySelectorAll('.rail-link').forEach((link) => {
    if (link.getAttribute('data-view') === viewName) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });

  document.querySelectorAll('.matrix-view').forEach((view) => {
    view.style.display = 'none';
  });

  const target = document.getElementById(`view${capitalize(viewName)}`);
  if (target) target.style.display = 'block';

  if (viewName === 'documents' || viewName === 'shared' || viewName === 'trash') {
    document.getElementById('viewDocuments').style.display = 'block';
    loadDocuments();
  } else if (viewName === 'audit') {
    loadAuditLogs();
  } else if (viewName === 'users') {
    loadUserDirectory();
  }
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Load Documents
async function loadDocuments() {
  const tableBody = document.getElementById('documentsTableBody');
  tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 24px;">Scanning cryptographic vault...</td></tr>`;

  const search = document.getElementById('searchInput')?.value.trim() || '';
  const category = document.getElementById('categoryFilter')?.value || '';
  const isTrash = currentView === 'trash';
  const isShared = currentView === 'shared';

  const titleHeader = document.getElementById('documentsViewTitle');
  if (isTrash) titleHeader.textContent = 'TRASH RECYCLE ARCHIVE';
  else if (isShared) titleHeader.textContent = 'DOCUMENTS SHARED WITH ME';
  else titleHeader.textContent = 'DOCUMENT REGISTRY';

  try {
    let url = `/api/documents?trash=${isTrash}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (category) url += `&category=${encodeURIComponent(category)}`;

    const res = await fetch(url);
    if (!res.ok) {
      tableBody.innerHTML = `<tr><td colspan="7" style="color: var(--dp-color-accent); text-align: center; padding: 20px;">Failed to load documents: Access Denied</td></tr>`;
      return;
    }

    const data = await res.json();
    let docs = data.documents || [];
    currentLoadedDocs = docs;

    if (isShared) {
      docs = docs.filter((d) => d.userAccessLevel !== 'OWNER');
    }

    if (docs.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 32px; color: #666;">No documents found matching criteria.</td></tr>`;
      return;
    }

    tableBody.innerHTML = docs
      .map((doc) => {
        const isOwner = doc.userAccessLevel === 'OWNER';
        const isEditor = doc.userAccessLevel === 'EDIT';
        const badgeClass = isOwner ? 'badge-owner' : isEditor ? 'badge-edit' : 'badge-read';

        return `
        <tr>
          <td>
            <div style="font-weight: 700;">${escapeHtml(doc.title)}</div>
            <div class="mono" style="font-size: 11px; color: #666;">${doc.id}</div>
          </td>
          <td><span class="badge">${escapeHtml(doc.category)}</span></td>
          <td><span class="mono" style="font-weight: 700;">v${doc.currentVersion}</span></td>
          <td>${(doc.currentByteSize / 1024).toFixed(1)} KB</td>
          <td>${doc.owner ? escapeHtml(doc.owner.name || doc.owner.email) : 'You'}</td>
          <td><span class="badge ${badgeClass}">${doc.userAccessLevel}</span></td>
          <td>
            <div style="display: flex; gap: 4px; flex-wrap: wrap;">
              ${
                !isTrash
                  ? `
                <a href="/api/documents/${doc.id}/download" class="btn btn-sm" download>DOWNLOAD</a>
                <button class="btn btn-sm" data-action="open-versions" data-id="${doc.id}">VERSIONS</button>
                ${isOwner ? `<button class="btn btn-sm" data-action="open-share" data-id="${doc.id}">SHARE</button>` : ''}
                ${isOwner || isEditor ? `<button class="btn btn-sm" data-action="open-rename" data-id="${doc.id}">RENAME</button>` : ''}
                ${isOwner ? `<button class="btn btn-sm" data-action="open-doc-audit" data-id="${doc.id}">AUDIT</button>` : ''}
                ${isOwner ? `<button class="btn btn-sm btn-accent" data-action="soft-delete" data-id="${doc.id}">TRASH</button>` : ''}
              `
                  : `
                <button class="btn btn-sm" data-action="restore-doc" data-id="${doc.id}">RESTORE</button>
                <button class="btn btn-sm btn-accent" data-action="purge-doc" data-id="${doc.id}">PURGE PERMANENTLY</button>
              `
              }
            </div>
          </td>
        </tr>
      `;
      })
      .join('');
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" style="color: var(--dp-color-accent); text-align: center; padding: 20px;">Connection failed</td></tr>`;
  }
}

// Ingest Upload
async function handleDocumentUpload() {
  const fileInput = document.getElementById('fileInput');
  const title = document.getElementById('uploadTitleInput').value.trim();
  const category = document.getElementById('uploadCategorySelect').value;
  const description = document.getElementById('uploadDescriptionInput').value.trim();

  if (!fileInput?.files?.length) {
    alert('Please select a file to ingest.');
    return;
  }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  if (title) formData.append('title', title);
  formData.append('category', category);
  if (description) formData.append('description', description);

  try {
    const res = await fetch('/api/documents', {
      method: 'POST',
      body: formData,
    });

    const data = await res.json();
    if (res.ok) {
      alert(`✅ Document '${data.document.title}' successfully ingested and cryptographically signed!`);
      fileInput.value = '';
      document.getElementById('uploadTitleInput').value = '';
      document.getElementById('uploadDescriptionInput').value = '';
      document.getElementById('selectedFileName').textContent = '';
      verifyChainStatus();
      navigateTo('documents');
    } else {
      alert(`❌ Upload Rejected: ${data.error}`);
    }
  } catch (err) {
    alert('Failed to transmit upload.');
  }
}

// Versions Management
async function openVersionsModal(docId) {
  currentDocIdForAction = docId;
  const tableBody = document.getElementById('versionsTableBody');
  tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 12px;">Loading historical versions...</td></tr>`;
  showModal('versionsModal');

  try {
    const res = await fetch(`/api/documents/${docId}`);
    const data = await res.json();
    if (!res.ok) {
      tableBody.innerHTML = `<tr><td colspan="5" style="color: var(--dp-color-accent); text-align: center;">Access Denied</td></tr>`;
      return;
    }

    const versions = data.document.versions || [];
    tableBody.innerHTML = versions
      .map(
        (v) => `
      <tr>
        <td class="mono" style="font-weight: 700;">v${v.versionNumber}</td>
        <td class="mono" style="font-size: 11px;">${new Date(v.createdAt).toISOString().replace('T', ' ').slice(0, 19)}</td>
        <td>${(v.byteSize / 1024).toFixed(1)} KB</td>
        <td>${escapeHtml(v.changeSummary || 'Initial commit')}</td>
        <td>
          <a href="/api/documents/${docId}/versions/${v.versionNumber}/download" class="btn btn-sm" download>
            DOWNLOAD v${v.versionNumber}
          </a>
        </td>
      </tr>
    `
      )
      .join('');
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="5" style="color: var(--dp-color-accent); text-align: center;">Error loading versions</td></tr>`;
  }
}

async function handleVersionUpload() {
  const fileInput = document.getElementById('versionFileInput');
  const summary = document.getElementById('versionSummaryInput').value.trim();

  if (!fileInput?.files?.length) {
    alert('Select an artifact file for new version.');
    return;
  }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  if (summary) formData.append('changeSummary', summary);

  try {
    const res = await fetch(`/api/documents/${currentDocIdForAction}/versions`, {
      method: 'POST',
      body: formData,
    });

    const data = await res.json();
    if (res.ok) {
      alert(`✅ Committed Version ${data.currentVersion} successfully!`);
      fileInput.value = '';
      document.getElementById('versionSummaryInput').value = '';
      openVersionsModal(currentDocIdForAction);
      loadDocuments();
      verifyChainStatus();
    } else {
      alert(`❌ Rejected: ${data.error}`);
    }
  } catch (err) {
    alert('Failed to push version.');
  }
}

// Sharing & Instant Revocation
async function openShareModal(docId) {
  currentDocIdForAction = docId;
  const doc = currentLoadedDocs.find((d) => d.id === docId);
  const title = doc ? doc.title : 'Document';
  document.getElementById('shareModalTitle').textContent = `SHARE: ${title}`;
  showModal('shareModal');
  loadCollaborators(docId);
}

async function loadCollaborators(docId) {
  const tableBody = document.getElementById('collaboratorsTableBody');
  tableBody.innerHTML = `<tr><td colspan="3" style="text-align: center; padding: 12px;">Querying access control list...</td></tr>`;

  try {
    const res = await fetch(`/api/documents/${docId}`);
    const data = await res.json();
    const perms = data.document.permissions || [];

    if (perms.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="3" style="text-align: center; padding: 12px; color: #666;">No active collaborators. Document is strictly private.</td></tr>`;
      return;
    }

    tableBody.innerHTML = perms
      .map(
        (p) => `
      <tr>
        <td>
          <div style="font-weight: 700;">${escapeHtml(p.user.name || 'Unnamed')}</div>
          <div class="mono" style="font-size: 11px; color: #666;">${escapeHtml(p.user.email)}</div>
        </td>
        <td><span class="badge ${p.accessLevel === 'EDIT' ? 'badge-edit' : 'badge-read'}">${p.accessLevel}</span></td>
        <td>
          <button class="btn btn-sm btn-accent" data-action="instant-revoke" data-doc-id="${docId}" data-user-id="${p.user.id}">
            REVOKE ACCESS (T=0)
          </button>
        </td>
      </tr>
    `
      )
      .join('');
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="3" style="color: var(--dp-color-accent); text-align: center;">Error loading permissions</td></tr>`;
  }
}

async function handleGrantShare() {
  const email = document.getElementById('shareEmailInput').value.trim();
  const level = document.querySelector('input[name="accessLevelRadio"]:checked')?.value || 'READ';

  if (!email) {
    alert('Enter collaborator email address.');
    return;
  }

  try {
    const res = await fetch(`/api/documents/${currentDocIdForAction}/permissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, accessLevel: level }),
    });

    const data = await res.json();
    if (res.ok) {
      alert(`✅ Granted '${level}' access to ${email}!`);
      document.getElementById('shareEmailInput').value = '';
      loadCollaborators(currentDocIdForAction);
      verifyChainStatus();
    } else {
      alert(`❌ Permission Grant Failed: ${data.error}`);
    }
  } catch (err) {
    alert('Failed to transmit permission grant.');
  }
}

async function instantRevoke(docId, userId) {
  if (!confirm('Are you sure you want to revoke this user? Access will be terminated immediately at T=0.')) return;

  try {
    const res = await fetch(`/api/documents/${docId}/permissions/${userId}`, {
      method: 'DELETE',
    });

    if (res.ok) {
      alert('🔒 Access revoked instantly! Target user session epoch has been invalidated.');
      loadCollaborators(docId);
      verifyChainStatus();
    } else {
      const data = await res.json();
      alert(`Revocation failed: ${data.error}`);
    }
  } catch (err) {
    alert('Failed to execute revocation.');
  }
}

// Rename
function openRenameModal(docId) {
  currentDocIdForAction = docId;
  const doc = currentLoadedDocs.find((d) => d.id === docId);
  document.getElementById('renameTitleInput').value = doc ? doc.title : '';
  document.getElementById('renameCategoryInput').value = doc ? doc.category : 'General';
  document.getElementById('renameDescriptionInput').value = doc?.description || '';
  showModal('renameModal');
}

async function handleRenameDocument() {
  const title = document.getElementById('renameTitleInput').value.trim();
  const category = document.getElementById('renameCategoryInput').value.trim();
  const description = document.getElementById('renameDescriptionInput').value.trim();

  try {
    const res = await fetch(`/api/documents/${currentDocIdForAction}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, category, description }),
    });

    if (res.ok) {
      closeModal('renameModal');
      loadDocuments();
      verifyChainStatus();
    } else {
      const data = await res.json();
      alert(`Rename failed: ${data.error}`);
    }
  } catch (err) {
    alert('Failed to save metadata.');
  }
}

// Trash / Restore / Purge
async function softDeleteDoc(docId) {
  if (!confirm('Move document to trash?')) return;
  const res = await fetch(`/api/documents/${docId}`, { method: 'DELETE' });
  if (res.ok) {
    loadDocuments();
    verifyChainStatus();
  }
}

async function restoreDoc(docId) {
  const res = await fetch(`/api/documents/${docId}/restore`, { method: 'POST' });
  if (res.ok) {
    loadDocuments();
    verifyChainStatus();
  }
}

async function purgeDoc(docId) {
  if (!confirm('PERMANENT PURGE: All physical files and versions will be erased from disk. This cannot be undone.')) return;
  const res = await fetch(`/api/documents/${docId}/purge`, { method: 'DELETE' });
  if (res.ok) {
    loadDocuments();
    verifyChainStatus();
  }
}

// Document-Specific Access History (Answers: "Who opened this file, and when?")
async function openDocAuditModal(docId) {
  const doc = currentLoadedDocs.find((d) => d.id === docId);
  const title = doc ? doc.title : 'Document';
  document.getElementById('docAuditModalTitle').textContent = `ACCESS AUDIT: ${title}`;
  const tableBody = document.getElementById('docAuditTableBody');
  tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 12px;">Querying access log...</td></tr>`;
  showModal('docAuditModal');

  try {
    const res = await fetch(`/api/audit/document/${docId}`);
    if (!res.ok) {
      tableBody.innerHTML = `<tr><td colspan="6" style="color: var(--dp-color-accent); text-align: center;">Access Denied: Only Owner or Admin can inspect document audit trail.</td></tr>`;
      return;
    }

    const data = await res.json();
    const logs = data.logs || [];
    if (logs.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 12px; color: #666;">No access events recorded yet.</td></tr>`;
      return;
    }

    tableBody.innerHTML = logs
      .map((l) => {
        const isSuccess = l.outcome === 'SUCCESS';
        return `
        <tr>
          <td class="mono" style="font-size: 11px;">${new Date(l.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</td>
          <td>
            <div style="font-weight: 700; font-size: 12px;">${escapeHtml(l.userId || 'ANONYMOUS')}</div>
            <div class="mono" style="font-size: 11px; color: #666;">${escapeHtml(l.userEmail || l.clientIp)}</div>
          </td>
          <td><span class="mono" style="font-weight: 700;">${escapeHtml(l.action)}</span></td>
          <td><span class="badge ${isSuccess ? 'badge-success' : 'badge-denied'}">${escapeHtml(l.outcome)}</span></td>
          <td class="mono" style="font-size: 11px;">${escapeHtml(l.clientIp || '127.0.0.1')}</td>
          <td class="mono" style="font-size: 10px;" title="${escapeHtml(l.entryHash)}">${escapeHtml(l.entryHash.slice(0, 8))}...</td>
        </tr>
      `;
      })
      .join('');
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="6" style="color: var(--dp-color-accent); text-align: center;">Failed to retrieve audit trail</td></tr>`;
  }
}

// Audit Ledger View
async function loadAuditLogs() {
  const tableBody = document.getElementById('auditTableBody');
  tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 24px;">Traversing cryptographic chain blocks...</td></tr>`;

  try {
    const res = await fetch('/api/audit?limit=50');
    if (!res.ok) {
      tableBody.innerHTML = `<tr><td colspan="7" style="color: var(--dp-color-accent); text-align: center; padding: 24px;">Access Denied: Only Administrators can inspect system-wide audit records.</td></tr>`;
      return;
    }

    const data = await res.json();
    const entries = data.entries || [];

    tableBody.innerHTML = entries
      .map((entry) => {
        const isSuccess = entry.outcome === 'SUCCESS';
        return `
        <tr>
          <td class="mono" style="font-weight: 700;">#${entry.id}</td>
          <td class="mono" style="font-size: 11px;">${new Date(entry.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</td>
          <td>
            <div style="font-weight: 700; font-size: 12px;">${escapeHtml(entry.userId || 'ANONYMOUS')}</div>
            <div class="mono" style="font-size: 11px; color: #666;">${escapeHtml(entry.userEmail || entry.clientIp)}</div>
          </td>
          <td><span class="mono" style="font-weight: 700;">${escapeHtml(entry.action)}</span></td>
          <td class="mono" style="font-size: 11px;">${escapeHtml(entry.resourceId)}</td>
          <td>
            <span class="badge ${isSuccess ? 'badge-success' : 'badge-denied'}">
              ${escapeHtml(entry.outcome)}
            </span>
            ${entry.reason ? `<div style="font-size: 10px; margin-top: 2px; color: #555;">${escapeHtml(entry.reason)}</div>` : ''}
          </td>
          <td>
            <div class="hash-link">
              <span title="Previous Hash">${escapeHtml(entry.previousHash.slice(0, 8))}...</span>
              <span class="arrow">→</span>
              <span title="Entry Signature" style="font-weight: 700;">${escapeHtml(entry.entryHash.slice(0, 8))}...</span>
            </div>
          </td>
        </tr>
      `;
      })
      .join('');
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" style="color: var(--dp-color-accent); text-align: center;">Failed to load audit chain</td></tr>`;
  }
}

// Chain Integrity Verification
async function verifyChainStatus() {
  try {
    const res = await fetch('/api/audit/verify');
    if (!res.ok) return;
    const data = await res.json();

    const tag = document.getElementById('chainStatusTag');
    const details = document.getElementById('railChainDetails');

    if (data.valid) {
      tag.className = 'telemetry-tag verified';
      tag.textContent = '● CHAIN: 100% VERIFIED';
      details.innerHTML = `
        Status: <span style="color: #1b5e20; font-weight: 700;">INTACT</span><br>
        Verified Blocks: <strong>${data.totalEntries}</strong><br>
        Head: ${data.latestEntryHash.slice(0, 12)}...
      `;
    } else {
      tag.className = 'telemetry-tag';
      tag.style.backgroundColor = 'var(--dp-color-accent)';
      tag.style.color = '#fff';
      tag.textContent = '❌ TAMPERING DETECTED';
      details.innerHTML = `<span style="color: red; font-weight: 700;">CHAIN BROKEN AT ROW ${data.brokenRowId}</span>`;
    }
  } catch (err) {
    // Ignore
  }
}

async function verifyFullChain() {
  const res = await fetch('/api/audit/verify');
  const data = await res.json();
  if (data.valid) {
    alert(`✅ Cryptographic Audit Chain 100% Verified!\n\nAll ${data.totalEntries} sequential event blocks mathematically match HMAC-SHA256 signatures with zero tampering.`);
  } else {
    alert(`❌ CHAIN TAMPERING DETECTED!\nBroken at Block #${data.brokenRowId}\nReason: ${data.reason}`);
  }
}

// User Governance (Admin Only)
async function loadUserDirectory() {
  const tableBody = document.getElementById('usersTableBody');
  tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 24px;">Querying user directory...</td></tr>`;

  try {
    const res = await fetch('/api/admin/users');
    if (!res.ok) {
      tableBody.innerHTML = `<tr><td colspan="7" style="color: var(--dp-color-accent); text-align: center;">Access Denied: Administrator required.</td></tr>`;
      return;
    }

    const data = await res.json();
    const users = data.users || [];

    tableBody.innerHTML = users
      .map(
        (u) => `
      <tr>
        <td style="font-weight: 700;">${escapeHtml(u.name)}</td>
        <td class="mono">${escapeHtml(u.email)}</td>
        <td><span class="badge ${u.role === 'ADMIN' ? 'badge-owner' : 'badge-read'}">${u.role}</span></td>
        <td>
          <span class="badge ${u.isActive ? 'badge-success' : 'badge-denied'}">
            ${u.isActive ? 'ACTIVE' : 'DEACTIVATED'}
          </span>
        </td>
        <td class="mono">${u.permissionEpoch}</td>
        <td>${u._count?.ownedDocuments || 0}</td>
        <td>
          ${
            u.id !== currentUser.id
              ? `
            <button class="btn btn-sm ${u.isActive ? 'btn-accent' : ''}" data-action="toggle-user-status" data-user-id="${u.id}" data-status="${!u.isActive}">
              ${u.isActive ? 'DEACTIVATE (T=0)' : 'ACTIVATE'}
            </button>
          `
              : `<span class="mono" style="font-size: 11px; color: #888;">CURRENT USER</span>`
          }
        </td>
      </tr>
    `
      )
      .join('');
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" style="color: var(--dp-color-accent); text-align: center;">Error loading users</td></tr>`;
  }
}

async function toggleUserStatus(userId, makeActive) {
  const res = await fetch(`/api/admin/users/${userId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ isActive: makeActive }),
  });

  if (res.ok) {
    loadUserDirectory();
    verifyChainStatus();
  } else {
    const data = await res.json();
    alert(`Status update failed: ${data.error}`);
  }
}

// Modal Helpers
function showModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = 'flex';
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = 'none';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
