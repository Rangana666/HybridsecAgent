/**
 * autofix.js — Auto-Fix and Rollback logic
 * Handles the confirmation modal, API calls, and toast notifications.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Auto-fix buttons
  document.querySelectorAll('.btn-autofix').forEach(btn => {
    btn.addEventListener('click', () => handleAutofixClick(btn));
  });

  // Rollback buttons
  document.querySelectorAll('.btn-rollback').forEach(btn => {
    btn.addEventListener('click', () => handleRollback(btn.dataset.backupId));
  });

  // Delete (clear) buttons
  document.querySelectorAll('.btn-delete-fix').forEach(btn => {
    btn.addEventListener('click', () => handleDeleteFix(btn.dataset.backupId, btn));
  });
});

// ── Auto-Fix ──────────────────────────────────────────────

let pendingVuln = null;

async function handleAutofixClick(btn) {
  const vulnType = btn.dataset.vulnType;
  const vulnId   = btn.dataset.vulnId || '';

  pendingVuln = { type: vulnType, id: vulnId };

  // First call — get confirmation message
  try {
    const resp = await fetch('/api/autofix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrf_token: window.CSRF_TOKEN,
        vuln: pendingVuln,
        confirmed: false,
      }),
    });
    const data = await resp.json();

    if (data.needs_confirmation) {
      document.getElementById('autofixModalBody').innerHTML =
        '<pre class="text-warning small mb-0" style="white-space:pre-wrap;">' +
        escapeHtml(data.confirmation_message) + '</pre>';
      const modal = new bootstrap.Modal(document.getElementById('autofixModal'));
      modal.show();

      document.getElementById('btnConfirmFix').onclick = async () => {
        modal.hide();
        await executeAutofix(pendingVuln);
      };
    } else if (data.error) {
      showToast('Fix error: ' + data.error, 'danger');
    } else {
      // No confirmation needed (config override) — execute directly
      await executeAutofix(pendingVuln);
    }
  } catch (err) {
    showToast('Request failed: ' + err.message, 'danger');
  }
}

async function executeAutofix(vuln) {
  showToast('Applying fix for ' + vuln.type + '…', 'secondary');
  try {
    const resp = await fetch('/api/autofix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrf_token: window.CSRF_TOKEN,
        vuln: vuln,
        confirmed: true,
      }),
    });
    const data = await resp.json();

    if (data.success) {
      let msg = 'Fix applied for ' + vuln.type;
      if (data.verify_result && data.verify_result.passed) msg += ' ✓ Verified';
      if (data.backup_id) msg += ' | Backup: ' + data.backup_id.substring(0, 30) + '…';
      showToast(msg, 'success');
      setTimeout(() => location.reload(), 2000);
    } else {
      showToast('Fix failed: ' + (data.error || 'Unknown error'), 'danger');
    }
  } catch (err) {
    showToast('Request failed: ' + err.message, 'danger');
  }
}

// ── Rollback ──────────────────────────────────────────────

async function handleRollback(backupId) {
  if (!confirm('Roll back this fix? The config file will be restored to its previous state.')) return;

  try {
    const resp = await fetch('/api/autofix/rollback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrf_token: window.CSRF_TOKEN,
        backup_id: backupId,
      }),
    });
    const data = await resp.json();

    if (data.success) {
      showToast('Rollback successful: ' + (data.message || backupId), 'success');
      setTimeout(() => location.reload(), 1500);
    } else {
      showToast('Rollback failed: ' + (data.error || 'Unknown error'), 'danger');
    }
  } catch (err) {
    showToast('Request failed: ' + err.message, 'danger');
  }
}

// ── Delete Fix Entry ──────────────────────────────────────

async function handleDeleteFix(backupId, btn) {
  try {
    const resp = await fetch('/api/autofix/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf_token: window.CSRF_TOKEN, backup_id: backupId }),
    });
    const data = await resp.json();
    if (data.success) {
      // Remove the table row from DOM immediately
      const row = btn.closest('tr');
      if (row) row.remove();
      showToast('Entry cleared.', 'success');
    } else {
      showToast('Delete failed: ' + (data.error || 'Unknown error'), 'danger');
    }
  } catch (err) {
    showToast('Request failed: ' + err.message, 'danger');
  }
}

// ── Helpers ───────────────────────────────────────────────

function showToast(message, type = 'secondary') {
  const toastEl   = document.getElementById('fixToast');
  const toastBody = document.getElementById('fixToastBody');
  if (!toastEl) return;

  toastEl.className = 'toast align-items-center text-white border-0 bg-' + type;
  toastBody.textContent = message;

  const toast = bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 5000 });
  toast.show();
}

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
