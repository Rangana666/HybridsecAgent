/**
 * scan.js — Scan page logic
 * Handles start-scan button, progress polling, and redirect on completion.
 */

let pollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  const btnStart = document.getElementById('btnStartScan');
  if (btnStart) {
    btnStart.addEventListener('click', handleStartScan);
  }
});

async function handleStartScan() {
  const target   = '127.0.0.1';
  const scanType = document.querySelector('input[name="scanType"]:checked')?.value || 'quick';

  const btn = document.getElementById('btnStartScan');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Starting…';

  try {
    const resp = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrf_token: window.CSRF_TOKEN,
        scan_type:  scanType,
        target:     target,
      }),
    });

    const data = await resp.json();
    if (data.error) {
      alert('Error: ' + data.error);
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-play-fill me-2"></i>Start Scan';
      return;
    }

    startPolling(data.scan_id);
  } catch (err) {
    alert('Request failed: ' + err.message);
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-play-fill me-2"></i>Start Scan';
  }
}

function startPolling(scanId) {
  // Show progress card
  const progressCard = document.getElementById('scanProgressCard');
  if (progressCard) progressCard.style.removeProperty('display');

  document.getElementById('scanIdDisplay').textContent = 'Scan ID: ' + scanId;
  document.getElementById('scanStatusText').textContent = 'Scan running…';

  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(() => pollStatus(scanId), 3000);
}

async function pollStatus(scanId) {
  try {
    const resp = await fetch('/api/scan/status/' + scanId);
    const data = await resp.json();

    const statusEl = document.getElementById('scanStatusText');

    if (data.status === 'completed') {
      clearInterval(pollInterval);
      if (statusEl) statusEl.textContent = 'Scan complete! Redirecting to results…';
      setTimeout(() => {
        window.location.href = '/risks?scan_id=' + scanId;
      }, 1200);
    } else if (data.status === 'failed') {
      clearInterval(pollInterval);
      if (statusEl) {
        statusEl.textContent = 'Scan failed. Check server logs.';
        statusEl.classList.add('text-danger');
      }
      const btn = document.getElementById('btnStartScan');
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-play-fill me-2"></i>Start Scan';
      }
    } else {
      if (statusEl) statusEl.textContent = 'Scanning… (status: ' + data.status + ')';
    }
  } catch (err) {
    console.warn('Poll error:', err);
  }
}
