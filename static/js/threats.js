/**
 * threats.js — Live Guard page: incidents, blocked IPs, and summary
 * counters, all polled and re-rendered without a manual page reload.
 */

const REFRESH_MS = 5000;

async function fetchJSON(url) {
  const resp = await fetch(url, { credentials: 'include' });
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  return resp.json();
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function titleCase(str) {
  return String(str).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function severityBadgeClass(sev) {
  if (sev === 'critical') return 'badge-sev-critical';
  if (sev === 'high')     return 'badge-sev-high';
  if (sev === 'medium')   return 'badge-sev-medium';
  return 'badge-sev-low';
}

const EMPTY_INCIDENTS_HTML =
  '<div class="empty-state" id="noIncidents">' +
  '<div class="empty-icon"><i class="bi bi-shield-check"></i></div>' +
  '<h6 class="fw-bold text-success">All Systems Guarded</h6>' +
  '<p class="text-muted small">No incidents recorded. Live Guard is active and monitoring traffic.</p></div>';

const EMPTY_BLOCKED_HTML =
  '<div class="empty-state" id="noBlockedIps">' +
  '<div class="empty-icon"><i class="bi bi-shield-check"></i></div>' +
  '<h6 class="fw-bold text-success">No IPs Currently Blocked</h6>' +
  '<p class="text-muted small">Blocked attacker IPs will appear here.</p></div>';

function renderIncidents(incidents) {
  const feed = document.getElementById('threatFeed');
  const clearAllBtn = document.getElementById('clearAllBtn');
  if (!feed) return;

  if (!incidents || incidents.length === 0) {
    feed.innerHTML = EMPTY_INCIDENTS_HTML;
    if (clearAllBtn) clearAllBtn.style.display = 'none';
    return;
  }

  if (clearAllBtn) clearAllBtn.style.display = '';

  const rows = incidents.map((inc, i) => {
    const sev = inc.severity || 'low';
    const detail = inc.detail ? `&nbsp;&middot;&nbsp;${escHtml(inc.detail)}` : '';
    const ts = (inc.timestamp || '').substring(0, 16).replace('T', ' ');
    return `
      <div class="incident-row" id="inc-${i}">
        <div class="d-flex align-items-center gap-3">
          <span class="severity-dot ${sev}"></span>
          <div>
            <div class="inc-type">${escHtml(titleCase(inc.type || ''))}</div>
            <div class="inc-meta">
              <strong>Source:</strong> ${escHtml(inc.source_ip || '—')} ${detail}
            </div>
          </div>
        </div>
        <div class="d-flex align-items-center gap-3">
          <div class="text-end">
            <span class="${severityBadgeClass(sev)}">${sev.toUpperCase()}</span>
            <div style="font-size:0.68rem; color:#94a3b8; margin-top:2px;">${ts}</div>
          </div>
          <button class="btn btn-sm btn-outline-secondary"
                  style="border-radius:50%; width:24px; height:24px; display:flex; align-items:center; justify-content:center; padding:0;"
                  onclick="clearOneIncident(${i}, this)" title="Dismiss">
            <i class="bi bi-x" style="font-size:1rem;"></i>
          </button>
        </div>
      </div>`;
  }).join('');

  feed.innerHTML = `<div class="list-group list-group-flush" id="incidentList">${rows}</div>`;
}

function renderBlockedIps(blocked) {
  const feed = document.getElementById('blockedIpFeed');
  if (!feed) return;

  if (!blocked || blocked.length === 0) {
    feed.innerHTML = EMPTY_BLOCKED_HTML;
    return;
  }

  const rows = blocked.map(b => {
    const ip = escHtml(b.ip);
    return `
      <div class="incident-row" id="blocked-${ip}">
        <div class="d-flex align-items-center gap-3">
          <span class="severity-dot critical"></span>
          <div>
            <div class="inc-type">${ip}</div>
            <div class="inc-meta">
              <strong>Reason:</strong> ${escHtml(b.reason || '—')}
              &nbsp;&middot;&nbsp; via ${escHtml(b.backend || 'unknown')}
            </div>
          </div>
        </div>
        <div class="d-flex align-items-center gap-3">
          <div style="font-size:0.68rem; color:#94a3b8;">
            ${(b.blocked_at || '').substring(0, 16).replace('T', ' ')}
          </div>
          <button class="btn btn-sm btn-outline-warning" style="border-radius:8px; font-weight:700;"
                  onclick="handleUnblockIp('${ip}', this)">
            <i class="bi bi-unlock me-1"></i>Unblock
          </button>
        </div>
      </div>`;
  }).join('');

  feed.innerHTML = `<div class="list-group list-group-flush" id="blockedIpList">${rows}</div>`;
}

function renderCounters(incidents) {
  const counts = { ssh_brute_force: 0, port_scan: 0, ddos: 0 };
  for (const inc of incidents) {
    if (inc.type in counts) counts[inc.type]++;
  }
  const sshEl  = document.getElementById('sshCount');
  const portEl = document.getElementById('portCount');
  const ddosEl = document.getElementById('ddosCount');
  if (sshEl)  sshEl.textContent  = counts.ssh_brute_force;
  if (portEl) portEl.textContent = counts.port_scan;
  if (ddosEl) ddosEl.textContent = counts.ddos;
}

async function refreshLiveGuard() {
  try {
    const [incidents, blocked] = await Promise.all([
      fetchJSON('/api/threats/recent'),
      fetchJSON('/api/threats/blocked'),
    ]);
    renderIncidents(incidents);
    renderBlockedIps(blocked);
    renderCounters(incidents);
  } catch (err) {
    console.warn('Live Guard refresh failed:', err);
  }
}

// ── Actions (exposed globally — called from inline onclick in rendered rows) ──

async function clearOneIncident(index, btn) {
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  try {
    const res = await fetch('/api/threats/incidents/clear-one', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf_token: window.CSRF_TOKEN, index: index }),
    });
    const data = await res.json();
    if (data.ok) {
      await refreshLiveGuard();
    } else {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-x"></i>';
      alert('Error: ' + (data.error || 'Failed to clear'));
    }
  } catch (err) {
    alert('Request failed: ' + err.message);
  }
}

async function clearAllIncidents() {
  if (!confirm('Clear all incidents? This cannot be undone.')) return;
  try {
    const res = await fetch('/api/threats/incidents/clear-all', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf_token: window.CSRF_TOKEN }),
    });
    const data = await res.json();
    if (data.ok) {
      await refreshLiveGuard();
    } else {
      alert('Error: ' + (data.error || 'Failed to clear'));
    }
  } catch (err) {
    alert('Request failed: ' + err.message);
  }
}

async function handleUnblockIp(ip, btn) {
  if (!confirm('Unblock ' + ip + '? Traffic from this IP will be allowed again.')) return;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  try {
    const res = await fetch('/api/threats/unblock', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf_token: window.CSRF_TOKEN, ip: ip }),
    });
    const data = await res.json();
    if (data.success) {
      await refreshLiveGuard();
    } else {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-unlock me-1"></i>Unblock';
      alert('Error: ' + (data.error || 'Failed to unblock'));
    }
  } catch (err) {
    alert('Request failed: ' + err.message);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  setInterval(refreshLiveGuard, REFRESH_MS);
});
