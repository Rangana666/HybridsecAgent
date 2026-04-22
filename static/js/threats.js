/**
 * threats.js — Live Guard feed auto-refresh
 */

async function refreshThreats() {
  try {
    const resp = await fetch('/api/threats/recent');
    if (!resp.ok) return;
    const incidents = await resp.json();

    const list = document.getElementById('incidentList');
    const empty = document.getElementById('noIncidents');

    if (!incidents || incidents.length === 0) {
      if (list)  list.innerHTML = '';
      if (empty) empty.style.display = '';
      return;
    }

    if (empty) empty.style.display = 'none';

    if (list) {
      list.innerHTML = incidents.map(inc => {
        const sev = inc.severity || 'low';
        const dotClass = sev === 'critical' || sev === 'high' ? 'bg-danger'
                       : sev === 'medium'                     ? 'bg-warning'
                       :                                        'bg-info';
        const badgeClass = sev === 'critical' ? 'bg-danger'
                         : sev === 'high'     ? 'bg-warning text-dark'
                         : sev === 'medium'   ? 'bg-info text-dark'
                         :                      'bg-secondary';
        const ts = (inc.timestamp || '').substring(0, 16).replace('T', ' ');
        const detail = inc.detail ? ` &mdash; ${escHtml(inc.detail)}` : '';

        return `
          <div class="list-group-item bg-transparent border-secondary py-2 px-3">
            <div class="d-flex justify-content-between align-items-center">
              <div class="d-flex align-items-center gap-2">
                <span class="threat-dot ${dotClass}"></span>
                <div>
                  <div class="fw-semibold small">${escHtml((inc.type || '').replace(/_/g,' '))}</div>
                  <div class="text-muted" style="font-size:0.75rem;">
                    From: ${escHtml(inc.source_ip || '—')}${detail}
                  </div>
                </div>
              </div>
              <div class="text-end">
                <span class="badge ${badgeClass}">${sev.toUpperCase()}</span>
                <div class="text-muted mt-1" style="font-size:0.7rem;">${ts}</div>
              </div>
            </div>
          </div>`;
      }).join('');
    }
  } catch (err) {
    console.warn('Threat feed refresh failed:', err);
  }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

document.addEventListener('DOMContentLoaded', () => {
  setInterval(refreshThreats, 15000);
});
