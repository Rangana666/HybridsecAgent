/**
 * dashboard.js — Dashboard live stats refresh
 */

async function refreshStats() {
  try {
    const resp = await fetch('/api/dashboard/stats');
    if (!resp.ok) return;
    const data = await resp.json();

    const update = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    update('statCritical', data.critical ?? '—');
    update('statHigh',     data.high     ?? '—');
    update('statMedium',   data.medium   ?? '—');
    update('statLow',      data.low      ?? '—');
    update('statLynis',    data.lynis_score ?? '—');
  } catch (err) {
    console.warn('Stats refresh failed:', err);
  }
}

// Refresh every 30 seconds
document.addEventListener('DOMContentLoaded', () => {
  setInterval(refreshStats, 30000);
});
