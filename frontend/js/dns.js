let allDnsRecords = [];

document.addEventListener('DOMContentLoaded', async () => {
  await window.initShell('dns');

  document.getElementById('dns-filter-btn').addEventListener('click', applyDnsFilters);
  document.getElementById('dns-hostname').addEventListener('input', applyDnsFilters);
  document.getElementById('dns-type').addEventListener('change', applyDnsFilters);

  document.getElementById('dns-reset-btn').addEventListener('click', () => {
    document.getElementById('dns-hostname').value = '';
    document.getElementById('dns-type').value = '';
    applyDnsFilters();
  });

  document.querySelectorAll('[data-type-pill]').forEach((card) => {
    card.addEventListener('click', () => {
      const t = card.getAttribute('data-type-pill');
      const sel = document.getElementById('dns-type');
      sel.value = sel.value === t ? '' : t;
      applyDnsFilters();
    });
  });

  document.getElementById('dns-host-selector').addEventListener('change', (e) => {
    renderHostnameTopology(e.target.value);
  });

  await fetchDnsRecords();
});

async function fetchDnsRecords() {
  try {
    const res = await window.SentinelAPI.getDnsRecords();
    allDnsRecords = res.records || [];

    // Update record type counters
    const counts = { A: 0, AAAA: 0, CNAME: 0, MX: 0, TXT: 0, NS: 0, CAA: 0, SOA: 0 };
    const uniqueHosts = new Set();

    for (const r of allDnsRecords) {
      if (counts[r.recordType] !== undefined) counts[r.recordType] += 1;
      uniqueHosts.add(r.hostname);
    }

    Object.keys(counts).forEach((k) => {
      const el = document.getElementById(`cnt-${k}`);
      if (el) el.textContent = counts[k];
    });

    const hostList = Array.from(uniqueHosts).sort();
    const selector = document.getElementById('dns-host-selector');
    selector.innerHTML =
      '<option value="">Select hostname</option>' +
      hostList.map((h) => `<option value="${window.escapeHtml(h)}">${window.escapeHtml(h)}</option>`).join('');

    if (hostList.length > 0) {
      selector.value = hostList[0];
      renderHostnameTopology(hostList[0]);
    } else {
      renderHostnameTopology('');
    }

    applyDnsFilters();
  } catch (err) {
    window.showToast(err.message, true);
  }
}

function renderHostnameTopology(hostname) {
  const container = document.getElementById('dns-relationship-map');
  if (!hostname) {
    container.innerHTML = `<div class="empty-state-box">No DNS records stored yet. Run a scan to populate this view.</div>`;
    return;
  }

  const hostRecs = allDnsRecords.filter((r) => r.hostname === hostname);
  const byType = {};
  for (const r of hostRecs) {
    if (!byType[r.recordType]) byType[r.recordType] = [];
    if (!byType[r.recordType].includes(r.value)) byType[r.recordType].push(r.value);
  }

  const rowsHtml = Object.entries(byType)
    .map(
      ([type, vals]) => `
      <div class="kv-item" style="align-items:flex-start;">
        <span class="kv-label mono" style="min-width:3.5rem;">${window.escapeHtml(type)}</span>
        <span class="kv-value mono" style="text-align:left; flex:1;">
          ${vals.map((v) => `<div>${window.escapeHtml(v)}</div>`).join('')}
        </span>
      </div>`
    )
    .join('');

  container.innerHTML = `
    <div class="mono" style="margin-bottom:0.5rem; color:var(--text-primary);">${window.escapeHtml(hostname)}</div>
    <div style="border-top:1px solid var(--border-subtle);">
      ${rowsHtml || '<div class="empty-state-box">No records found for this hostname.</div>'}
    </div>
  `;
}

function applyDnsFilters() {
  const search = document.getElementById('dns-hostname').value.trim().toLowerCase();
  const type = document.getElementById('dns-type').value;

  const filtered = allDnsRecords.filter((r) => {
    if (type && r.recordType !== type) return false;
    if (search) {
      const hay = `${r.hostname} ${r.value}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  document.querySelectorAll('[data-type-pill]').forEach((c) => c.classList.toggle('active', c.getAttribute('data-type-pill') === type));

  const tbody = document.getElementById('dns-tbody');
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state-box">No DNS records match the current filter.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered
    .map(
      (r) => `
      <tr class="clickable-row" onclick="selectHostTopology('${window.escapeHtml(r.hostname)}')">
        <td class="mono">${window.escapeHtml(r.recordType)}</td>
        <td class="mono">${window.escapeHtml(r.hostname)}</td>
        <td class="mono" style="word-break:break-all;">${window.escapeHtml(r.value)}</td>
        <td class="num">${r.ttl ?? '—'}</td>
        <td><span class="badge badge-${r.resolutionStatus === 'NOERROR' ? 'ok' : 'medium'}">${window.escapeHtml(r.resolutionStatus)}</span></td>
        <td>${window.escapeHtml(r.provider)}</td>
        <td class="mono" style="color:var(--text-secondary);">${new Date(r.lastObserved).toLocaleString()}</td>
      </tr>
    `
    )
    .join('');
}

function selectHostTopology(hostname) {
  const sel = document.getElementById('dns-host-selector');
  if (sel) sel.value = hostname;
  renderHostnameTopology(hostname);
}

window.selectHostTopology = selectHostTopology;
