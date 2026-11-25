let allAssets = [];
let filteredAssets = [];
let selectedAssetIds = new Set();
let currentPage = 1;
let pageSize = 25;
let sortField = 'riskRank';
let sortAsc = false;
let activeDrawerAsset = null;
let activeDrawerTab = 'overview';

const RISK_RANK = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

function deriveAssetType(a) {
  if (!a.resolves) return 'Dormant CT';
  if (a.cname) return 'CNAME Alias';
  if (a.subdomain === a.domain) return 'Root Domain';
  return 'Subdomain';
}

document.addEventListener('DOMContentLoaded', async () => {
  await window.initShell('assets');

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('search')) {
    document.getElementById('asset-search').value = urlParams.get('search');
  }
  if (urlParams.get('view') === 'subdomains') {
    document.getElementById('assets-page-title').textContent = 'Subdomains';
  }

  bindAssetEvents();
  await fetchAssetsFromBackend();
});

function bindAssetEvents() {
  document.getElementById('asset-apply-btn').addEventListener('click', () => {
    currentPage = 1;
    applyClientFiltersAndSort();
  });

  document.getElementById('asset-search').addEventListener('input', () => {
    currentPage = 1;
    applyClientFiltersAndSort();
  });

  ['asset-type-filter', 'asset-risk-filter', 'asset-dns-filter'].forEach((id) => {
    document.getElementById(id).addEventListener('change', () => {
      currentPage = 1;
      applyClientFiltersAndSort();
    });
  });

  document.getElementById('asset-clear-btn').addEventListener('click', () => {
    document.getElementById('asset-search').value = '';
    document.getElementById('asset-type-filter').value = '';
    document.getElementById('asset-risk-filter').value = '';
    document.getElementById('asset-dns-filter').value = '';
    currentPage = 1;
    applyClientFiltersAndSort();
  });

  // Sortable headers
  document.querySelectorAll('#assets-table th.sortable').forEach((th) => {
    th.addEventListener('click', () => {
      const field = th.getAttribute('data-sort');
      if (sortField === field) {
        sortAsc = !sortAsc;
      } else {
        sortField = field;
        sortAsc = true;
      }
      applyClientFiltersAndSort();
    });
  });

  // Pagination controls
  document.getElementById('assets-page-size').addEventListener('change', (e) => {
    pageSize = parseInt(e.target.value, 10) || 25;
    currentPage = 1;
    renderAssetsTable();
  });

  document.getElementById('assets-prev-btn').addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage -= 1;
      renderAssetsTable();
    }
  });

  document.getElementById('assets-next-btn').addEventListener('click', () => {
    const totalPages = Math.max(Math.ceil(filteredAssets.length / pageSize), 1);
    if (currentPage < totalPages) {
      currentPage += 1;
      renderAssetsTable();
    }
  });

  // Column visibility menu
  const colBtn = document.getElementById('col-vis-btn');
  const colMenu = document.getElementById('col-vis-menu');
  colBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    colMenu.classList.toggle('open');
  });
  document.addEventListener('click', (e) => {
    if (!colMenu.contains(e.target) && e.target !== colBtn) {
      colMenu.classList.remove('open');
    }
  });

  document.querySelectorAll('[data-col-toggle]').forEach((cb) => {
    cb.addEventListener('change', () => {
      applyColumnVisibility();
    });
  });

  // Select All checkbox
  document.getElementById('select-all-assets').addEventListener('change', (e) => {
    const checked = e.target.checked;
    filteredAssets.forEach((a) => {
      if (checked) selectedAssetIds.add(a.id);
      else selectedAssetIds.delete(a.id);
    });
    updateSelectionBadge();
    renderAssetsTable();
  });

  // Drawer tabs & close
  document.getElementById('drawer-close-btn').addEventListener('click', () => {
    document.getElementById('asset-drawer').classList.remove('open');
  });
  document.getElementById('asset-drawer').addEventListener('click', (e) => {
    if (e.target.id === 'asset-drawer') {
      document.getElementById('asset-drawer').classList.remove('open');
    }
  });

  document.querySelectorAll('[data-drawer-tab]').forEach((tabBtn) => {
    tabBtn.addEventListener('click', () => {
      document.querySelectorAll('[data-drawer-tab]').forEach((b) => b.classList.remove('active'));
      tabBtn.classList.add('active');
      activeDrawerTab = tabBtn.getAttribute('data-drawer-tab');
      renderDrawerTabContent();
    });
  });
}

async function fetchAssetsFromBackend() {
  const urlParams = new URLSearchParams(window.location.search);
  const query = { limit: 250 };
  if (urlParams.get('scanId')) query.scanId = urlParams.get('scanId');

  try {
    const res = await window.SentinelAPI.getAssets(query);
    allAssets = (res.assets || []).map((a) => ({
      ...a,
      assetType: deriveAssetType(a),
      portsCount: (a.exposedPorts || []).length,
      cvesCount: (a.associatedCves || []).length,
      riskRank: RISK_RANK[a.riskLevel] || 1,
    }));
    applyClientFiltersAndSort();
  } catch (err) {
    window.showToast(`Failed to load assets: ${err.message}`, true);
  }
}

function applyClientFiltersAndSort() {
  const search = document.getElementById('asset-search').value.trim().toLowerCase();
  const typeFilter = document.getElementById('asset-type-filter').value;
  const riskFilter = document.getElementById('asset-risk-filter').value;
  const dnsFilter = document.getElementById('asset-dns-filter').value;

  filteredAssets = allAssets.filter((a) => {
    if (typeFilter && a.assetType !== typeFilter) return false;
    if (riskFilter && a.riskLevel !== riskFilter) return false;
    if (dnsFilter && a.dnsStatus !== dnsFilter) return false;
    if (search) {
      const hay = `${a.subdomain} ${a.domain} ${a.ipAddress || ''} ${a.ipv6Address || ''} ${a.cname || ''} ${a.hostingProvider || ''}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  filteredAssets.sort((a, b) => {
    const valA = a[sortField] ?? '';
    const valB = b[sortField] ?? '';
    if (typeof valA === 'number' && typeof valB === 'number') {
      return sortAsc ? valA - valB : valB - valA;
    }
    return sortAsc
      ? String(valA).localeCompare(String(valB))
      : String(valB).localeCompare(String(valA));
  });

  renderAssetsTable();
}

function updateSelectionBadge() {
  const badge = document.getElementById('selected-rows-badge');
  if (selectedAssetIds.size > 0) {
    badge.style.display = 'inline-flex';
    badge.textContent = `${selectedAssetIds.size} selected`;
  } else {
    badge.style.display = 'none';
  }
}

function applyColumnVisibility() {
  document.querySelectorAll('[data-col-toggle]').forEach((cb) => {
    const colClass = cb.getAttribute('data-col-toggle');
    const visible = cb.checked;
    document.querySelectorAll(`.${colClass}`).forEach((cell) => {
      cell.style.display = visible ? '' : 'none';
    });
  });
}

function renderAssetsTable() {
  const tbody = document.getElementById('assets-tbody');
  const total = filteredAssets.length;
  const totalPages = Math.max(Math.ceil(total / pageSize), 1);
  if (currentPage > totalPages) currentPage = totalPages;

  const startIdx = (currentPage - 1) * pageSize;
  const slice = filteredAssets.slice(startIdx, startIdx + pageSize);

  document.getElementById('assets-pagination-info').textContent =
    total === 0
      ? 'Showing 0 of 0 assets'
      : `Showing ${startIdx + 1}–${Math.min(startIdx + slice.length, total)} of ${total} assets`;
  document.getElementById('assets-page-indicator').textContent = `Page ${currentPage} / ${totalPages}`;
  document.getElementById('assets-prev-btn').disabled = currentPage <= 1;
  document.getElementById('assets-next-btn').disabled = currentPage >= totalPages;

  if (slice.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10">
      <div class="empty-state-box">
        <div>No assets match the current filters.</div>
      </div>
    </td></tr>`;
    return;
  }

  tbody.innerHTML = slice
    .map((a) => {
      const isChecked = selectedAssetIds.has(a.id) ? 'checked' : '';
      const portsDisplay =
        (a.exposedPorts || []).length > 0
          ? `<span class="mono">${(a.exposedPorts || []).slice(0, 5).join(', ')}</span>` +
            (a.exposedPorts.length > 5 ? `<span class="mono" style="color:var(--text-muted);"> +${a.exposedPorts.length - 5}</span>` : '')
          : '<span style="color:var(--text-muted);">—</span>';

      const cvesDisplay =
        (a.associatedCves || []).length > 0
          ? `<span class="num" style="color:var(--sev-high-text);">${a.associatedCves.length}</span>`
          : '<span style="color:var(--text-muted);">0</span>';

      return `
        <tr class="clickable-row" data-asset-id="${a.id}">
          <td onclick="event.stopPropagation()">
            <input type="checkbox" class="asset-row-cb" data-id="${a.id}" ${isChecked} />
          </td>
          <td>
            <div class="mono" style="font-size:var(--text-sm);">${window.escapeHtml(a.subdomain)}</div>
            ${a.cname ? `<div class="mono" style="color:var(--text-muted);">↳ CNAME ${window.escapeHtml(a.cname)}</div>` : ''}
          </td>
          <td class="col-type" style="color:var(--text-secondary);">${window.escapeHtml(a.assetType)}</td>
          <td class="col-domain mono">${window.escapeHtml(a.domain)}</td>
          <td class="col-ip mono">
            <div>${window.escapeHtml(a.ipAddress || '—')}</div>
            ${a.ipv6Address ? `<div style="color:var(--text-muted);">${window.escapeHtml(a.ipv6Address.slice(0, 22))}</div>` : ''}
          </td>
          <td class="col-dns"><span class="badge badge-${a.resolves ? 'ok' : 'info'}">${window.escapeHtml(a.dnsStatus)}</span></td>
          <td class="col-services">${portsDisplay}</td>
          <td class="col-vulns num">${cvesDisplay}</td>
          <td>${window.riskBadgeHtml(a.riskLevel)}</td>
          <td class="col-observed mono" style="color:var(--text-secondary);">${new Date(a.lastObserved).toLocaleDateString()}</td>
        </tr>
      `;
    })
    .join('');

  applyColumnVisibility();

  // Bind row click to open detail drawer
  tbody.querySelectorAll('tr.clickable-row').forEach((tr) => {
    tr.addEventListener('click', () => {
      const id = tr.getAttribute('data-asset-id');
      openAssetDrawer(id);
    });
  });

  tbody.querySelectorAll('.asset-row-cb').forEach((cb) => {
    cb.addEventListener('change', (e) => {
      const id = Number(e.target.getAttribute('data-id'));
      if (e.target.checked) selectedAssetIds.add(id);
      else selectedAssetIds.delete(id);
      updateSelectionBadge();
    });
  });
}

async function openAssetDrawer(assetId) {
  const drawer = document.getElementById('asset-drawer');
  const titleEl = document.getElementById('drawer-asset-name');
  const bodyEl = document.getElementById('drawer-tab-content');

  drawer.classList.add('open');
  titleEl.textContent = 'Loading…';
  bodyEl.innerHTML = '<div class="empty-state-box">Loading…</div>';

  try {
    activeDrawerAsset = await window.SentinelAPI.getAssetById(assetId);
    titleEl.textContent = activeDrawerAsset.subdomain;
    activeDrawerTab = 'overview';
    document.querySelectorAll('[data-drawer-tab]').forEach((b) => {
      b.classList.toggle('active', b.getAttribute('data-drawer-tab') === 'overview');
    });
    renderDrawerTabContent();
  } catch (err) {
    bodyEl.innerHTML = `<div class="notice notice-error">${window.escapeHtml(err.message)}</div>`;
  }
}

function renderDrawerTabContent() {
  const a = activeDrawerAsset;
  const bodyEl = document.getElementById('drawer-tab-content');
  if (!a || !bodyEl) return;
  const rc = a.riskClassification || {};

  if (activeDrawerTab === 'overview') {
    bodyEl.innerHTML = `
      <div class="kv-grid">
        <div class="kv-item"><div class="kv-label">Risk</div><div class="kv-value">${window.riskBadgeHtml(a.riskLevel)}</div></div>
        <div class="kv-item"><div class="kv-label">Confidence</div><div class="kv-value">${window.escapeHtml(rc.confidence || 'Authoritative')}</div></div>
        <div class="kv-item"><div class="kv-label">IPv4</div><div class="kv-value mono">${window.escapeHtml(a.ipAddress || 'Unresolved')}</div></div>
        <div class="kv-item"><div class="kv-label">IPv6</div><div class="kv-value mono">${window.escapeHtml(a.ipv6Address || 'None')}</div></div>
        <div class="kv-item"><div class="kv-label">Hosting</div><div class="kv-value">${window.escapeHtml(a.hostingProvider || 'Standard')}</div></div>
        <div class="kv-item"><div class="kv-label">DNS status</div><div class="kv-value"><span class="badge badge-${a.resolves ? 'ok' : 'info'}">${window.escapeHtml(a.dnsStatus)}</span></div></div>
      </div>

      <div class="section-title">Risk explanation</div>
      <div class="kv-grid" style="grid-template-columns:1fr;">
        <div class="kv-item"><span class="kv-label">Reason</span><span class="kv-value">${window.escapeHtml(rc.reason || 'Active asset')}</span></div>
        <div class="kv-item"><span class="kv-label">Evidence</span><span class="kv-value">${window.escapeHtml(rc.supportingEvidence || 'Cloudflare DoH & crt.sh')}</span></div>
        <div class="kv-item"><span class="kv-label">Recommended action</span><span class="kv-value">${window.escapeHtml(rc.recommendedAction || 'Routine monitoring')}</span></div>
        <div class="kv-item"><span class="kv-label">Sources</span><span class="kv-value mono">${window.escapeHtml(a.source)}</span></div>
      </div>
    `;
    return;
  }

  if (activeDrawerTab === 'dns') {
    const records = a.dnsRecords || [];
    if (records.length === 0) {
      bodyEl.innerHTML = '<div class="empty-state-box">No DNS records stored for this hostname.</div>';
      return;
    }
    bodyEl.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead><tr><th>Type</th><th>Hostname</th><th>Value</th><th>TTL</th><th>Status</th></tr></thead>
          <tbody>
            ${records
              .map(
                (r) => `
              <tr>
                <td class="mono">${window.escapeHtml(r.recordType)}</td>
                <td class="mono">${window.escapeHtml(r.hostname)}</td>
                <td class="mono">${window.escapeHtml(r.value)}</td>
                <td class="mono">${r.ttl ?? '—'}</td>
                <td><span class="badge badge-ok">${window.escapeHtml(r.resolutionStatus)}</span></td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
    return;
  }

  if (activeDrawerTab === 'certificates') {
    const certs = a.certificates || [];
    if (certs.length === 0) {
      bodyEl.innerHTML = `<div class="empty-state-box">No specific crt.sh certificate entries linked to ${window.escapeHtml(a.subdomain)}.</div>`;
      return;
    }
    bodyEl.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead><tr><th>Cert ID</th><th>Common Name</th><th>Issuer</th><th>Valid Until</th></tr></thead>
          <tbody>
            ${certs
              .map(
                (c) => `
              <tr>
                <td class="mono">${window.escapeHtml(c.certificateId)}</td>
                <td class="mono">${window.escapeHtml(c.commonName)}</td>
                <td style="font-size:0.74rem;">${window.escapeHtml(c.issuerName)}</td>
                <td class="mono">${window.escapeHtml((c.notAfter || '').slice(0, 10))}</td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
    return;
  }

  if (activeDrawerTab === 'exposures') {
    const exps = a.exposures || [];
    if (exps.length === 0) {
      bodyEl.innerHTML = '<div class="empty-state-box">No public IP exposures observed on Shodan InternetDB for this asset.</div>';
      return;
    }
    bodyEl.innerHTML = exps
      .map(
        (e) => `
        <div class="section-title" style="margin-top:0;"><span class="mono" style="text-transform:none;">${window.escapeHtml(e.ipAddress)}</span><span style="font-weight:400;text-transform:none;letter-spacing:0;">Shodan InternetDB</span></div>
        <div class="kv-grid" style="grid-template-columns:1fr; margin-bottom:1rem;">
          <div class="kv-item"><span class="kv-label">Open ports</span><span class="kv-value mono">${(e.openPorts || []).join(', ') || 'None'}</span></div>
          <div class="kv-item"><span class="kv-label">CPE</span><span class="kv-value mono">${(e.cpes || []).join(', ') || 'None'}</span></div>
          <div class="kv-item"><span class="kv-label">Tags</span><span class="kv-value">${(e.tags || []).join(', ') || 'None'}</span></div>
        </div>
      `
      )
      .join('');
    return;
  }

  if (activeDrawerTab === 'vulnerabilities') {
    const vulns = a.vulnerabilities || [];
    if (vulns.length === 0) {
      bodyEl.innerHTML = '<div class="empty-state-box">No observed CVE associations for this asset.</div>';
      return;
    }
    bodyEl.innerHTML = vulns
      .map(
        (v) => `
        <div style="padding:0.6rem 0; border-bottom:1px solid var(--border-subtle);">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
            <span class="mono" style="color:var(--text-primary);">${window.escapeHtml(v.cveId)}</span>
            <span>${window.riskBadgeHtml(v.severity)} <span class="mono">CVSS ${v.cvssScore ?? 'N/A'}</span></span>
          </div>
          <div style="font-size:var(--text-xs); color:var(--text-muted); margin-bottom:0.25rem;">${window.escapeHtml(v.verificationStatus)}</div>
          <div style="font-size:var(--text-sm); color:var(--text-secondary);">${window.escapeHtml(v.description)}</div>
        </div>
      `
      )
      .join('');
    return;
  }

  if (activeDrawerTab === 'history') {
    const hist = a.history || [];
    bodyEl.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead><tr><th>Scan</th><th>IP address</th><th>DNS</th><th>Ports</th><th>Risk</th><th>Observed</th></tr></thead>
          <tbody>
            ${hist
              .map(
                (h) => `
              <tr>
                <td class="mono">${window.escapeHtml(h.scanId)}</td>
                <td class="mono">${window.escapeHtml(h.ipAddress || '—')}</td>
                <td>${window.escapeHtml(h.dnsStatus)}</td>
                <td class="mono">${(h.exposedPorts || []).join(', ') || '—'}</td>
                <td>${window.riskBadgeHtml(h.riskLevel)}</td>
                <td class="mono">${new Date(h.lastObserved).toLocaleString()}</td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
  }
}
