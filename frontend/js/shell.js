/**
 * SENTINEL — Enterprise Application Shell
 * Renders the collapsible sidebar (5 groups, 14 items), top navigation bar
 * (breadcrumbs, global search, provider status, notifications, user profile),
 * and live System Drawers (API Providers, Audit Logs, Settings/Scope).
 */

const NAV_GROUPS = [
  {
    group: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', href: '/dashboard.html', icon: 'dashboard' },
    ],
  },
  {
    group: 'Attack surface',
    items: [
      { id: 'assets', label: 'Asset Inventory', href: '/assets.html', icon: 'layers' },
      { id: 'subdomains', label: 'Subdomains', href: '/assets.html?view=subdomains', icon: 'globe' },
      { id: 'dns', label: 'DNS Intelligence', href: '/dns.html', icon: 'network' },
      { id: 'exposures', label: 'IP Exposure', href: '/findings.html?tab=exposures', icon: 'server' },
    ],
  },
  {
    group: 'Threat intelligence',
    items: [
      { id: 'vulnerabilities', label: 'Vulnerabilities', href: '/vulnerabilities.html', icon: 'bug' },
      { id: 'findings', label: 'Findings', href: '/findings.html?tab=findings', icon: 'alertTriangle' },
      { id: 'takeover', label: 'Takeover Risks', href: '/findings.html?tab=takeover', icon: 'unlink' },
    ],
  },
  {
    group: 'Operations',
    items: [
      { id: 'scans', label: 'Discovery Scans', href: '/scans.html', icon: 'radar' },
      { id: 'history', label: 'Scan History', href: '/scans.html?view=history', icon: 'history' },
      { id: 'reports', label: 'Reports', href: '/reports.html', icon: 'fileText' },
    ],
  },
  {
    group: 'System',
    items: [
      { id: 'sys-providers', label: 'API Providers', action: 'openProvidersModal', icon: 'activity' },
      { id: 'sys-audit', label: 'Audit Logs', action: 'openAuditModal', icon: 'scroll' },
      { id: 'sys-settings', label: 'Settings', action: 'openSettingsModal', icon: 'settings' },
    ],
  },
];

const PAGE_METADATA = {
  dashboard: { section: 'Overview', title: 'Security Overview' },
  assets: { section: 'Attack Surface', title: 'Asset Inventory' },
  subdomains: { section: 'Attack Surface', title: 'Discovered Subdomains' },
  dns: { section: 'Attack Surface', title: 'DNS Intelligence' },
  exposures: { section: 'Attack Surface', title: 'Public IP Exposure' },
  vulnerabilities: { section: 'Threat Intelligence', title: 'Vulnerability Intelligence' },
  findings: { section: 'Threat Intelligence', title: 'Security Findings' },
  takeover: { section: 'Threat Intelligence', title: 'Subdomain Takeover Risks' },
  scans: { section: 'Operations', title: 'Discovery Scans' },
  history: { section: 'Operations', title: 'Scan History & Drift' },
  reports: { section: 'Operations', title: 'Reports & Compliance Exports' },
};

function resolveActiveNavId(defaultPage) {
  const params = new URLSearchParams(window.location.search);
  const view = params.get('view');
  const tab = params.get('tab');
  if (defaultPage === 'assets' && view === 'subdomains') return 'subdomains';
  if (defaultPage === 'scans' && view === 'history') return 'history';
  if (defaultPage === 'findings') {
    if (tab === 'exposures') return 'exposures';
    if (tab === 'takeover') return 'takeover';
    return 'findings';
  }
  return defaultPage;
}

function buildSidebarHtml(activeId) {
  const getIcon = window.SentinelIcons ? window.SentinelIcons.getIcon : () => '';

  const groupsHtml = NAV_GROUPS.map((g) => {
    const itemsHtml = g.items
      .map((item) => {
        const isActive = item.id === activeId ? 'active' : '';
        if (item.action) {
          return `<button type="button" class="nav-item ${isActive}" data-tooltip="${item.label}" data-sys-action="${item.action}">
            ${getIcon(item.icon)}
            <span class="nav-item-label">${item.label}</span>
          </button>`;
        }
        return `<a href="${item.href}" class="nav-item ${isActive}" data-tooltip="${item.label}" data-page="${item.id}">
          ${getIcon(item.icon)}
          <span class="nav-item-label">${item.label}</span>
        </a>`;
      })
      .join('');

    return `<div class="nav-group">
      <div class="nav-group-label">${g.group}</div>
      ${itemsHtml}
    </div>`;
  }).join('');

  return `
    <div class="sidebar-header">
      <a href="/dashboard.html" class="brand-lockup">
        <div class="brand-mark">${getIcon('shield')}</div>
        <div class="brand-text">
          <span class="brand-name">SENTINEL</span>
          <span class="brand-subtitle">Attack surface</span>
        </div>
      </a>
      <button type="button" id="sidebar-collapse-btn" class="sidebar-toggle-btn" title="Toggle Sidebar">
        ${getIcon('panelLeft')}
      </button>
    </div>
    <div class="sidebar-scroll">
      ${groupsHtml}
    </div>
    <div class="sidebar-footer">
      <span class="sidebar-footer-text">Passive recon · v1.0</span>
      <span class="mono" id="sidebar-node-badge">WEB01</span>
    </div>
  `;
}

function buildTopbarHtml(activeId) {
  const getIcon = window.SentinelIcons ? window.SentinelIcons.getIcon : () => '';
  const meta = PAGE_METADATA[activeId] || { section: 'Platform', title: 'Operations' };

  return `
    <div class="topbar-left">
      <div class="breadcrumbs">
        <span>SENTINEL</span>
        <span class="breadcrumb-sep">/</span>
        <span>${meta.section}</span>
        <span class="breadcrumb-sep">/</span>
        <span class="breadcrumb-current">${meta.title}</span>
      </div>
    </div>

    <div class="topbar-center">
      <form id="global-search-form" class="global-search-wrapper">
        ${getIcon('search')}
        <input type="text" id="global-search-input" class="global-search-input" placeholder="Search assets, IPs or CVE IDs" />
      </form>
    </div>

    <div class="topbar-right">
      <button type="button" id="topbar-providers-pill" class="topbar-status" title="External intelligence providers">
        <span class="status-dot" id="topbar-providers-dot"></span>
        <span id="topbar-providers-label">Providers</span>
      </button>
      <button type="button" id="topbar-notifications-btn" class="btn btn-ghost btn-sm" title="Audit and activity log" aria-label="Audit and activity log">
        ${getIcon('bell')}
      </button>
      <span class="topbar-divider"></span>
      <span id="topbar-server" class="mono" style="color:var(--text-muted);">WEB01</span>
      <div id="topbar-user"></div>
    </div>
  `;
}

function ensureSystemModalExists() {
  if (document.getElementById('sentinel-sys-modal')) return;
  const getIcon = window.SentinelIcons ? window.SentinelIcons.getIcon : () => '';
  const modal = document.createElement('div');
  modal.id = 'sentinel-sys-modal';
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal-panel">
      <div class="modal-head">
        <h3 id="sys-modal-title">System</h3>
        <button type="button" class="btn btn-ghost btn-sm" id="sys-modal-close" aria-label="Close">${getIcon('x')}</button>
      </div>
      <div class="modal-body" id="sys-modal-body"></div>
    </div>
  `;
  document.body.appendChild(modal);

  document.getElementById('sys-modal-close').addEventListener('click', () => {
    modal.classList.remove('open');
  });
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.remove('open');
  });
}

async function openProvidersModal() {
  ensureSystemModalExists();
  const modal = document.getElementById('sentinel-sys-modal');
  const title = document.getElementById('sys-modal-title');
  const body = document.getElementById('sys-modal-body');

  title.textContent = 'External intelligence providers';
  body.innerHTML = '<div class="empty-state-box">Loading…</div>';
  modal.classList.add('open');

  try {
    const res = await window.SentinelAPI.getProvidersStatus();
    const rows = (res.providers || [])
      .map(
        (p) => `
        <tr>
          <td>${window.escapeHtml(p.name)}</td>
          <td><span class="badge badge-${p.status === 'operational' ? 'ok' : 'medium'}">${window.escapeHtml(p.status)}</span></td>
          <td class="num">${p.totalRequests}</td>
          <td class="num">${p.cacheHits}</td>
          <td class="num">${p.lastLatencyMs ? `${p.lastLatencyMs} ms` : '—'}</td>
          <td style="color:var(--text-secondary);">${p.lastSuccessAt ? new Date(p.lastSuccessAt).toLocaleTimeString() : 'No requests yet'}</td>
        </tr>
      `
      )
      .join('');

    body.innerHTML = `
      <div class="table-responsive" style="margin-bottom:0.85rem;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Status</th>
              <th class="num">Calls</th>
              <th class="num">Cache hits</th>
              <th class="num">Latency</th>
              <th>Last success</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="notice">
        <div><strong>Shodan InternetDB licensing:</strong> ${window.escapeHtml(res.shodanLicenseNotice || '')}</div>
        <div style="margin-top:0.35rem;"><strong>NIST NVD API key:</strong> ${res.nvdApiKeyConfigured ? 'Authenticated API Key Active' : 'Public Rate-Limited Tier Active (Key Hidden on Backend)'}</div>
      </div>
    `;
  } catch (err) {
    body.innerHTML = `<div class="notice notice-error">${window.escapeHtml(err.message)}</div>`;
  }
}

async function openAuditModal() {
  ensureSystemModalExists();
  const modal = document.getElementById('sentinel-sys-modal');
  const title = document.getElementById('sys-modal-title');
  const body = document.getElementById('sys-modal-body');

  title.textContent = 'Audit log';
  body.innerHTML = '<div class="empty-state-box">Loading…</div>';
  modal.classList.add('open');

  try {
    const res = await window.SentinelAPI.getActivity();
    const activities = res.activities || [];
    if (activities.length === 0) {
      body.innerHTML = '<div class="empty-state-box">No audit events recorded yet.</div>';
      return;
    }

    body.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Operator</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Node</th>
            </tr>
          </thead>
          <tbody>
            ${activities
              .map(
                (a) => `
              <tr>
                <td class="mono" style="color:var(--text-secondary);">${new Date(a.timestamp).toLocaleString()}</td>
                <td>${window.escapeHtml(a.username || 'system')}</td>
                <td class="mono">${window.escapeHtml(a.action)}</td>
                <td class="mono">${window.escapeHtml(a.resourceId || '—')}</td>
                <td class="mono" style="color:var(--text-muted);">${window.escapeHtml(a.serverId)}</td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    body.innerHTML = `<div class="notice notice-error">${window.escapeHtml(err.message)}</div>`;
  }
}

async function openSettingsModal() {
  ensureSystemModalExists();
  const modal = document.getElementById('sentinel-sys-modal');
  const title = document.getElementById('sys-modal-title');
  const body = document.getElementById('sys-modal-body');

  title.textContent = 'Settings';
  modal.classList.add('open');

  try {
    const [ver, ready, scope] = await Promise.all([
      window.SentinelAPI.getVersion(),
      window.SentinelAPI.getReady(),
      window.SentinelAPI.getAuthorizedDomains(),
    ]);

    const domainsHtml = (scope.domains || [])
      .map((d) => `<span class="badge badge-neutral mono">${window.escapeHtml(d.domain)}</span>`)
      .join(' ');

    body.innerHTML = `
      <div class="kv-grid" style="margin-bottom:1rem;">
        <div class="kv-item"><div class="kv-label">Version</div><div class="kv-value mono">v${window.escapeHtml(ver.version)} (API ${window.escapeHtml(ver.apiVersion)})</div></div>
        <div class="kv-item"><div class="kv-label">Application node</div><div class="kv-value mono">${window.escapeHtml(ver.serverId.toUpperCase())} (${window.escapeHtml(ver.nodeVersion)})</div></div>
        <div class="kv-item"><div class="kv-label">Database</div><div class="kv-value mono">${window.escapeHtml(ready.checks?.database?.mode || 'PostgreSQL')} (${ready.checks?.database?.latencyMs ?? 0} ms)</div></div>
        <div class="kv-item"><div class="kv-label">Reconnaissance policy</div><div class="kv-value">Passive only, explicit scope</div></div>
      </div>
      <div class="section-title" style="margin-top:0;">Authorized domains</div>
      <div style="display:flex; flex-wrap:wrap; gap:0.35rem; margin-bottom:0.6rem;">${domainsHtml}</div>
      <a href="/scans.html" class="btn btn-secondary btn-sm">Manage scope</a>

      <div class="section-title" style="margin-top:1.5rem;">Danger zone</div>
      <div class="notice notice-danger" style="display:flex; align-items:center; justify-content:space-between; gap:1rem; flex-wrap:wrap;">
        <div>
          <div style="color:var(--text-primary); font-weight:600;">Clear all reconnaissance data</div>
          <div style="font-size:var(--text-xs);">Deletes all scans, assets, DNS records, exposures, CVEs, findings and provider caches.</div>
        </div>
        <button type="button" id="sys-clear-data-btn" class="btn btn-danger btn-sm">Clear data</button>
      </div>
    `;
    const clearBtn = document.getElementById('sys-clear-data-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', async () => {
        clearBtn.disabled = true;
        clearBtn.textContent = 'Clearing…';
        try {
          await window.SentinelAPI.resetSystemData();
          window.showToast('All system scan data and caches cleared');
          modal.classList.remove('open');
          window.location.reload();
        } catch (err) {
          window.showToast(`Reset failed: ${err.message}`, true);
          clearBtn.disabled = false;
          clearBtn.textContent = 'Clear data';
        }
      });
    }
  } catch (err) {
    body.innerHTML = `<div class="notice notice-error">${window.escapeHtml(err.message)}</div>`;
  }
}

async function initEnterpriseShell(defaultPage) {
  const activeId = resolveActiveNavId(defaultPage);
  const sidebarEl = document.querySelector('.app-sidebar') || document.querySelector('.sidebar');
  const topbarEl = document.querySelector('.app-topbar') || document.querySelector('.topbar');

  if (localStorage.getItem('sentinel_sidebar_collapsed') === '1') {
    document.body.classList.add('sidebar-collapsed');
  }

  if (sidebarEl) {
    sidebarEl.className = 'app-sidebar';
    sidebarEl.innerHTML = buildSidebarHtml(activeId);
  }

  if (topbarEl) {
    topbarEl.className = 'app-topbar';
    topbarEl.innerHTML = buildTopbarHtml(activeId);
  }

  const collapseBtn = document.getElementById('sidebar-collapse-btn');
  if (collapseBtn) {
    collapseBtn.addEventListener('click', () => {
      document.body.classList.toggle('sidebar-collapsed');
      const isCol = document.body.classList.contains('sidebar-collapsed');
      localStorage.setItem('sentinel_sidebar_collapsed', isCol ? '1' : '0');
    });
  }

  document.querySelectorAll('[data-sys-action]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const act = btn.getAttribute('data-sys-action');
      if (act === 'openProvidersModal') openProvidersModal();
      if (act === 'openAuditModal') openAuditModal();
      if (act === 'openSettingsModal') openSettingsModal();
    });
  });

  const provPill = document.getElementById('topbar-providers-pill');
  if (provPill) provPill.addEventListener('click', openProvidersModal);

  const notifBtn = document.getElementById('topbar-notifications-btn');
  if (notifBtn) notifBtn.addEventListener('click', openAuditModal);

  const searchForm = document.getElementById('global-search-form');
  if (searchForm) {
    searchForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const q = document.getElementById('global-search-input').value.trim();
      if (!q) return;
      if (/^CVE-\d{4}-/i.test(q)) {
        window.location.href = `/vulnerabilities.html?search=${encodeURIComponent(q)}`;
      } else {
        window.location.href = `/assets.html?search=${encodeURIComponent(q)}`;
      }
    });
  }

  // Hydrate server node badge & provider health status
  try {
    const [health, prov] = await Promise.all([
      window.SentinelAPI.getHealth(),
      window.SentinelAPI.getProvidersStatus(),
    ]);
    const srvEl = document.getElementById('topbar-server');
    const sideBadge = document.getElementById('sidebar-node-badge');
    if (srvEl) srvEl.textContent = health.serverId.toUpperCase();
    if (sideBadge) sideBadge.textContent = health.serverId.toUpperCase();

    const onlineCount = (prov.providers || []).filter((p) => p.status === 'operational').length;
    const totalCount = (prov.providers || []).length || 4;
    const provLabel = document.getElementById('topbar-providers-label');
    if (provLabel) provLabel.textContent = `Providers ${onlineCount}/${totalCount}`;
    const provDot = document.getElementById('topbar-providers-dot');
    if (provDot && onlineCount < totalCount) provDot.classList.add('degraded');
  } catch (_) {}

  // Hydrate user profile session
  const userEl = document.getElementById('topbar-user');
  try {
    const me = await window.SentinelAPI.getMe();
    if (userEl && me.authenticated && me.user) {
      userEl.innerHTML = `
        <div style="display:flex; align-items:center; gap:0.5rem;">
          <span class="topbar-user-name"><strong>${window.escapeHtml(me.user.username)}</strong> · ${window.escapeHtml(me.user.role)}</span>
          <button type="button" id="logout-btn" class="btn btn-ghost btn-sm">Sign out</button>
        </div>
      `;
      document.getElementById('logout-btn').addEventListener('click', async () => {
        await window.SentinelAPI.logout();
        window.location.href = '/login.html';
      });
    } else if (userEl) {
      userEl.innerHTML = `<a href="/login.html" class="btn btn-primary btn-sm">Sign in</a>`;
    }
  } catch (_) {
    if (userEl) {
      userEl.innerHTML = `<a href="/login.html" class="btn btn-primary btn-sm">Sign in</a>`;
    }
  }
}

window.initShell = initEnterpriseShell;
window.SentinelShell = {
  initEnterpriseShell,
  openProvidersModal,
  openAuditModal,
  openSettingsModal,
};
