const API_BASE = '/api/v1';

const SentinelAPI = {
  csrfToken: localStorage.getItem('sentinel_csrf') || null,

  setCsrfToken(token) {
    this.csrfToken = token;
    if (token) {
      localStorage.setItem('sentinel_csrf', token);
    } else {
      localStorage.removeItem('sentinel_csrf');
    }
  },

  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    };
    if (this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'same-origin',
    });

    const contentType = response.headers.get('content-type') || '';
    const data = contentType.includes('application/json')
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      const error = new Error((data && data.message) || `HTTP Error ${response.status}`);
      error.status = response.status;
      error.payload = data;
      throw error;
    }
    return data;
  },

  getHealth() { return this.request('/health'); },
  getReady() { return this.request('/ready'); },
  getVersion() { return this.request('/version'); },
  getProvidersStatus() { return this.request('/providers/status'); },
  resetSystemData() {
    return this.request('/system/reset', { method: 'POST' });
  },

  async login(username, password) {
    const res = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    if (res.csrfToken) this.setCsrfToken(res.csrfToken);
    return res;
  },

  async logout() {
    const res = await this.request('/auth/logout', { method: 'POST' });
    this.setCsrfToken(null);
    return res;
  },

  async getMe() {
    const res = await this.request('/auth/me');
    if (res.csrfToken) this.setCsrfToken(res.csrfToken);
    return res;
  },

  getDashboardOverview() { return this.request('/dashboard/overview'); },
  getRiskDistribution() { return this.request('/dashboard/risk-distribution'); },
  getActivity() { return this.request('/dashboard/activity'); },

  getAuthorizedDomains() { return this.request('/scans/authorized-domains'); },
  addAuthorizedDomain(domain, description) {
    return this.request('/scans/authorized-domains', {
      method: 'POST',
      body: JSON.stringify({ domain, description }),
    });
  },

  startScan(payload) {
    return this.request('/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },
  getScans() { return this.request('/scans'); },
  getScanById(id) { return this.request(`/scans/${encodeURIComponent(id)}`); },
  getScanProgress(id) { return this.request(`/scans/${encodeURIComponent(id)}/progress`); },
  cancelScan(id) {
    return this.request(`/scans/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
  },
  compareScans(idA, idB) {
    return this.request(`/scans/${encodeURIComponent(idA)}/compare/${encodeURIComponent(idB)}`);
  },

  getAssets(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request(`/assets${qs ? `?${qs}` : ''}`);
  },
  getAssetById(id) { return this.request(`/assets/${encodeURIComponent(id)}`); },

  getDnsRecords(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request(`/dns${qs ? `?${qs}` : ''}`);
  },

  getExposures(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request(`/exposures${qs ? `?${qs}` : ''}`);
  },

  getFindings(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request(`/findings${qs ? `?${qs}` : ''}`);
  },

  getVulnerabilities(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.request(`/vulnerabilities${qs ? `?${qs}` : ''}`);
  },

  getReports() { return this.request('/reports'); },
};

function showToast(message, isError = false) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const el = document.createElement('div');
  el.className = 'toast';
  if (isError) el.style.borderLeftColor = '#ef4444';
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function riskBadgeHtml(level) {
  const clean = String(level || 'Informational');
  const cls = `badge-${clean.toLowerCase()}`;
  return `<span class="badge ${cls}">${escapeHtml(clean)}</span>`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function initShell(activePage) {
  const links = document.querySelectorAll('.nav-link');
  links.forEach((l) => {
    if (l.dataset.page === activePage) l.classList.add('active');
  });

  const userEl = document.getElementById('topbar-user');
  const serverEl = document.getElementById('topbar-server');

  try {
    const health = await SentinelAPI.getHealth();
    if (serverEl) {
      serverEl.textContent = `Node: ${health.serverId.toUpperCase()}`;
    }
  } catch (_) {}

  try {
    const me = await SentinelAPI.getMe();
    if (userEl && me.authenticated) {
      userEl.innerHTML = `<span>${escapeHtml(me.user.username)} (${escapeHtml(me.user.role)})</span> <button id="logout-btn" class="btn btn-secondary" style="padding:0.25rem 0.6rem;font-size:0.75rem;margin-left:0.5rem;">Sign Out</button>`;
      const btn = document.getElementById('logout-btn');
      if (btn) {
        btn.addEventListener('click', async () => {
          await SentinelAPI.logout();
          window.location.href = '/login.html';
        });
      }
    }
  } catch (_) {
    if (userEl) {
      userEl.innerHTML = `<a href="/login.html" class="btn btn-secondary" style="padding:0.25rem 0.6rem;font-size:0.78rem;">Sign In</a>`;
    }
  }
}

window.SentinelAPI = SentinelAPI;
window.showToast = showToast;
window.riskBadgeHtml = riskBadgeHtml;
window.escapeHtml = escapeHtml;
window.initShell = initShell;
