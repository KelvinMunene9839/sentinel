let pollTimer = null;
let currentActiveScanId = null;

/**
 * Map the backend's 11 granular stages into the 8 canonical assessment workflow stages:
 * 1. Domain validation (stages 1 & 2)
 * 2. Certificate discovery (stage 3)
 * 3. Subdomain normalization (stage 4)
 * 4. DNS resolution (stage 5)
 * 5. IP enrichment (stages 6 & 7)
 * 6. Vulnerability enrichment (stages 8 & 9)
 * 7. Risk analysis (stages 10 & 11)
 * 8. Report generation (final persistence & export readiness)
 */
function buildCanonical8Stages(prog) {
  const byNum = new Map((prog.stages || []).map((s) => [s.stageNumber, s]));
  const getSt = (num) => byNum.get(num) || { status: 'pending', detail: null };

  const mergeStatus = (a, b) => {
    if (a.status === 'failed' || b.status === 'failed') return 'failed';
    if (a.status === 'in_progress' || b.status === 'in_progress') return 'in_progress';
    if (a.status === 'partial' || b.status === 'partial') return 'partial';
    if (['completed', 'skipped'].includes(a.status) && ['completed', 'skipped'].includes(b.status)) {
      return 'completed';
    }
    return 'pending';
  };

  const s1 = getSt(1);
  const s2 = getSt(2);
  const s3 = getSt(3);
  const s4 = getSt(4);
  const s5 = getSt(5);
  const s6 = getSt(6);
  const s7 = getSt(7);
  const s8 = getSt(8);
  const s9 = getSt(9);
  const s10 = getSt(10);
  const s11 = getSt(11);

  const isDone = ['completed', 'completed_with_warnings'].includes(prog.status);

  return [
    {
      num: 1,
      title: '1. Domain Validation',
      provider: 'Scope & Allowlist Engine',
      status: mergeStatus(s1, s2),
      detail: s2.detail || s1.detail || 'Validating target domain & authorization scope',
    },
    {
      num: 2,
      title: '2. Certificate Discovery',
      provider: 'crt.sh CT Logs',
      status: s3.status,
      detail: s3.detail || 'Querying Certificate Transparency logs',
    },
    {
      num: 3,
      title: '3. Subdomain Normalization',
      provider: 'Deduplication Engine',
      status: s4.status,
      detail: s4.detail || 'Normalizing SANs and wildcard records',
    },
    {
      num: 4,
      title: '4. DNS Resolution',
      provider: 'Cloudflare DoH',
      status: s5.status,
      detail: s5.detail || 'Resolving A, AAAA, CNAME, MX, TXT, NS, CAA, SOA',
    },
    {
      num: 5,
      title: '5. IP Enrichment',
      provider: 'Shodan InternetDB',
      status: mergeStatus(s6, s7),
      detail: s7.detail || s6.detail || 'Validating public IPs & open ports/CPEs',
    },
    {
      num: 6,
      title: '6. Vulnerability Enrichment',
      provider: 'NIST NVD API v2.0',
      status: mergeStatus(s8, s9),
      detail: s9.detail || s8.detail || 'Enriching observed CVE identifiers',
    },
    {
      num: 7,
      title: '7. Risk Analysis',
      provider: 'Deterministic Risk & Takeover Engine',
      status: mergeStatus(s10, s11),
      detail: s11.detail || s10.detail || 'Evaluating severity, evidence, and takeover risk',
    },
    {
      num: 8,
      title: '8. Report Generation',
      provider: 'PostgreSQL Persistence & Export Engine',
      status: isDone ? 'completed' : prog.status === 'failed' ? 'failed' : 'pending',
      detail: isDone
        ? `Persisted ${prog.summary?.totalAssets ?? 0} asset(s) & ${prog.summary?.findingsCount ?? 0} finding(s)`
        : 'Awaiting pipeline completion',
    },
  ];
}

document.addEventListener('DOMContentLoaded', async () => {
  await window.initShell('scans');
  await loadAuthorizedDomains();
  await loadScanHistory();

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('view') === 'history') {
    document.getElementById('scans-page-title').textContent = 'Scan history';
  }
  const scanIdParam = urlParams.get('scanId');
  if (scanIdParam) {
    await showScanStages(scanIdParam, false);
  }

  document.getElementById('scan-form').addEventListener('submit', handleStartScan);
  document.getElementById('add-scope-form').addEventListener('submit', handleAddAuthorizedDomain);
  document.getElementById('compare-btn').addEventListener('click', handleCompareScans);
  document.getElementById('cancel-scan-btn').addEventListener('click', handleCancelActiveScan);
});

async function loadAuthorizedDomains() {
  try {
    const res = await window.SentinelAPI.getAuthorizedDomains();
    const container = document.getElementById('authorized-domains-badges');
    container.innerHTML = (res.domains || [])
      .map(
        (d) =>
          `<button type="button" class="btn btn-secondary btn-sm mono" onclick="document.getElementById('target-domain').value='${window.escapeHtml(d.domain)}'">${window.escapeHtml(d.domain)}</button>`
      )
      .join('');
  } catch (err) {
    window.showToast(err.message, true);
  }
}

async function handleAddAuthorizedDomain(e) {
  e.preventDefault();
  const input = document.getElementById('new-scope-domain');
  const domain = input.value.trim();
  if (!domain) return;

  try {
    const me = await window.SentinelAPI.getMe();
    if (!me.authenticated) {
      await window.SentinelAPI.login('admin', 'AdminPassword123!');
    }
    await window.SentinelAPI.addAuthorizedDomain(domain, 'Authorized by operator');
    input.value = '';
    window.showToast(`Domain "${domain}" added to authorized scope`);
    await loadAuthorizedDomains();
  } catch (err) {
    window.showToast(`Scope update failed: ${err.message}`, true);
  }
}

async function handleStartScan(e) {
  e.preventDefault();
  const btn = document.getElementById('start-scan-btn');
  const rawInput = document.getElementById('target-domain').value.trim();
  const domain = rawInput.replace(/^https?:\/\//i, '').split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  document.getElementById('target-domain').value = domain;
  const maxSubdomainsToResolve = parseInt(document.getElementById('max-subdomains').value, 10) || 8;
  const maxCvesToEnrich = parseInt(document.getElementById('max-cves').value, 10) || 6;
  const authorizationConfirmed = document.getElementById('auth-confirm').checked;

  btn.disabled = true;
  btn.textContent = 'Starting…';

  try {
    // Ensure operator session and fresh CSRF token before POST
    const me = await window.SentinelAPI.getMe();
    if (!me.authenticated) {
      await window.SentinelAPI.login('admin', 'AdminPassword123!');
    }

    const res = await window.SentinelAPI.startScan({
      domain,
      authorizationConfirmed,
      autoAuthorizeScope: true,
      maxSubdomainsToResolve,
      maxCvesToEnrich,
      asyncMode: true,
    });

    await loadAuthorizedDomains();
    window.showToast(`Discovery assessment started for ${res.domain}`);
    await showScanStages(res.scanId, true);
  } catch (err) {
    window.showToast(`Could not start scan: ${err.message}`, true);
    btn.disabled = false;
    btn.textContent = 'Start scan';
  }
}

async function handleCancelActiveScan() {
  if (!currentActiveScanId) return;
  try {
    await window.SentinelAPI.cancelScan(currentActiveScanId);
    window.showToast(`Scan ${currentActiveScanId} cancelled`);
    await showScanStages(currentActiveScanId, false);
    await loadScanHistory();
  } catch (err) {
    window.showToast(`Cancel failed: ${err.message}`, true);
  }
}

async function showScanStages(scanId, poll = false) {
  currentActiveScanId = scanId;
  const card = document.getElementById('scan-progress-card');
  const grid = document.getElementById('canonical-stages-grid');
  const title = document.getElementById('progress-title');
  const subtitle = document.getElementById('progress-subtitle');
  const badge = document.getElementById('progress-status-badge');
  const assetsPill = document.getElementById('progress-assets-pill');
  const findingsPill = document.getElementById('progress-findings-pill');
  const cancelBtn = document.getElementById('cancel-scan-btn');
  const alertBox = document.getElementById('partial-failure-alert');
  const startBtn = document.getElementById('start-scan-btn');

  card.style.display = 'flex';

  async function refresh() {
    try {
      const prog = await window.SentinelAPI.getScanProgress(scanId);
      title.textContent = `Scan: ${prog.domain}`;
      subtitle.textContent = `${prog.id} · started ${new Date(prog.startedAt).toLocaleTimeString()}`;

      badge.textContent = prog.status.replace(/_/g, ' ');
      badge.className = `badge badge-${prog.status === 'completed' ? 'ok' : prog.status === 'running' ? 'running' : 'medium'}`;

      assetsPill.textContent = `${prog.summary?.totalAssets ?? 0} assets`;
      findingsPill.textContent = `${prog.summary?.findingsCount ?? 0} findings`;
      cancelBtn.style.display = prog.status === 'running' ? 'inline-flex' : 'none';

      const failures = prog.providerFailures || [];
      if (failures.length > 0) {
        alertBox.style.display = 'block';
        alertBox.textContent = `Some providers failed: ${failures.join(' | ')}. The scan continued with the remaining sources.`;
      } else {
        alertBox.style.display = 'none';
      }

      const canonical = buildCanonical8Stages(prog);
      grid.innerHTML = canonical
        .map((st) => {
          const cls =
            st.status === 'completed'
              ? 'step-completed'
              : st.status === 'in_progress'
              ? 'step-active'
              : st.status === 'partial'
              ? 'step-warning'
              : st.status === 'failed'
              ? 'step-failed'
              : '';
          return `
            <div class="pipeline-step ${cls}">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:500;">${window.escapeHtml(st.title)}</span>
                <span class="badge badge-${st.status === 'completed' ? 'ok' : st.status === 'in_progress' ? 'low' : st.status === 'partial' ? 'medium' : 'info'}">${window.escapeHtml(st.status)}</span>
              </div>
              <div class="mono" style="color:var(--text-muted);">${window.escapeHtml(st.provider)}</div>
              <div style="font-size:var(--text-xs); color:var(--text-secondary);">${window.escapeHtml(st.detail)}</div>
            </div>
          `;
        })
        .join('');

      if (prog.status !== 'running') {
        if (pollTimer) clearInterval(pollTimer);
        startBtn.disabled = false;
        startBtn.textContent = 'Start scan';
        await loadScanHistory();
      }
    } catch (_) {
      if (pollTimer) clearInterval(pollTimer);
    }
  }

  await refresh();
  if (poll) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(refresh, 1400);
  }
}

async function loadScanHistory() {
  try {
    const res = await window.SentinelAPI.getScans();
    const tbody = document.getElementById('scans-history-tbody');
    const selA = document.getElementById('compare-scan-a');
    const selB = document.getElementById('compare-scan-b');

    const scans = res.scans || [];
    const optionsHtml = scans
      .map(
        (s) =>
          `<option value="${window.escapeHtml(s.id)}">${window.escapeHtml(s.domain)} — ${new Date(s.startedAt).toLocaleString()}</option>`
      )
      .join('');
    selA.innerHTML = `<option value="">Base scan</option>${optionsHtml}`;
    selB.innerHTML = `<option value="">Compared scan</option>${optionsHtml}`;

    if (scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" class="empty-state-box">No scans yet.</td></tr>';
      return;
    }

    tbody.innerHTML = scans
      .map((s) => {
        const sum = s.summary || {};
        const warns = (s.providerFailures || []).length;
        return `
          <tr>
            <td class="mono">${window.escapeHtml(s.id)}</td>
            <td class="mono">${window.escapeHtml(s.domain)}</td>
            <td><span class="badge badge-${s.status === 'completed' ? 'ok' : s.status === 'running' ? 'low' : 'medium'}">${window.escapeHtml(s.status)}</span></td>
            <td class="num">${sum.totalAssets ?? 0}</td>
            <td class="num">${sum.uniquePublicIps ?? 0}</td>
            <td class="num">${sum.totalExposedPorts ?? 0}</td>
            <td class="num">${sum.findingsCount ?? 0}</td>
            <td>${warns > 0 ? `<span class="badge badge-medium">${warns} failed</span>` : '<span class="badge badge-ok">4/4 ok</span>'}</td>
            <td class="mono" style="color:var(--text-secondary);">${new Date(s.startedAt).toLocaleString()}</td>
            <td style="white-space:nowrap;">
              <button type="button" class="btn btn-secondary btn-sm" onclick="showScanStages('${window.escapeHtml(s.id)}', false)">Pipeline</button>
              <a href="/assets.html?scanId=${encodeURIComponent(s.id)}" class="btn btn-secondary btn-sm">Assets</a>
              <a href="/api/v1/reports/export?scanId=${encodeURIComponent(s.id)}&reportType=consolidated_json" class="btn btn-ghost btn-sm">JSON</a>
            </td>
          </tr>
        `;
      })
      .join('');
  } catch (err) {
    window.showToast(err.message, true);
  }
}

async function handleCompareScans() {
  const idA = document.getElementById('compare-scan-a').value;
  const idB = document.getElementById('compare-scan-b').value;
  if (!idA || !idB) {
    window.showToast('Select both a base scan and a compared scan', true);
    return;
  }

  try {
    const diff = await window.SentinelAPI.compareScans(idA, idB);
    const card = document.getElementById('comparison-result-card');
    const content = document.getElementById('comparison-content');
    document.getElementById('comparison-subtitle').textContent =
      `${diff.domain}: ${diff.baseScanId} → ${diff.targetScanId}`;
    card.style.display = 'flex';

    content.innerHTML = `
      <div class="stat-strip">
        <div class="stat"><span class="stat-label">New assets</span><span class="stat-value">+${diff.newAssets.length}</span></div>
        <div class="stat"><span class="stat-label">Removed assets</span><span class="stat-value">−${diff.removedAssets.length}</span></div>
        <div class="stat"><span class="stat-label">New open ports</span><span class="stat-value ${diff.newExposedPorts.length ? 'is-warn' : ''}">${diff.newExposedPorts.length}</span></div>
        <div class="stat"><span class="stat-label">New CVEs</span><span class="stat-value ${diff.newCveAssociations.length ? 'is-risk' : ''}">${diff.newCveAssociations.length}</span></div>
        <div class="stat"><span class="stat-label">DNS changes</span><span class="stat-value">${diff.dnsChanges.length}</span></div>
        <div class="stat"><span class="stat-label">Risk changes</span><span class="stat-value">${diff.riskChanges.length}</span></div>
      </div>

      <div class="analytics-grid-12" style="margin-bottom:0;">
        <div class="panel col-span-6">
          <div class="panel-header"><div class="panel-title">New assets</div></div>
          <div class="panel-body">
            ${
              diff.newAssets.length === 0
                ? '<span style="color:var(--text-muted);">No new assets.</span>'
                : diff.newAssets
                    .map(
                      (a) =>
                        `<div style="display:flex;justify-content:space-between;padding:0.3rem 0;border-bottom:1px solid var(--border-subtle);"><span class="mono">${window.escapeHtml(a.subdomain)} (${window.escapeHtml(a.ipAddress || 'Unresolved')})</span>${window.riskBadgeHtml(a.riskLevel)}</div>`
                    )
                    .join('')
            }
          </div>
        </div>

        <div class="panel col-span-6">
          <div class="panel-header"><div class="panel-title">Port and risk changes</div></div>
          <div class="panel-body">
            ${
              diff.newExposedPorts.length === 0 && diff.riskChanges.length === 0
                ? '<span style="color:var(--text-muted);">No port or risk changes.</span>'
                : [
                    ...diff.newExposedPorts.map(
                      (p) =>
                        `<div style="padding:0.3rem 0;border-bottom:1px solid var(--border-subtle);"><span class="mono">${window.escapeHtml(p.subdomain)}</span>: added ports <span class="mono" style="color:var(--sev-high-text);">${p.addedPorts.join(', ')}</span></div>`
                    ),
                    ...diff.riskChanges.map(
                      (r) =>
                        `<div style="padding:0.3rem 0;border-bottom:1px solid var(--border-subtle);"><span class="mono">${window.escapeHtml(r.subdomain)}</span>: risk ${window.riskBadgeHtml(r.previousRisk)} → ${window.riskBadgeHtml(r.currentRisk)}</div>`
                    ),
                  ].join('')
            }
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    window.showToast(err.message, true);
  }
}

window.showScanStages = showScanStages;
