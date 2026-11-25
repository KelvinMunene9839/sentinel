document.addEventListener('DOMContentLoaded', async () => {
  hydrateStaticIcons();
  await window.initShell('dashboard');

  const refreshBtn = document.getElementById('dash-refresh-btn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await loadDashboardTelemetry(true);
    });
  }

  await loadDashboardTelemetry(false);
});

function hydrateStaticIcons() {
  if (!window.SentinelIcons) return;
  document.querySelectorAll('[data-icon]').forEach((el) => {
    el.innerHTML = window.SentinelIcons.getIcon(el.getAttribute('data-icon'));
  });
  const refHolder = document.getElementById('icon-refresh-holder');
  if (refHolder) refHolder.innerHTML = window.SentinelIcons.getIcon('refresh');
  const plusHolder = document.getElementById('icon-plus-holder');
  if (plusHolder) plusHolder.innerHTML = window.SentinelIcons.getIcon('plus');
}

async function loadDashboardTelemetry(notify = false) {
  try {
    const data = await window.SentinelAPI.getDashboardOverview();
    const m = data.metrics || {};

    document.getElementById('dash-last-updated').textContent = `Updated ${new Date(data.timestamp).toLocaleTimeString()}`;

    document.getElementById('kpi-total-assets').textContent = m.totalDiscoveredAssets ?? 0;
    document.getElementById('kpi-active-ratio').textContent = `${m.activeDnsResolvingAssets ?? 0} resolving`;
    document.getElementById('kpi-subdomains').textContent = m.discoveredSubdomains ?? 0;
    document.getElementById('kpi-public-ips').textContent = m.uniquePublicIps ?? 0;
    document.getElementById('kpi-exposed-services').textContent = m.exposedPorts ?? 0;
    document.getElementById('kpi-vulns').textContent = m.cveAssociations ?? 0;
    document.getElementById('kpi-takeovers').textContent = m.potentialTakeoverIndicators ?? 0;
    // Colour a figure only when it is itself a risk signal
    document.getElementById('kpi-takeovers').classList.toggle('is-risk', (m.potentialTakeoverIndicators ?? 0) > 0);
    document.getElementById('kpi-vulns').classList.toggle('is-warn', (m.cveAssociations ?? 0) > 0);

    const emptyBanner = document.getElementById('dash-empty-state');
    emptyBanner.style.display = data.hasData ? 'none' : 'flex';

    document.getElementById('trend-scans-count').textContent = `${m.totalScans ?? 0} scan${(m.totalScans ?? 0) === 1 ? '' : 's'}`;

    // 1. Asset Discovery Trend Chart
    document.getElementById('chart-asset-trend').innerHTML =
      window.SentinelCharts.renderAssetTrendSvg(data.recentScans || []);

    // 2. Risk & Vulnerability Distribution
    document.getElementById('chart-risk-distribution').innerHTML =
      window.SentinelCharts.renderRiskDistributionHtml(data.riskDistribution || {});

    // 3. Exposure by Service / Port
    document.getElementById('chart-exposure-ports').innerHTML =
      window.SentinelCharts.renderExposureByPortHtml(data.exposureByPort || []);

    // 4. Attack Surface Composition
    document.getElementById('chart-surface-composition').innerHTML =
      window.SentinelCharts.renderCompositionHtml(
        data.attackSurfaceComposition || {},
        m.totalDiscoveredAssets || 0
      );

    // 5. External Intelligence Provider Availability
    const provTbody = document.getElementById('dash-providers-tbody');
    provTbody.innerHTML = (data.providerHealth || [])
      .map(
        (p) => `
        <tr>
          <td>${window.escapeHtml(p.name)}</td>
          <td><span class="badge badge-${p.status === 'operational' ? 'ok' : 'medium'}">${window.escapeHtml(p.status)}</span></td>
          <td class="num">${p.totalRequests}</td>
          <td class="num">${p.cacheHits}</td>
        </tr>
      `
      )
      .join('');

    // 6. Highest-Priority Findings Timeline
    const findingsTbody = document.getElementById('dash-findings-tbody');
    const findings = data.recentFindings || [];
    if (findings.length === 0) {
      findingsTbody.innerHTML = '<tr><td colspan="4" class="empty-state-box">No findings recorded yet.</td></tr>';
    } else {
      findingsTbody.innerHTML = findings
        .map(
          (f) => `
          <tr>
            <td>${window.riskBadgeHtml(f.severity)}</td>
            <td>
              <div>${window.escapeHtml(f.title)}</div>
              <div style="font-size:var(--text-xs);color:var(--text-muted);">${window.escapeHtml(f.source)} · ${window.escapeHtml(f.confidence)} confidence · ${new Date(f.timestamp).toLocaleTimeString()}</div>
            </td>
            <td class="mono">${window.escapeHtml(f.affectedAsset)}</td>
            <td style="color:var(--text-secondary);">${window.escapeHtml(f.recommendedAction || f.title)}</td>
          </tr>
        `
        )
        .join('');
    }

    // 8. Recently Discovered External Assets
    const assetsTbody = document.getElementById('dash-recent-assets-tbody');
    const recentAssets = data.recentAssets || [];
    if (recentAssets.length === 0) {
      assetsTbody.innerHTML = '<tr><td colspan="6" class="empty-state-box">No assets discovered yet.</td></tr>';
    } else {
      assetsTbody.innerHTML = recentAssets
        .slice(0, 8)
        .map(
          (a) => `
          <tr class="clickable-row" onclick="window.location.href='/assets.html?search=${encodeURIComponent(a.subdomain)}'">
            <td class="mono">${window.escapeHtml(a.subdomain)}</td>
            <td class="mono">${window.escapeHtml(a.ipAddress || a.ipv6Address || '—')}</td>
            <td>${window.escapeHtml(a.hostingProvider || '—')}</td>
            <td><span class="badge badge-${a.resolves ? 'ok' : 'info'}">${window.escapeHtml(a.dnsStatus)}</span></td>
            <td class="mono">${(a.exposedPorts || []).join(', ') || '—'}</td>
            <td>${window.riskBadgeHtml(a.riskLevel)}</td>
          </tr>
        `
        )
        .join('');
    }

    // 9. Recent Scans
    const scansTbody = document.getElementById('dash-recent-scans-tbody');
    const recentScans = data.recentScans || [];
    if (recentScans.length === 0) {
      scansTbody.innerHTML = '<tr><td colspan="4" class="empty-state-box">No scans yet.</td></tr>';
    } else {
      scansTbody.innerHTML = recentScans
        .map(
          (s) => `
          <tr class="clickable-row" onclick="window.location.href='/scans.html?scanId=${encodeURIComponent(s.id)}'">
            <td class="mono">${window.escapeHtml(s.domain)}</td>
            <td><span class="badge badge-${s.status === 'completed' ? 'ok' : 'medium'}">${window.escapeHtml(s.status)}</span></td>
            <td class="num">${s.summary?.totalAssets ?? 0}</td>
            <td class="num">${s.summary?.findingsCount ?? 0}</td>
          </tr>
        `
        )
        .join('');
    }

    if (notify) {
      window.showToast('Refreshed');
    }
  } catch (err) {
    window.showToast(`Could not load overview: ${err.message}`, true);
  }
}
