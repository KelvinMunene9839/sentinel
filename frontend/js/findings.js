document.addEventListener('DOMContentLoaded', async () => {
  await window.initShell('findings');

  const params = new URLSearchParams(window.location.search);
  const tab = params.get('tab') || 'all';
  switchSectionView(tab);

  document.querySelectorAll('[data-view-switch]').forEach((btn) => {
    btn.addEventListener('click', () => {
      switchSectionView(btn.getAttribute('data-view-switch'));
    });
  });

  document.getElementById('finding-filter-btn').addEventListener('click', loadFindingsData);
  document.getElementById('finding-search').addEventListener('input', loadFindingsData);

  await Promise.all([loadExposuresData(), loadFindingsData()]);
});

function switchSectionView(mode) {
  const sections = {
    takeover: document.getElementById('section-takeover'),
    exposures: document.getElementById('section-exposures'),
    findings: document.getElementById('section-findings'),
  };
  const titles = {
    takeover: 'Subdomain takeover risk',
    exposures: 'Public IP exposure',
    findings: 'Security findings',
  };
  const active = sections[mode] ? mode : 'all';
  Object.entries(sections).forEach(([key, el]) => {
    el.style.display = active === 'all' || active === key ? 'flex' : 'none';
  });
  document.getElementById('findings-page-title').textContent = titles[active] || 'Findings and exposure';
  document.querySelectorAll('[data-view-switch]').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-view-switch') === active);
  });
}

function confidenceBadgeHtml(confidence) {
  const c = String(confidence || 'Informational');
  const lower = c.toLowerCase();
  if (lower.includes('confirmed')) return `<span class="badge badge-critical">${window.escapeHtml(c)}</span>`;
  if (lower.includes('verified')) return `<span class="badge badge-high">${window.escapeHtml(c)}</span>`;
  if (lower.includes('potentially')) return `<span class="badge badge-medium">${window.escapeHtml(c)}</span>`;
  if (lower.includes('suspicious')) return `<span class="badge badge-low">${window.escapeHtml(c)}</span>`;
  return `<span class="badge badge-info">${window.escapeHtml(c)}</span>`;
}

async function loadExposuresData() {
  try {
    const res = await window.SentinelAPI.getExposures();
    const exposures = res.exposures || [];
    const tbody = document.getElementById('exposures-tbody');

    if (exposures.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state-box">No public IP exposures recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = exposures
      .map((e) => {
        const sensHtml =
          (e.sensitivePorts || [])
            .map(
              (s) =>
                `<span class="badge badge-${s.severity.toLowerCase()}" style="margin-right:3px;">${s.port} (${window.escapeHtml(s.service)})</span>`
            )
            .join('') || '<span style="color:var(--text-muted);">—</span>';

        return `
          <tr>
            <td class="mono">${window.escapeHtml(e.ipAddress)}</td>
            <td class="mono">${window.escapeHtml((e.associatedHostnames || []).join(', ') || '—')}</td>
            <td class="mono">${(e.openPorts || []).join(', ') || 'None'}</td>
            <td>${sensHtml}</td>
            <td class="mono" style="font-size:0.72rem;">${window.escapeHtml((e.cpes || []).join(', ') || '—')}</td>
            <td>${(e.tags || []).map((t) => `<span class="badge badge-neutral" style="margin-right:2px;">${window.escapeHtml(t)}</span>`).join('') || '—'}</td>
            <td class="mono">${window.escapeHtml((e.cves || []).join(', ') || 'None')}</td>
            <td class="mono" style="color:var(--text-secondary);">${new Date(e.lastEnrichedAt).toLocaleString()}</td>
          </tr>
        `;
      })
      .join('');
  } catch (err) {
    window.showToast(err.message, true);
  }
}

async function loadFindingsData() {
  const severity = document.getElementById('finding-severity').value;
  const findingType = document.getElementById('finding-type').value;
  const search = document.getElementById('finding-search').value.trim();

  const params = {};
  if (severity) params.severity = severity;
  if (findingType) params.findingType = findingType;
  if (search) params.search = search;

  try {
    const res = await window.SentinelAPI.getFindings(params);
    const findings = res.findings || [];
    const takeovers = res.takeoverIndicators || [];

    const takeoverTbody = document.getElementById('takeover-tbody');
    if (takeovers.length === 0) {
      takeoverTbody.innerHTML = '<tr><td colspan="7" class="empty-state-box">No takeover indicators evaluated yet.</td></tr>';
    } else {
      takeoverTbody.innerHTML = takeovers
        .map(
          (t) => `
          <tr>
            <td class="mono">${window.escapeHtml(t.affectedHostname)}</td>
            <td class="mono">${window.escapeHtml(t.cnameDestination || 'Direct NXDOMAIN (No CNAME)')}</td>
            <td>${window.escapeHtml(t.detectedProviderPattern || 'Standard DNS')}</td>
            <td>${confidenceBadgeHtml(t.confidence)}</td>
            <td><span class="badge badge-${t.hasIndicator ? 'high' : 'ok'}">${t.hasIndicator ? 'Indicator detected' : 'Resolving normally'}</span></td>
            <td style="max-width:300px;">${window.escapeHtml(t.evidence)}</td>
            <td style="max-width:260px;">${window.escapeHtml(t.recommendedRemediation)}</td>
          </tr>
        `
        )
        .join('');
    }

    const tbody = document.getElementById('findings-tbody');
    if (findings.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state-box">No findings match the current filters.</td></tr>';
      return;
    }

    tbody.innerHTML = findings
      .map(
        (f) => `
        <tr>
          <td>${window.riskBadgeHtml(f.severity)}</td>
          <td class="mono" style="color:var(--text-secondary);">${window.escapeHtml(f.findingType)}</td>
          <td>${window.escapeHtml(f.title)}</td>
          <td class="mono">${window.escapeHtml(f.affectedAsset)}</td>
          <td>${confidenceBadgeHtml(f.confidence)}</td>
          <td style="max-width:340px;">
            <div>${window.escapeHtml(f.reason)}</div>
            <div style="color:var(--text-muted);margin-top:0.15rem;">${window.escapeHtml(f.supportingEvidence)}</div>
          </td>
          <td style="max-width:260px;">${window.escapeHtml(f.recommendedAction)}</td>
          <td style="font-size:0.72rem;color:var(--text-secondary);">${window.escapeHtml(f.source)}</td>
        </tr>
      `
      )
      .join('');
  } catch (err) {
    window.showToast(err.message, true);
  }
}
