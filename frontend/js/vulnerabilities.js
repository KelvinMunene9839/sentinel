let cachedCves = [];

document.addEventListener('DOMContentLoaded', async () => {
  await window.initShell('vulnerabilities');

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('search')) {
    document.getElementById('cve-search').value = urlParams.get('search');
  }

  document.getElementById('cve-filter-btn').addEventListener('click', loadVulnerabilities);
  document.getElementById('cve-clear-btn').addEventListener('click', () => {
    document.getElementById('cve-search').value = '';
    document.getElementById('cve-severity').value = '';
    document.getElementById('cve-sort').value = 'cvss_desc';
    loadVulnerabilities();
  });

  document.getElementById('cve-drawer-close').addEventListener('click', () => {
    document.getElementById('cve-drawer').classList.remove('open');
  });
  document.getElementById('cve-drawer').addEventListener('click', (e) => {
    if (e.target.id === 'cve-drawer') {
      document.getElementById('cve-drawer').classList.remove('open');
    }
  });

  await loadVulnerabilities();
});

async function loadVulnerabilities() {
  const search = document.getElementById('cve-search').value.trim();
  const severity = document.getElementById('cve-severity').value;
  const sort = document.getElementById('cve-sort').value;
  const params = { sort };
  if (search) params.search = search;
  if (severity) params.severity = severity;

  try {
    const res = await window.SentinelAPI.getVulnerabilities(params);
    cachedCves = res.vulnerabilities || [];

    // Update severity distribution counters
    const counts = { total: cachedCves.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const v of cachedCves) {
      const sev = String(v.severity || 'LOW').toUpperCase();
      if (counts[sev] !== undefined) counts[sev] += 1;
      else counts.LOW += 1;
    }
    document.getElementById('vuln-count-total').textContent = counts.total;
    document.getElementById('vuln-count-critical').textContent = counts.CRITICAL;
    document.getElementById('vuln-count-high').textContent = counts.HIGH;
    document.getElementById('vuln-count-medium').textContent = counts.MEDIUM;
    document.getElementById('vuln-count-low').textContent = counts.LOW;

    const tbody = document.getElementById('cves-tbody');
    if (cachedCves.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state-box">No CVE associations recorded. When InternetDB reports CPE or CVE data for a discovered IP, it is enriched from NIST NVD automatically.</div></td></tr>`;
      return;
    }

    tbody.innerHTML = cachedCves
      .map(
        (v, idx) => `
        <tr class="clickable-row" onclick="openCveDrawer(${idx})">
          <td class="mono">${window.escapeHtml(v.cveId)}</td>
          <td class="num">${v.cvssScore ?? 'N/A'}${v.cvssVersion ? ` <span style="color:var(--text-muted);font-size:var(--text-xs);">v${window.escapeHtml(v.cvssVersion)}</span>` : ''}</td>
          <td>${window.riskBadgeHtml(v.severity)}</td>
          <td class="mono">${window.escapeHtml((v.affectedAssets || []).join(', ') || '—')}</td>
          <td class="mono" style="max-width:210px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${window.escapeHtml((v.associatedCpes || [])[0] || '—')}</td>
          <td style="color:var(--text-secondary);">${window.escapeHtml(v.verificationStatus)}</td>
          <td class="mono" style="color:var(--text-secondary);">${window.escapeHtml((v.publishedDate || '').slice(0, 10) || '—')}</td>
          <td class="mono" style="color:var(--text-secondary);">${window.escapeHtml((v.lastModifiedDate || '').slice(0, 10) || '—')}</td>
          <td><button type="button" class="btn btn-ghost btn-sm">Details</button></td>
        </tr>
      `
      )
      .join('');
  } catch (err) {
    window.showToast(err.message, true);
  }
}

function openCveDrawer(index) {
  const v = cachedCves[index];
  if (!v) return;
  const drawer = document.getElementById('cve-drawer');
  document.getElementById('drawer-cve-id').textContent = v.cveId;

  const refsHtml =
    (v.references || [])
      .map(
        (r) =>
          `<li style="margin-bottom:0.3rem;"><a href="${window.escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer" class="mono">${window.escapeHtml(r.url)}</a></li>`
      )
      .join('') || '<li>No external references listed.</li>';

  document.getElementById('drawer-cve-body').innerHTML = `
    <div class="kv-grid">
      <div class="kv-item"><div class="kv-label">CVSS base score</div><div class="kv-value mono">${v.cvssScore ?? 'N/A'} (CVSS v${window.escapeHtml(v.cvssVersion || '3.1')})</div></div>
      <div class="kv-item"><div class="kv-label">Severity</div><div class="kv-value">${window.riskBadgeHtml(v.severity)}</div></div>
      <div class="kv-item"><div class="kv-label">Evidence</div><div class="kv-value">${window.escapeHtml(v.verificationStatus)}</div></div>
      <div class="kv-item"><div class="kv-label">Remediation</div><div class="kv-value">${window.escapeHtml(v.remediationStatus || 'Pending host version check')}</div></div>
      <div class="kv-item"><div class="kv-label">Published</div><div class="kv-value mono">${window.escapeHtml((v.publishedDate || '').slice(0, 10) || 'N/A')}</div></div>
      <div class="kv-item"><div class="kv-label">Modified</div><div class="kv-value mono">${window.escapeHtml((v.lastModifiedDate || '').slice(0, 10) || 'N/A')}</div></div>
    </div>

    <div class="section-title">Summary</div>
    <div style="font-size:var(--text-sm);">${window.escapeHtml(v.description)}</div>
    <div class="notice" style="margin-top:0.6rem;">
      <strong>Evidence scope:</strong> ${window.escapeHtml(v.verificationNote || 'Observed via passive CPE/IP correlation.')}
    </div>

    <div class="section-title">Affected infrastructure</div>
    <div class="kv-grid" style="grid-template-columns:1fr;">
      <div class="kv-item"><span class="kv-label">Subdomains</span><span class="kv-value mono">${window.escapeHtml((v.affectedAssets || []).join(', ') || 'None')}</span></div>
      <div class="kv-item"><span class="kv-label">Public IPs</span><span class="kv-value mono">${window.escapeHtml((v.associatedIps || []).join(', ') || 'None')}</span></div>
      <div class="kv-item"><span class="kv-label">CPEs</span><span class="kv-value mono">${window.escapeHtml((v.associatedCpes || []).join(', ') || 'None')}</span></div>
      <div class="kv-item"><span class="kv-label">CWE</span><span class="kv-value mono">${window.escapeHtml((v.weaknesses || []).join(', ') || 'Not specified')}</span></div>
    </div>

    <div class="section-title">Recommended remediation</div>
    <div style="font-size:var(--text-sm); color:var(--text-secondary);">Verify the exact installed build and any backported distribution patches on the affected hosts. Apply vendor advisories if the running version falls within the vulnerable CPE range.</div>

    <div class="section-title">References</div>
    <ul style="padding-left:1.1rem; font-size:var(--text-sm);">${refsHtml}</ul>
  `;

  drawer.classList.add('open');
}

window.openCveDrawer = openCveDrawer;
