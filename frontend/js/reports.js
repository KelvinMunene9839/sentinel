let allReports = [];

document.addEventListener('DOMContentLoaded', async () => {
  await window.initShell('reports');
  document.getElementById('report-search').addEventListener('input', renderReportsTable);
  document.getElementById('report-status-filter').addEventListener('change', renderReportsTable);
  await loadReports();
});

async function loadReports() {
  try {
    const res = await window.SentinelAPI.getReports();
    allReports = res.availableScanReports || [];
    renderReportsTable();
  } catch (err) {
    window.showToast(err.message, true);
  }
}

function renderReportsTable() {
  const search = document.getElementById('report-search').value.trim().toLowerCase();
  const statusFilter = document.getElementById('report-status-filter').value;
  const tbody = document.getElementById('reports-tbody');

  const filtered = allReports.filter((r) => {
    if (statusFilter && r.status !== statusFilter) return false;
    if (search) {
      const hay = `${r.scanId} ${r.domain}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state-box">No completed scans match. Run a scan first.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered
    .map((r) => {
      const warns = (r.providerFailures || []).length;
      return `
        <tr>
          <td class="mono">${window.escapeHtml(r.scanId)}</td>
          <td class="mono">${window.escapeHtml(r.domain)}</td>
          <td><span class="badge badge-${r.status === 'completed' ? 'ok' : 'medium'}">${window.escapeHtml(r.status)}</span></td>
          <td class="mono" style="color:var(--text-secondary);">${new Date(r.completedAt || r.startedAt).toLocaleString()}</td>
          <td class="num">${r.summary?.totalAssets ?? 0}</td>
          <td class="num">${r.summary?.findingsCount ?? 0}</td>
          <td>${warns > 0 ? `<span class="badge badge-medium">${warns} failed</span>` : '<span class="badge badge-ok">None</span>'}</td>
          <td style="white-space:nowrap;">
            <a href="/api/v1/reports/export?scanId=${encodeURIComponent(r.scanId)}&reportType=assets_csv" class="btn btn-secondary btn-sm">Assets CSV</a>
            <a href="/api/v1/reports/export?scanId=${encodeURIComponent(r.scanId)}&reportType=dns_csv" class="btn btn-secondary btn-sm">DNS CSV</a>
            <a href="/api/v1/reports/export?scanId=${encodeURIComponent(r.scanId)}&reportType=vulnerabilities_csv" class="btn btn-secondary btn-sm">CVE CSV</a>
            <a href="/api/v1/reports/export?scanId=${encodeURIComponent(r.scanId)}&reportType=consolidated_json" class="btn btn-secondary btn-sm">Consolidated JSON</a>
          </td>
        </tr>
      `;
    })
    .join('');
}
