/**
 * SENTINEL — Pure Vanilla SVG Analytical Chart Renderer
 * Renders real backend telemetry without inventing or fabricating numbers.
 */

const SentinelCharts = {
  /**
   * 1. Asset Discovery Trend Chart (Area / Bar SVG across real completed scans)
   */
  renderAssetTrendSvg(scans = []) {
    if (!scans || scans.length === 0) {
      return `<div class="empty-state-box">No scans to chart yet. Run a discovery scan to see asset counts over time.</div>`;
    }

    const ordered = [...scans].reverse().slice(-10);
    const width = 560;
    const height = 175;
    const padLeft = 36;
    const padRight = 20;
    const padTop = 18;
    const padBottom = 32;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    const values = ordered.map((s) => Number(s.summary?.totalAssets || 0));
    const maxVal = Math.max(...values, 4);

    const stepX = ordered.length > 1 ? plotW / (ordered.length - 1) : plotW / 2;
    const points = ordered.map((s, idx) => {
      const val = Number(s.summary?.totalAssets || 0);
      const x = ordered.length > 1 ? padLeft + idx * stepX : padLeft + plotW / 2;
      const y = padTop + plotH - (val / maxVal) * plotH;
      return { x, y, val, label: s.domain, date: new Date(s.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) };
    });

    const polylinePoints = points.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');

    const gridLines = [0, 0.5, 1]
      .map((ratio) => {
        const y = padTop + plotH * (1 - ratio);
        const val = Math.round(maxVal * ratio);
        return `
          <line x1="${padLeft}" y1="${y}" x2="${width - padRight}" y2="${y}" stroke="#2a2e35"/>
          <text x="${padLeft - 8}" y="${y + 4}" text-anchor="end" fill="#757c88" font-size="10" font-family="ui-monospace, Consolas, monospace">${val}</text>
        `;
      })
      .join('');

    const dotsAndLabels = points
      .map(
        (p) => `
        <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3" fill="#3d7fd1" stroke="#1a1d22" stroke-width="1.5">
          <title>${window.escapeHtml(p.label)}: ${p.val} assets (${p.date})</title>
        </circle>
        <text x="${p.x.toFixed(1)}" y="${p.y - 8}" text-anchor="middle" fill="#e6e8eb" font-size="10" font-family="ui-monospace, Consolas, monospace">${p.val}</text>
        <text x="${p.x.toFixed(1)}" y="${height - 10}" text-anchor="middle" fill="#a3a9b3" font-size="10">${window.escapeHtml(p.label.slice(0, 12))}</text>
      `
      )
      .join('');

    return `
      <svg viewBox="0 0 ${width} ${height}" style="width:100%; height:170px; display:block;">
        ${gridLines}
        ${points.length > 1 ? `<polyline fill="none" stroke="#3d7fd1" stroke-width="1.5" points="${polylinePoints}"/>` : ''}
        ${dotsAndLabels}
      </svg>
    `;
  },

  /**
   * 2. Vulnerability & Asset Risk Severity Distribution
   */
  renderRiskDistributionHtml(dist = {}) {
    const levels = [
      { key: 'Critical', color: '#e5484d' },
      { key: 'High', color: '#e5832f' },
      { key: 'Medium', color: '#d1a630' },
      { key: 'Low', color: '#6b95c9' },
      { key: 'Informational', color: '#7b828e' },
    ];
    const total = levels.reduce((acc, l) => acc + Number(dist[l.key] || 0), 0);

    const stackedSegments = levels
      .map((l) => {
        const count = Number(dist[l.key] || 0);
        const pct = total > 0 ? (count / total) * 100 : 0;
        if (pct === 0) return '';
        return `<div style="width:${pct}%; background:${l.color}; height:100%;" title="${l.key}: ${count}"></div>`;
      })
      .join('');

    const rows = levels
      .map((l) => {
        const count = Number(dist[l.key] || 0);
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        return `
          <div class="dist-row">
            <span class="dist-name"><span class="dist-swatch" style="background:${l.color};"></span>${l.key}</span>
            <span class="dist-count"><strong>${count}</strong>${pct}%</span>
          </div>`;
      })
      .join('');

    return `
      <div style="height:6px; background:var(--bg-surface-3); border-radius:1px; overflow:hidden; display:flex; gap:1px; margin-bottom:0.5rem;">
        ${stackedSegments}
      </div>
      <div>${rows}</div>
      <div style="font-size:var(--text-xs); color:var(--text-muted); margin-top:0.4rem;">${total} classified</div>
    `;
  },

  /**
   * 3. Exposure by Service / Port Horizontal Bar Chart
   */
  renderExposureByPortHtml(exposureByPort = []) {
    if (!exposureByPort || exposureByPort.length === 0) {
      return `<div class="empty-state-box" style="padding:0.5rem 0;">No open ports observed yet.</div>`;
    }

    const maxCount = Math.max(...exposureByPort.map((e) => e.count), 1);
    const sensitiveSet = new Set([21, 22, 23, 25, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5601, 5900, 6379, 9200, 11211, 27017]);

    return exposureByPort
      .map((item) => {
        const pct = Math.round((item.count / maxCount) * 100);
        const isSens = sensitiveSet.has(Number(item.port));
        const barColor = isSens ? '#e5832f' : '#757c88';
        return `
          <div class="dist-row" style="grid-template-columns: minmax(0, 9rem) 1fr auto;">
            <span class="mono" style="${isSens ? 'color:var(--sev-high-text);' : ''}" ${isSens ? 'title="Sensitive service"' : ''}>${window.escapeHtml(item.label)}${isSens ? ' ▲' : ''}</span>
            <span class="meter"><span style="width:${pct}%; background:${barColor};"></span></span>
            <span class="dist-count"><strong>${item.count}</strong></span>
          </div>`;
      })
      .join('');
  },

  /**
   * 4. Attack Surface Composition Breakdown
   */
  renderCompositionHtml(comp = {}, totalAssets = 0) {
    const items = [
      { label: 'Resolving over IPv4', count: comp.ipv4Active || 0 },
      { label: 'IPv6 (AAAA) enabled', count: comp.ipv6Enabled || 0 },
      { label: 'CNAME aliases', count: comp.cnameAliased || 0 },
      { label: 'Dormant CT entries', count: comp.dormantCt || 0 },
    ];
    const base = Math.max(totalAssets, 1);

    return items
      .map((it) => {
        const pct = totalAssets > 0 ? Math.min(Math.round((it.count / base) * 100), 100) : 0;
        return `
          <div class="dist-row">
            <span class="dist-name">${it.label}</span>
            <span class="dist-count"><strong>${it.count}</strong>${pct}%</span>
          </div>`;
      })
      .join('');
  },
};

window.SentinelCharts = SentinelCharts;
