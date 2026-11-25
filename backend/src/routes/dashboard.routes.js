const express = require('express');
const { query } = require('../database/db');
const { getProvidersHealthStatus } = require('../services/providers/http.client');
const { getAuthorizedDomainsList } = require('../database/scan.repository');
const config = require('../config');

const router = express.Router();

// GET /api/v1/dashboard/overview
router.get('/overview', async (req, res, next) => {
  try {
    const [
      scansCountRes,
      assetsRes,
      ipsRes,
      cveRes,
      findingsRes,
      recentScansRes,
      recentFindingsRes,
      recentAssetsRes,
      exposuresRes,
      authorizedDomains,
    ] = await Promise.all([
      query('SELECT COUNT(*)::int AS count FROM scans'),
      query('SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE resolves = TRUE)::int AS active, COUNT(DISTINCT subdomain)::int AS unique_subdomains FROM assets'),
      query('SELECT COUNT(DISTINCT ip_address)::int AS unique_ips, COALESCE(SUM(jsonb_array_length(open_ports_json)), 0)::int AS total_open_ports FROM ip_exposures WHERE status = $1', ['success']),
      query('SELECT COUNT(DISTINCT cve_id)::int AS unique_cves FROM cve_records'),
      query("SELECT COUNT(*)::int AS total_findings, COUNT(*) FILTER (WHERE finding_type = 'SUBDOMAIN_TAKEOVER_INDICATOR')::int AS takeover_count FROM findings"),
      query('SELECT id, domain, status, summary_json, provider_failures_json, started_at, completed_at FROM scans ORDER BY started_at DESC LIMIT 8'),
      query('SELECT id, scan_id, finding_type, title, severity, confidence, affected_asset, recommended_action, source, created_at FROM findings ORDER BY created_at DESC LIMIT 10'),
      query('SELECT id, scan_id, domain, subdomain, ip_address, ipv6_address, cname, hosting_provider, dns_status, resolves, exposed_ports_json, associated_cves_json, risk_level, last_observed FROM assets ORDER BY last_observed DESC, id DESC LIMIT 12'),
      query('SELECT open_ports_json FROM ip_exposures WHERE status = $1', ['success']),
      getAuthorizedDomainsList(),
    ]);

    const totalScans = scansCountRes.rows[0]?.count || 0;
    const totalAssets = assetsRes.rows[0]?.total || 0;
    const activeAssets = assetsRes.rows[0]?.active || 0;
    const discoveredSubdomains = assetsRes.rows[0]?.unique_subdomains || 0;
    const uniquePublicIps = ipsRes.rows[0]?.unique_ips || 0;
    const exposedPorts = ipsRes.rows[0]?.total_open_ports || 0;
    const cveAssociations = cveRes.rows[0]?.unique_cves || 0;
    const potentialTakeoverIndicators = findingsRes.rows[0]?.takeover_count || 0;

    const riskDistRes = await query(
      `SELECT risk_level, COUNT(*)::int AS count
       FROM assets
       GROUP BY risk_level`
    );
    const riskDistribution = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Informational: 0,
    };
    for (const r of riskDistRes.rows) {
      if (riskDistribution[r.risk_level] !== undefined) {
        riskDistribution[r.risk_level] = r.count;
      }
    }

    // Aggregate exposure by service/port from actual ip_exposures records
    const portLabels = {
      21: 'FTP (21)',
      22: 'SSH (22)',
      23: 'Telnet (23)',
      25: 'SMTP (25)',
      53: 'DNS (53)',
      80: 'HTTP (80)',
      443: 'HTTPS (443)',
      445: 'SMB (445)',
      2052: 'Cloudflare HTTP (2052)',
      2082: 'cPanel/Edge (2082)',
      2083: 'cPanel SSL (2083)',
      2086: 'WHM (2086)',
      2087: 'WHM SSL (2087)',
      3306: 'MySQL (3306)',
      3389: 'RDP (3389)',
      5432: 'PostgreSQL (5432)',
      6379: 'Redis (6379)',
      8080: 'HTTP-Alt (8080)',
      8443: 'HTTPS-Alt (8443)',
      9200: 'Elasticsearch (9200)',
    };
    const portCountsMap = new Map();
    for (const row of exposuresRes.rows) {
      const ports = row.open_ports_json || [];
      for (const p of ports) {
        portCountsMap.set(p, (portCountsMap.get(p) || 0) + 1);
      }
    }
    const exposureByPort = Array.from(portCountsMap.entries())
      .map(([port, count]) => ({
        port: Number(port),
        label: portLabels[port] || `TCP/${port}`,
        count,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    // Attack surface composition from actual assets table
    const compRes = await query(
      `SELECT
         COUNT(*) FILTER (WHERE resolves = TRUE AND ip_address IS NOT NULL)::int AS ipv4_active,
         COUNT(*) FILTER (WHERE ipv6_address IS NOT NULL)::int AS ipv6_enabled,
         COUNT(*) FILTER (WHERE cname IS NOT NULL)::int AS cname_aliased,
         COUNT(*) FILTER (WHERE resolves = FALSE)::int AS dormant_ct
       FROM assets`
    );
    const compRow = compRes.rows[0] || {};
    const attackSurfaceComposition = {
      ipv4Active: compRow.ipv4_active || 0,
      ipv6Enabled: compRow.ipv6_enabled || 0,
      cnameAliased: compRow.cname_aliased || 0,
      dormantCt: compRow.dormant_ct || 0,
    };

    res.status(200).json({
      hasData: totalScans > 0,
      serverId: config.serverId,
      timestamp: new Date().toISOString(),
      authorizedDomains,
      metrics: {
        totalScans,
        totalDiscoveredAssets: totalAssets,
        activeDnsResolvingAssets: activeAssets,
        uniquePublicIps,
        discoveredSubdomains,
        exposedPorts,
        potentialTakeoverIndicators,
        cveAssociations,
      },
      riskDistribution,
      exposureByPort,
      attackSurfaceComposition,
      recentAssets: recentAssetsRes.rows.map((a) => ({
        id: a.id,
        scanId: a.scan_id,
        domain: a.domain,
        subdomain: a.subdomain,
        ipAddress: a.ip_address,
        ipv6Address: a.ipv6_address,
        cname: a.cname,
        hostingProvider: a.hosting_provider,
        dnsStatus: a.dns_status,
        resolves: a.resolves,
        exposedPorts: a.exposed_ports_json || [],
        associatedCves: a.associated_cves_json || [],
        riskLevel: a.risk_level,
        lastObserved: a.last_observed,
      })),
      recentScans: recentScansRes.rows.map((s) => ({
        id: s.id,
        domain: s.domain,
        status: s.status,
        summary: s.summary_json || {},
        providerFailures: s.provider_failures_json || [],
        startedAt: s.started_at,
        completedAt: s.completed_at,
      })),
      recentFindings: recentFindingsRes.rows.map((f) => ({
        id: f.id,
        scanId: f.scan_id,
        findingType: f.finding_type,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        affectedAsset: f.affected_asset,
        recommendedAction: f.recommended_action,
        source: f.source,
        timestamp: f.created_at,
      })),
      providerHealth: getProvidersHealthStatus(),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/dashboard/risk-distribution
router.get('/risk-distribution', async (req, res, next) => {
  try {
    const [assetRiskRes, vulnSeverityRes] = await Promise.all([
      query('SELECT risk_level, COUNT(*)::int AS count FROM assets GROUP BY risk_level'),
      query('SELECT severity, COUNT(*)::int AS count FROM cve_records GROUP BY severity'),
    ]);

    const assetRisks = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    for (const r of assetRiskRes.rows) {
      if (assetRisks[r.risk_level] !== undefined) assetRisks[r.risk_level] = r.count;
    }

    const vulnerabilitySeverities = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    for (const v of vulnSeverityRes.rows) {
      const key = String(v.severity || 'UNKNOWN').toUpperCase();
      vulnerabilitySeverities[key] = (vulnerabilitySeverities[key] || 0) + v.count;
    }

    res.status(200).json({
      assetRisks,
      vulnerabilitySeverities,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/dashboard/activity
router.get('/activity', async (req, res, next) => {
  try {
    const logsRes = await query(
      'SELECT id, username, action, resource_type, resource_id, details_json, server_id, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 25'
    );
    res.status(200).json({
      activities: logsRes.rows.map((l) => ({
        id: l.id,
        username: l.username,
        action: l.action,
        resourceType: l.resource_type,
        resourceId: l.resource_id,
        details: l.details_json || {},
        serverId: l.server_id,
        timestamp: l.created_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
