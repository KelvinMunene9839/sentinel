const express = require('express');
const { query } = require('../database/db');
const { mapAssetRow } = require('../database/scan.repository');

const router = express.Router();

// GET /api/v1/assets
router.get('/', async (req, res, next) => {
  try {
    const {
      scanId,
      domain,
      riskLevel,
      dnsStatus,
      search,
      page = 1,
      limit = 50,
    } = req.query;

    const conditions = [];
    const params = [];

    if (scanId) {
      params.push(String(scanId));
      conditions.push(`scan_id = $${params.length}`);
    }
    if (domain) {
      params.push(String(domain).toLowerCase());
      conditions.push(`LOWER(domain) = $${params.length}`);
    }
    if (riskLevel) {
      params.push(String(riskLevel));
      conditions.push(`risk_level = $${params.length}`);
    }
    if (dnsStatus) {
      params.push(String(dnsStatus));
      conditions.push(`dns_status = $${params.length}`);
    }
    if (search) {
      params.push(`%${String(search).toLowerCase()}%`);
      conditions.push(
        `(LOWER(subdomain) LIKE $${params.length} OR LOWER(COALESCE(ip_address, '')) LIKE $${params.length} OR LOWER(COALESCE(cname, '')) LIKE $${params.length} OR LOWER(COALESCE(hosting_provider, '')) LIKE $${params.length})`
      );
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const pageNum = Math.max(parseInt(page, 10) || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 250);
    const offset = (pageNum - 1) * limitNum;

    const countRes = await query(`SELECT COUNT(*)::int AS total FROM assets ${whereClause}`, params);
    const total = countRes.rows[0]?.total || 0;

    const dataParams = [...params, limitNum, offset];
    const rowsRes = await query(
      `SELECT * FROM assets ${whereClause}
       ORDER BY last_observed DESC, subdomain ASC
       LIMIT $${dataParams.length - 1} OFFSET $${dataParams.length}`,
      dataParams
    );

    res.status(200).json({
      total,
      page: pageNum,
      limit: limitNum,
      assets: rowsRes.rows.map(mapAssetRow),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/assets/:id
router.get('/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'InvalidAssetId', message: 'Asset ID must be an integer' });
    }
    const rowRes = await query('SELECT * FROM assets WHERE id = $1', [id]);
    if (rowRes.rows.length === 0) {
      return res.status(404).json({ error: 'AssetNotFound', message: 'Asset not found' });
    }
    const asset = mapAssetRow(rowRes.rows[0]);
    const [dnsRes, findingsRes, certsRes, expRes, cvesRes, historyRes] = await Promise.all([
      query('SELECT * FROM dns_records WHERE scan_id = $1 AND hostname = $2 ORDER BY record_type ASC', [asset.scanId, asset.subdomain]),
      query('SELECT * FROM findings WHERE scan_id = $1 AND affected_asset = $2 ORDER BY id ASC', [asset.scanId, asset.subdomain]),
      query('SELECT * FROM certificates WHERE scan_id = $1 ORDER BY id ASC LIMIT 50', [asset.scanId]),
      query('SELECT * FROM ip_exposures WHERE scan_id = $1 ORDER BY ip_address ASC', [asset.scanId]),
      query('SELECT * FROM cve_records WHERE scan_id = $1 ORDER BY cvss_score DESC NULLS LAST', [asset.scanId]),
      query(
        'SELECT id, scan_id, ip_address, cname, dns_status, risk_level, exposed_ports_json, associated_cves_json, last_observed FROM assets WHERE subdomain = $1 ORDER BY last_observed DESC LIMIT 15',
        [asset.subdomain]
      ),
    ]);

    const assetIps = new Set([...(asset.ipv4Addresses || []), ...(asset.ipv6Addresses || []), asset.ipAddress].filter(Boolean));
    const assetCveIds = new Set(asset.associatedCves || []);

    const matchedCerts = certsRes.rows
      .filter((c) => {
        const sans = c.subject_alt_names_json || [];
        return c.common_name === asset.subdomain || sans.includes(asset.subdomain);
      })
      .map((c) => ({
        certificateId: c.certificate_id,
        commonName: c.common_name,
        subjectAlternativeNames: c.subject_alt_names_json || [],
        issuerName: c.issuer_name,
        serialNumber: c.serial_number,
        notBefore: c.not_before,
        notAfter: c.not_after,
      }));

    const matchedExposures = expRes.rows
      .filter((e) => assetIps.has(e.ip_address) || (e.associated_hostnames_json || []).includes(asset.subdomain))
      .map((e) => ({
        ipAddress: e.ip_address,
        status: e.status,
        openPorts: e.open_ports_json || [],
        hostnames: e.hostnames_json || [],
        cpes: e.cpes_json || [],
        cves: e.cves_json || [],
        tags: e.tags_json || [],
        lastEnrichedAt: e.last_enriched_at,
      }));

    const matchedVulnerabilities = cvesRes.rows
      .filter((v) => assetCveIds.has(v.cve_id) || (v.affected_assets_json || []).includes(asset.subdomain))
      .map((v) => ({
        cveId: v.cve_id,
        cvssScore: v.cvss_score !== null ? Number(v.cvss_score) : null,
        cvssVersion: v.cvss_version,
        severity: v.severity,
        description: v.description,
        verificationStatus: v.verification_status,
        publishedDate: v.published_date,
      }));

    res.status(200).json({
      ...asset,
      dnsRecords: dnsRes.rows.map((r) => ({
        recordType: r.record_type,
        hostname: r.hostname,
        value: r.value,
        ttl: r.ttl,
        resolutionStatus: r.resolution_status,
        provider: r.provider,
        lastObserved: r.last_observed,
      })),
      certificates: matchedCerts,
      exposures: matchedExposures,
      vulnerabilities: matchedVulnerabilities,
      findings: findingsRes.rows.map((f) => ({
        id: f.id,
        findingType: f.finding_type,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        reason: f.reason,
        supportingEvidence: f.supporting_evidence,
        recommendedAction: f.recommended_action,
      })),
      history: historyRes.rows.map((h) => ({
        assetId: h.id,
        scanId: h.scan_id,
        ipAddress: h.ip_address,
        cname: h.cname,
        dnsStatus: h.dns_status,
        riskLevel: h.risk_level,
        exposedPorts: h.exposed_ports_json || [],
        associatedCves: h.associated_cves_json || [],
        lastObserved: h.last_observed,
      })),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
