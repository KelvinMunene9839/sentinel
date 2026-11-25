const express = require('express');
const { query } = require('../database/db');

const router = express.Router();

function mapCveRow(v) {
  return {
    id: v.id,
    scanId: v.scan_id,
    cveId: v.cve_id,
    cvssScore: v.cvss_score !== null ? Number(v.cvss_score) : null,
    cvssVersion: v.cvss_version,
    severity: v.severity,
    description: v.description,
    affectedAssets: v.affected_assets_json || [],
    associatedIps: v.associated_ips_json || [],
    associatedCpes: v.associated_cpes_json || [],
    weaknesses: v.weaknesses_json || [],
    references: v.references_json || [],
    publishedDate: v.published_date,
    lastModifiedDate: v.last_modified_date,
    verificationStatus: v.verification_status,
    verificationNote: v.verification_note,
    remediationStatus: 'Pending Operator Version Verification',
    source: v.source,
    retrievedAt: v.retrieved_at,
  };
}

// GET /api/v1/vulnerabilities
router.get('/', async (req, res, next) => {
  try {
    const { scanId, severity, search, sort = 'cvss_desc' } = req.query;
    const conditions = [];
    const params = [];

    if (scanId) {
      params.push(String(scanId));
      conditions.push(`scan_id = $${params.length}`);
    }
    if (severity) {
      params.push(String(severity).toUpperCase());
      conditions.push(`UPPER(severity) = $${params.length}`);
    }
    if (search) {
      params.push(`%${String(search).toLowerCase()}%`);
      conditions.push(
        `(LOWER(cve_id) LIKE $${params.length} OR LOWER(description) LIKE $${params.length})`
      );
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const orderBy =
      sort === 'cvss_asc'
        ? 'ORDER BY cvss_score ASC NULLS LAST, cve_id ASC'
        : 'ORDER BY cvss_score DESC NULLS LAST, cve_id ASC';

    const rowsRes = await query(
      `SELECT * FROM cve_records ${whereClause} ${orderBy} LIMIT 300`,
      params
    );

    res.status(200).json({
      total: rowsRes.rows.length,
      vulnerabilities: rowsRes.rows.map(mapCveRow),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/vulnerabilities/:id
router.get('/:id', async (req, res, next) => {
  try {
    const param = String(req.params.id).trim();
    let rowRes;
    if (/^CVE-/i.test(param)) {
      rowRes = await query(
        'SELECT * FROM cve_records WHERE UPPER(cve_id) = UPPER($1) ORDER BY retrieved_at DESC LIMIT 1',
        [param]
      );
    } else {
      const id = parseInt(param, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ error: 'InvalidVulnerabilityId', message: 'Invalid vulnerability ID' });
      }
      rowRes = await query('SELECT * FROM cve_records WHERE id = $1', [id]);
    }

    if (rowRes.rows.length === 0) {
      return res.status(404).json({ error: 'VulnerabilityNotFound', message: 'Vulnerability record not found' });
    }

    res.status(200).json(mapCveRow(rowRes.rows[0]));
  } catch (err) {
    next(err);
  }
});

module.exports = router;
