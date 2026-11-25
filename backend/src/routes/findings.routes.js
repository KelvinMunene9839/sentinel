const express = require('express');
const { query } = require('../database/db');

const router = express.Router();

// GET /api/v1/findings
router.get('/', async (req, res, next) => {
  try {
    const { scanId, severity, findingType, search } = req.query;
    const conditions = [];
    const params = [];

    if (scanId) {
      params.push(String(scanId));
      conditions.push(`scan_id = $${params.length}`);
    }
    if (severity) {
      params.push(String(severity));
      conditions.push(`severity = $${params.length}`);
    }
    if (findingType) {
      params.push(String(findingType));
      conditions.push(`finding_type = $${params.length}`);
    }
    if (search) {
      params.push(`%${String(search).toLowerCase()}%`);
      conditions.push(
        `(LOWER(title) LIKE $${params.length} OR LOWER(affected_asset) LIKE $${params.length} OR LOWER(reason) LIKE $${params.length})`
      );
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const rowsRes = await query(
      `SELECT * FROM findings ${whereClause}
       ORDER BY created_at DESC, id DESC
       LIMIT 300`,
      params
    );

    const takeoverRes = await query(
      `SELECT id AS scan_id, domain, takeover_indicators_json, completed_at
       FROM scans
       WHERE jsonb_array_length(takeover_indicators_json) > 0
       ORDER BY started_at DESC
       LIMIT 25`
    );

    const takeoverIndicators = [];
    for (const s of takeoverRes.rows) {
      if (scanId && s.scan_id !== scanId) continue;
      for (const item of s.takeover_indicators_json || []) {
        takeoverIndicators.push({
          scanId: s.scan_id,
          domain: s.domain,
          ...item,
        });
      }
    }

    res.status(200).json({
      total: rowsRes.rows.length,
      findings: rowsRes.rows.map((f) => ({
        id: f.id,
        scanId: f.scan_id,
        findingType: f.finding_type,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        affectedAsset: f.affected_asset,
        ipAddress: f.ip_address,
        port: f.port,
        cnameTarget: f.cname_target,
        providerPattern: f.provider_pattern,
        cveId: f.cve_id,
        cvssScore: f.cvss_score !== null ? Number(f.cvss_score) : null,
        reason: f.reason,
        supportingEvidence: f.supporting_evidence,
        source: f.source,
        recommendedAction: f.recommended_action,
        timestamp: f.created_at,
      })),
      takeoverIndicators,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/findings/:id
router.get('/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'InvalidFindingId', message: 'Finding ID must be an integer' });
    }
    const rowRes = await query('SELECT * FROM findings WHERE id = $1', [id]);
    if (rowRes.rows.length === 0) {
      return res.status(404).json({ error: 'FindingNotFound', message: 'Finding not found' });
    }
    const f = rowRes.rows[0];
    res.status(200).json({
      id: f.id,
      scanId: f.scan_id,
      findingType: f.finding_type,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      affectedAsset: f.affected_asset,
      ipAddress: f.ip_address,
      port: f.port,
      cnameTarget: f.cname_target,
      providerPattern: f.provider_pattern,
      cveId: f.cve_id,
      cvssScore: f.cvss_score !== null ? Number(f.cvss_score) : null,
      reason: f.reason,
      supportingEvidence: f.supporting_evidence,
      source: f.source,
      recommendedAction: f.recommended_action,
      timestamp: f.created_at,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
