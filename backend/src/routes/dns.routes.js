const express = require('express');
const { query } = require('../database/db');

const router = express.Router();

// GET /api/v1/dns
router.get('/', async (req, res, next) => {
  try {
    const { scanId, recordType, hostname, status } = req.query;
    const conditions = [];
    const params = [];

    if (scanId) {
      params.push(String(scanId));
      conditions.push(`scan_id = $${params.length}`);
    }
    if (recordType) {
      params.push(String(recordType).toUpperCase());
      conditions.push(`record_type = $${params.length}`);
    }
    if (hostname) {
      params.push(`%${String(hostname).toLowerCase()}%`);
      conditions.push(`LOWER(hostname) LIKE $${params.length}`);
    }
    if (status) {
      params.push(String(status).toUpperCase());
      conditions.push(`resolution_status = $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const rowsRes = await query(
      `SELECT * FROM dns_records ${whereClause}
       ORDER BY last_observed DESC, hostname ASC, record_type ASC
       LIMIT 500`,
      params
    );

    res.status(200).json({
      total: rowsRes.rows.length,
      records: rowsRes.rows.map((r) => ({
        id: r.id,
        scanId: r.scan_id,
        hostname: r.hostname,
        recordType: r.record_type,
        value: r.value,
        ttl: r.ttl,
        provider: r.provider,
        resolutionStatus: r.resolution_status,
        lastObserved: r.last_observed,
      })),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/dns/:id
router.get('/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'InvalidDnsId', message: 'DNS record ID must be an integer' });
    }
    const rowRes = await query('SELECT * FROM dns_records WHERE id = $1', [id]);
    if (rowRes.rows.length === 0) {
      return res.status(404).json({ error: 'DnsRecordNotFound', message: 'DNS record not found' });
    }
    const r = rowRes.rows[0];
    res.status(200).json({
      id: r.id,
      scanId: r.scan_id,
      hostname: r.hostname,
      recordType: r.record_type,
      value: r.value,
      ttl: r.ttl,
      provider: r.provider,
      resolutionStatus: r.resolution_status,
      lastObserved: r.last_observed,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
