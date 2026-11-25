const express = require('express');
const { query } = require('../database/db');
const { classifyExposedPorts } = require('../services/risk/risk.engine');
const config = require('../config');

const router = express.Router();

// GET /api/v1/exposures
router.get('/', async (req, res, next) => {
  try {
    const { scanId, ip } = req.query;
    const conditions = [];
    const params = [];

    if (scanId) {
      params.push(String(scanId));
      conditions.push(`scan_id = $${params.length}`);
    }
    if (ip) {
      params.push(`%${String(ip).trim()}%`);
      conditions.push(`ip_address LIKE $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const rowsRes = await query(
      `SELECT * FROM ip_exposures ${whereClause}
       ORDER BY last_enriched_at DESC, ip_address ASC
       LIMIT 250`,
      params
    );

    const exposures = rowsRes.rows.map((e) => {
      const openPorts = e.open_ports_json || [];
      const { sensitiveExposures, standardPorts } = classifyExposedPorts(openPorts);
      return {
        id: e.id,
        scanId: e.scan_id,
        ipAddress: e.ip_address,
        status: e.status,
        openPorts,
        sensitivePorts: sensitiveExposures,
        standardPorts,
        hostnames: e.hostnames_json || [],
        associatedHostnames: e.associated_hostnames_json || [],
        cpes: e.cpes_json || [],
        cves: e.cves_json || [],
        tags: e.tags_json || [],
        source: e.source,
        lastEnrichedAt: e.last_enriched_at,
        exposureMethodologyNote:
          'An exposed port indicates network reachability observed by Shodan InternetDB. It is not automatically an exploitable vulnerability without service and version verification.',
      };
    });

    res.status(200).json({
      total: exposures.length,
      shodanLicenseNotice: config.providers.shodan.licenseNotice,
      exposures,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
