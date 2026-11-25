const express = require('express');
const { query } = require('../database/db');
const { getScanDetailsById } = require('../database/scan.repository');
const {
  generateAssetInventoryCsv,
  generateVulnerabilityCsv,
  generateDnsInventoryCsv,
  generateConsolidatedJsonReport,
} = require('../services/reports/report.generator');
const { recordAuditLog } = require('../utils/audit');

const router = express.Router();

// GET /api/v1/reports
router.get('/', async (req, res, next) => {
  try {
    const scansRes = await query(
      `SELECT id, domain, status, summary_json, provider_failures_json, started_at, completed_at
       FROM scans
       ORDER BY started_at DESC
       LIMIT 50`
    );

    res.status(200).json({
      availableScanReports: scansRes.rows.map((s) => ({
        scanId: s.id,
        domain: s.domain,
        status: s.status,
        summary: s.summary_json || {},
        providerFailures: s.provider_failures_json || [],
        startedAt: s.started_at,
        completedAt: s.completed_at,
        supportedFormats: [
          { type: 'assets_csv', label: 'Asset Inventory (CSV)' },
          { type: 'vulnerabilities_csv', label: 'Vulnerability Report (CSV)' },
          { type: 'dns_csv', label: 'DNS Inventory (CSV)' },
          { type: 'consolidated_json', label: 'Consolidated Scan Report (JSON)' },
        ],
      })),
    });
  } catch (err) {
    next(err);
  }
});

async function handleReportExport(req, res, next) {
  try {
    const source = req.method === 'GET' ? req.query : req.body;
    let { scanId, reportType = 'consolidated_json' } = source || {};

    if (!scanId) {
      const latestRes = await query('SELECT id FROM scans ORDER BY started_at DESC LIMIT 1');
      if (latestRes.rows.length === 0) {
        return res.status(404).json({
          error: 'NoScansAvailable',
          message: 'No completed scans exist yet to export. Run a domain discovery scan first.',
        });
      }
      scanId = latestRes.rows[0].id;
    }

    const scan = await getScanDetailsById(scanId);
    if (!scan) {
      return res.status(404).json({
        error: 'ScanNotFound',
        message: `Scan "${scanId}" was not found.`,
      });
    }

    let report;
    switch (reportType) {
      case 'assets_csv':
        report = generateAssetInventoryCsv(scan);
        break;
      case 'vulnerabilities_csv':
        report = generateVulnerabilityCsv(scan);
        break;
      case 'dns_csv':
        report = generateDnsInventoryCsv(scan);
        break;
      case 'consolidated_json':
      case 'json':
      default:
        report = generateConsolidatedJsonReport(scan);
        break;
    }

    await recordAuditLog({
      userId: req.user?.id || null,
      username: req.user?.username || 'anonymous',
      action: 'REPORT_EXPORTED',
      resourceType: 'report',
      resourceId: `${scan.id}:${reportType}`,
      details: { filename: report.filename },
      ipAddress: req.ip,
    });

    res.setHeader('Content-Type', report.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
    res.status(200).send(report.content);
  } catch (err) {
    next(err);
  }
}

// POST /api/v1/reports/export & GET /api/v1/reports/export
router.post('/export', handleReportExport);
router.get('/export', handleReportExport);

module.exports = router;
