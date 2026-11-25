const express = require('express');
const config = require('../config');
const { checkHealth, query } = require('../database/db');
const { getProvidersHealthStatus, clearProviderCache } = require('../services/providers/http.client');

const router = express.Router();

// GET /api/v1/health
router.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'SENTINEL Attack Surface Intelligence Platform',
    serverId: config.serverId,
    version: config.appVersion,
    environment: config.env,
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
  });
});

// GET /api/v1/ready
router.get('/ready', async (req, res) => {
  const dbHealth = await checkHealth();
  const isReady = dbHealth.healthy;

  res.status(isReady ? 200 : 503).json({
    status: isReady ? 'ready' : 'not_ready',
    serverId: config.serverId,
    version: config.appVersion,
    timestamp: new Date().toISOString(),
    checks: {
      database: dbHealth,
    },
  });
});

// GET /api/v1/version
router.get('/version', (req, res) => {
  res.status(200).json({
    name: 'SENTINEL',
    title: 'Cloud & Enterprise Attack Surface Intelligence Platform',
    version: config.appVersion,
    serverId: config.serverId,
    apiVersion: 'v1',
    nodeVersion: process.version,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/v1/providers/status
router.get('/providers/status', (req, res) => {
  res.status(200).json({
    serverId: config.serverId,
    timestamp: new Date().toISOString(),
    providers: getProvidersHealthStatus(),
    shodanLicenseNotice: config.providers.shodan.licenseNotice,
    nvdApiKeyConfigured: Boolean(config.providers.nvd.apiKey),
  });
});

// POST /api/v1/system/reset
router.post('/system/reset', async (req, res, next) => {
  try {
    await query(
      `TRUNCATE TABLE
         scan_stages,
         assets,
         dns_records,
         ip_exposures,
         cve_records,
         findings,
         certificates,
         scans,
         api_provider_logs,
         audit_logs
       RESTART IDENTITY CASCADE`
    );
    clearProviderCache();
    res.status(200).json({
      status: 'cleared',
      message: 'All scan history, assets, DNS records, exposures, CVEs, findings, and caches have been cleared.',
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
