const express = require('express');
const { query } = require('../database/db');
const {
  normalizeDomain,
  isValidDomain,
  isDomainAuthorized,
} = require('../validators/network.validator');
const {
  executeDomainDiscoveryPipeline,
  compareScanResults,
} = require('../services/discovery/discovery.orchestrator');
const {
  getAuthorizedDomainsList,
  createInitialScanRecord,
  updateScanStageProgress,
  saveCompletedScanResults,
  getScanDetailsById,
} = require('../database/scan.repository');
const { requireAuth, requireRole, verifyCsrf } = require('../middleware/auth.middleware');
const { recordAuditLog } = require('../utils/audit');

const router = express.Router();

// GET /api/v1/scans/authorized-domains
router.get('/authorized-domains', async (req, res, next) => {
  try {
    const resDb = await query('SELECT id, domain, description, is_active, created_at FROM authorized_domains WHERE is_active = TRUE ORDER BY domain ASC');
    res.status(200).json({
      domains: resDb.rows,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/v1/scans/authorized-domains (Administrator can add an authorized domain)
router.post(
  '/authorized-domains',
  requireAuth,
  requireRole(['Administrator', 'Security Analyst']),
  verifyCsrf,
  async (req, res, next) => {
    try {
      const { domain, description } = req.body || {};
      const clean = normalizeDomain(domain);
      if (!isValidDomain(clean)) {
        return res.status(400).json({
          error: 'InvalidDomain',
          message: `Invalid domain format: "${domain}"`,
        });
      }

      await query(
        `INSERT INTO authorized_domains (domain, description, added_by, is_active)
         VALUES ($1, $2, $3, TRUE)
         ON CONFLICT (domain) DO UPDATE SET is_active = TRUE, description = EXCLUDED.description`,
        [clean, description || 'Authorized target domain', req.user.id]
      );

      await recordAuditLog({
        userId: req.user.id,
        username: req.user.username,
        action: 'AUTHORIZED_DOMAIN_ADDED',
        resourceType: 'authorized_domain',
        resourceId: clean,
        ipAddress: req.ip,
      });

      const domains = await getAuthorizedDomainsList();
      res.status(201).json({
        status: 'added',
        domain: clean,
        authorizedDomains: domains,
      });
    } catch (err) {
      next(err);
    }
  }
);

// POST /api/v1/scans
router.post(
  '/',
  requireAuth,
  requireRole(['Administrator', 'Security Analyst']),
  verifyCsrf,
  async (req, res, next) => {
    try {
      const {
        domain,
        authorizationConfirmed,
        autoAuthorizeScope = false,
        maxSubdomainsToResolve = 12,
        maxCvesToEnrich = 8,
        asyncMode = false,
      } = req.body || {};

      const cleanDomain = normalizeDomain(domain);
      if (!isValidDomain(cleanDomain)) {
        return res.status(400).json({
          error: 'InvalidDomain',
          message: `Invalid domain syntax: "${domain}"`,
        });
      }

      if (!authorizationConfirmed) {
        return res.status(403).json({
          error: 'AuthorizationConfirmationRequired',
          message: 'Explicit authorization confirmation is required before initiating discovery.',
        });
      }

      const authorizedDomainsList = await getAuthorizedDomainsList();
      if (!isDomainAuthorized(cleanDomain, authorizedDomainsList)) {
        if (!autoAuthorizeScope) {
          return res.status(403).json({
            error: 'OutOfScopeDomain',
            message: `Domain "${cleanDomain}" is not in the authorized scope (${authorizedDomainsList.join(', ')}). Add it to authorized domains first.`,
          });
        }
        await query(
          `INSERT INTO authorized_domains (domain, description, added_by, is_active)
           VALUES ($1, $2, $3, TRUE)
           ON CONFLICT (domain) DO UPDATE SET is_active = TRUE`,
          [cleanDomain, 'Authorized via explicit operator scan attestation', req.user.id]
        );
        authorizedDomainsList.push(cleanDomain);
      }

      const scanId = await createInitialScanRecord({
        domain: cleanDomain,
        userId: req.user.id,
      });

      await recordAuditLog({
        userId: req.user.id,
        username: req.user.username,
        action: 'SCAN_INITIATED',
        resourceType: 'scan',
        resourceId: scanId,
        details: { domain: cleanDomain },
        ipAddress: req.ip,
      });

      const runPipelineJob = async () => {
        try {
          const result = await executeDomainDiscoveryPipeline({
            domain: cleanDomain,
            authorizationConfirmed: true,
            authorizedDomainsList,
            maxSubdomainsToResolve: Math.min(Math.max(Number(maxSubdomainsToResolve) || 12, 1), 30),
            maxCvesToEnrich: Math.min(Math.max(Number(maxCvesToEnrich) || 8, 1), 20),
            onStageUpdate: async (progress) => {
              await updateScanStageProgress(scanId, progress);
            },
          });
          await saveCompletedScanResults(scanId, result);
          return result;
        } catch (err) {
          await query(
            `UPDATE scans
             SET status = 'failed',
                 provider_failures_json = $1,
                 completed_at = NOW()
             WHERE id = $2`,
            [JSON.stringify([err.message]), scanId]
          );
          throw err;
        }
      };

      if (asyncMode) {
        runPipelineJob().catch(() => {});
        return res.status(202).json({
          scanId,
          domain: cleanDomain,
          status: 'running',
        });
      }

      await runPipelineJob();
      const fullScan = await getScanDetailsById(scanId);
      res.status(201).json(fullScan);
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/v1/scans
router.get('/', async (req, res, next) => {
  try {
    const scansRes = await query(
      `SELECT id, domain, status, current_stage_number, current_stage_key,
              provider_status_json, provider_failures_json, summary_json,
              started_at, completed_at
       FROM scans
       ORDER BY started_at DESC
       LIMIT 100`
    );

    res.status(200).json({
      total: scansRes.rows.length,
      scans: scansRes.rows.map((s) => ({
        id: s.id,
        domain: s.domain,
        status: s.status,
        currentStageNumber: s.current_stage_number,
        currentStageKey: s.current_stage_key,
        providerStatusSummary: s.provider_status_json || {},
        providerFailures: s.provider_failures_json || [],
        summary: s.summary_json || {},
        startedAt: s.started_at,
        completedAt: s.completed_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/scans/:id
router.get('/:id', async (req, res, next) => {
  try {
    const details = await getScanDetailsById(req.params.id);
    if (!details) {
      return res.status(404).json({
        error: 'ScanNotFound',
        message: `Scan ${req.params.id} was not found.`,
      });
    }
    res.status(200).json(details);
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/scans/:id/progress
router.get('/:id/progress', async (req, res, next) => {
  try {
    const scanRes = await query(
      `SELECT id, domain, status, current_stage_number, current_stage_key,
              provider_status_json, provider_failures_json, summary_json,
              started_at, completed_at
       FROM scans WHERE id = $1`,
      [req.params.id]
    );
    if (scanRes.rows.length === 0) {
      return res.status(404).json({ error: 'ScanNotFound', message: 'Scan not found' });
    }
    const stagesRes = await query(
      'SELECT stage_number, stage_key, stage_label, status, detail, started_at, completed_at FROM scan_stages WHERE scan_id = $1 ORDER BY stage_number ASC',
      [req.params.id]
    );
    const s = scanRes.rows[0];
    res.status(200).json({
      id: s.id,
      domain: s.domain,
      status: s.status,
      currentStageNumber: s.current_stage_number,
      currentStageKey: s.current_stage_key,
      providerStatusSummary: s.provider_status_json || {},
      providerFailures: s.provider_failures_json || [],
      summary: s.summary_json || {},
      startedAt: s.started_at,
      completedAt: s.completed_at,
      stages: stagesRes.rows.map((st) => ({
        stageNumber: st.stage_number,
        key: st.stage_key,
        label: st.stage_label,
        status: st.status,
        detail: st.detail,
        startedAt: st.started_at,
        completedAt: st.completed_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/v1/scans/:id/cancel
router.post(
  '/:id/cancel',
  requireAuth,
  requireRole(['Administrator', 'Security Analyst']),
  verifyCsrf,
  async (req, res, next) => {
    try {
      const scanRes = await query('SELECT id, status FROM scans WHERE id = $1', [req.params.id]);
      if (scanRes.rows.length === 0) {
        return res.status(404).json({ error: 'ScanNotFound', message: 'Scan not found' });
      }
      await query(
        `UPDATE scans SET status = 'cancelled', completed_at = NOW() WHERE id = $1 AND status = 'running'`,
        [req.params.id]
      );
      res.status(200).json({ id: req.params.id, status: 'cancelled' });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/v1/scans/:id/compare/:otherId
router.get('/:id/compare/:otherId', async (req, res, next) => {
  try {
    const [scanA, scanB] = await Promise.all([
      getScanDetailsById(req.params.id),
      getScanDetailsById(req.params.otherId),
    ]);
    if (!scanA || !scanB) {
      return res.status(404).json({
        error: 'ScanNotFound',
        message: 'One or both scan IDs could not be found for comparison.',
      });
    }
    const comparison = compareScanResults(scanA, scanB);
    res.status(200).json(comparison);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
