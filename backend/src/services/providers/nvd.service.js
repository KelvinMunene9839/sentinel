const config = require('../../config');
const { isValidCveId } = require('../../validators/network.validator');
const {
  getCached,
  setCached,
  recordCacheHit,
  fetchWithRetry,
  sleep,
} = require('./http.client');

let lastNvdRequestTimestamp = 0;

/**
 * Extract preferred CVSS metric (v3.1 -> v3.0 -> v4.0 -> v2.0) from NVD CVE v2.0 metrics object.
 */
function extractCvssMetrics(metrics = {}) {
  if (Array.isArray(metrics.cvssMetricV31) && metrics.cvssMetricV31.length > 0) {
    const primary = metrics.cvssMetricV31.find((m) => m.type === 'Primary') || metrics.cvssMetricV31[0];
    const data = primary.cvssData || {};
    return {
      cvssVersion: '3.1',
      cvssScore: typeof data.baseScore === 'number' ? data.baseScore : null,
      severity: (data.baseSeverity || primary.baseSeverity || 'UNKNOWN').toUpperCase(),
      vectorString: data.vectorString || null,
    };
  }

  if (Array.isArray(metrics.cvssMetricV30) && metrics.cvssMetricV30.length > 0) {
    const primary = metrics.cvssMetricV30.find((m) => m.type === 'Primary') || metrics.cvssMetricV30[0];
    const data = primary.cvssData || {};
    return {
      cvssVersion: '3.0',
      cvssScore: typeof data.baseScore === 'number' ? data.baseScore : null,
      severity: (data.baseSeverity || primary.baseSeverity || 'UNKNOWN').toUpperCase(),
      vectorString: data.vectorString || null,
    };
  }

  if (Array.isArray(metrics.cvssMetricV40) && metrics.cvssMetricV40.length > 0) {
    const primary = metrics.cvssMetricV40[0];
    const data = primary.cvssData || {};
    return {
      cvssVersion: '4.0',
      cvssScore: typeof data.baseScore === 'number' ? data.baseScore : null,
      severity: (data.baseSeverity || 'UNKNOWN').toUpperCase(),
      vectorString: data.vectorString || null,
    };
  }

  if (Array.isArray(metrics.cvssMetricV2) && metrics.cvssMetricV2.length > 0) {
    const primary = metrics.cvssMetricV2[0];
    const data = primary.cvssData || {};
    return {
      cvssVersion: '2.0',
      cvssScore: typeof data.baseScore === 'number' ? data.baseScore : null,
      severity: (primary.baseSeverity || 'UNKNOWN').toUpperCase(),
      vectorString: data.vectorString || null,
    };
  }

  return {
    cvssVersion: null,
    cvssScore: null,
    severity: 'UNKNOWN',
    vectorString: null,
  };
}

/**
 * Normalize a single NVD CVE 2.0 record into SENTINEL's internal vulnerability format.
 */
function normalizeNvdCveItem(cveObj, retrievedAt) {
  const cveId = String(cveObj?.id || '').toUpperCase();
  const descriptions = Array.isArray(cveObj?.descriptions) ? cveObj.descriptions : [];
  const enDesc = descriptions.find((d) => d.lang === 'en') || descriptions[0];
  const description = enDesc ? String(enDesc.value).trim() : 'No description provided by NVD.';

  const cvss = extractCvssMetrics(cveObj?.metrics || {});

  const weaknesses = [];
  if (Array.isArray(cveObj?.weaknesses)) {
    for (const w of cveObj.weaknesses) {
      if (Array.isArray(w.description)) {
        for (const wd of w.description) {
          if (wd.value && !weaknesses.includes(wd.value)) {
            weaknesses.push(wd.value);
          }
        }
      }
    }
  }

  const references = [];
  if (Array.isArray(cveObj?.references)) {
    for (const ref of cveObj.references.slice(0, 12)) {
      if (ref && ref.url) {
        references.push({
          url: ref.url,
          source: ref.source || null,
          tags: Array.isArray(ref.tags) ? ref.tags : [],
        });
      }
    }
  }

  const affectedProducts = [];
  if (Array.isArray(cveObj?.configurations)) {
    for (const cfg of cveObj.configurations) {
      const nodes = Array.isArray(cfg.nodes) ? cfg.nodes : [];
      for (const node of nodes) {
        const matches = Array.isArray(node.cpeMatch) ? node.cpeMatch : [];
        for (const m of matches) {
          if (m.criteria && affectedProducts.length < 25 && !affectedProducts.includes(m.criteria)) {
            affectedProducts.push(m.criteria);
          }
        }
      }
    }
  }

  return {
    cveId,
    description,
    cvssScore: cvss.cvssScore,
    cvssVersion: cvss.cvssVersion,
    severity: cvss.severity,
    vectorString: cvss.vectorString,
    publishedDate: cveObj?.published || null,
    lastModifiedDate: cveObj?.lastModified || null,
    vulnStatus: cveObj?.vulnStatus || null,
    weaknesses,
    affectedProducts,
    references,
    verificationStatus: 'CVE_ASSOCIATION_OBSERVED',
    verificationNote:
      'Observed CVE association via passive CPE/IP fingerprint. Active version verification has not been performed; do not assume exploitability without confirming the exact software patch level.',
    source: 'NIST NVD',
    retrievedAt,
  };
}

/**
 * Throttle requests to NIST NVD when no API key is configured or during batch enrichment.
 */
async function enforceNvdRateLimit(customDelayMs) {
  const delayMs =
    typeof customDelayMs === 'number'
      ? customDelayMs
      : config.providers.nvd.apiKey
      ? 250
      : config.providers.nvd.rateLimitDelayMs;

  const now = Date.now();
  const elapsed = now - lastNvdRequestTimestamp;
  if (lastNvdRequestTimestamp > 0 && elapsed < delayMs) {
    await sleep(delayMs - elapsed);
  }
  lastNvdRequestTimestamp = Date.now();
}

/**
 * Enrich a single CVE identifier from NIST NVD API v2.0.
 */
async function enrichCve(cveIdInput, options = {}) {
  const cleanCveId = String(cveIdInput || '').trim().toUpperCase();
  if (!isValidCveId(cleanCveId)) {
    throw new Error(`Invalid CVE identifier format: "${cveIdInput}"`);
  }

  const cacheKey = `nvd:${cleanCveId}`;
  if (!options.bypassCache) {
    const cached = getCached(cacheKey);
    if (cached) {
      recordCacheHit('nvd');
      return {
        ...cached.data,
        fromCache: true,
        cachedAt: cached.cachedAt,
      };
    }
  }

  await enforceNvdRateLimit(options.rateLimitDelayMs);

  const url = `${config.providers.nvd.baseUrl}?cveId=${encodeURIComponent(cleanCveId)}`;
  const headers = {
    Accept: 'application/json',
  };
  // Never expose NVD_API_KEY to frontend; attach only in backend-to-NVD request headers
  if (config.providers.nvd.apiKey) {
    headers.apiKey = config.providers.nvd.apiKey;
  }

  const retrievedAt = new Date().toISOString();

  try {
    const response = await fetchWithRetry(url, {
      providerKey: 'nvd',
      timeoutMs: options.timeoutMs || config.providers.nvd.timeoutMs,
      maxRetries: options.maxRetries ?? config.providers.nvd.maxRetries,
      headers,
      fetchImpl: options.fetchImpl,
    });

    let parsed;
    try {
      parsed = JSON.parse(response.text);
    } catch (err) {
      throw new Error(`Invalid JSON from NIST NVD: ${err.message}`);
    }

    const vulnerabilities = Array.isArray(parsed?.vulnerabilities) ? parsed.vulnerabilities : [];
    if (vulnerabilities.length === 0 || !vulnerabilities[0]?.cve) {
      const notFoundResult = {
        provider: 'NIST NVD',
        status: 'not_found',
        cveId: cleanCveId,
        description: 'CVE record not found in NIST NVD database.',
        cvssScore: null,
        cvssVersion: null,
        severity: 'UNKNOWN',
        publishedDate: null,
        lastModifiedDate: null,
        weaknesses: [],
        affectedProducts: [],
        references: [],
        verificationStatus: 'CVE_ASSOCIATION_OBSERVED',
        verificationNote: 'Unverified CVE identifier.',
        source: 'NIST NVD',
        retrievedAt,
        fromCache: false,
      };
      setCached(cacheKey, notFoundResult, config.providers.nvd.cacheTtlMinutes);
      return notFoundResult;
    }

    const normalized = normalizeNvdCveItem(vulnerabilities[0].cve, retrievedAt);
    const result = {
      provider: 'NIST NVD',
      status: 'success',
      latencyMs: response.latencyMs,
      ...normalized,
      fromCache: false,
    };

    setCached(cacheKey, result, config.providers.nvd.cacheTtlMinutes);
    return result;
  } catch (err) {
    return {
      provider: 'NIST NVD',
      status: 'failed',
      cveId: cleanCveId,
      description: `NVD enrichment unavailable (${err.message}).`,
      cvssScore: null,
      cvssVersion: null,
      severity: 'UNKNOWN',
      publishedDate: null,
      lastModifiedDate: null,
      weaknesses: [],
      affectedProducts: [],
      references: [],
      verificationStatus: 'CVE_ASSOCIATION_OBSERVED',
      verificationNote:
        'Observed CVE association from passive IP intelligence; NVD enrichment could not be completed at scan time.',
      source: 'NIST NVD',
      error: err.message,
      retrievedAt,
      fromCache: false,
    };
  }
}

/**
 * Deduplicate and enrich a batch of CVE identifiers.
 */
async function enrichCveBatch(cveList = [], options = {}) {
  const uniqueCves = Array.from(
    new Set(
      (Array.isArray(cveList) ? cveList : [])
        .map((c) => String(c || '').trim().toUpperCase())
        .filter((c) => isValidCveId(c))
    )
  );

  const maxBatch = options.maxBatchSize || 15;
  const targetCves = uniqueCves.slice(0, maxBatch);
  const results = [];

  for (const cveId of targetCves) {
    const enriched = await enrichCve(cveId, options);
    results.push(enriched);
  }

  return {
    totalUniqueCves: uniqueCves.length,
    enrichedCount: results.filter((r) => r.status === 'success').length,
    failedCount: results.filter((r) => r.status === 'failed').length,
    records: results,
  };
}

module.exports = {
  extractCvssMetrics,
  normalizeNvdCveItem,
  enrichCve,
  enrichCveBatch,
};
