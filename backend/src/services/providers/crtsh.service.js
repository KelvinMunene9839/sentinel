const config = require('../../config');
const {
  normalizeDomain,
  isValidDomain,
  isSubdomainOf,
} = require('../../validators/network.validator');
const {
  getCached,
  setCached,
  recordCacheHit,
  fetchWithRetry,
} = require('./http.client');

/**
 * Normalize raw crt.sh JSON entries into deduplicated subdomains and certificate records.
 */
function normalizeCrtshEntries(rawEntries, targetDomain) {
  const cleanRoot = normalizeDomain(targetDomain);
  const subdomainMap = new Map();
  const certificateMap = new Map();

  if (!Array.isArray(rawEntries)) {
    return { subdomains: [], certificates: [] };
  }

  for (const item of rawEntries) {
    if (!item || typeof item !== 'object') continue;

    const certId = item.id ? String(item.id) : null;
    const commonNameRaw = item.common_name ? String(item.common_name) : '';
    const nameValueRaw = item.name_value ? String(item.name_value) : '';
    const issuerName = item.issuer_name ? String(item.issuer_name).trim() : 'Unknown Issuer';
    const notBefore = item.not_before || null;
    const notAfter = item.not_after || null;
    const serialNumber = item.serial_number || null;

    // Extract candidate hostnames from common_name and newline-separated name_value (SANs)
    const candidates = [
      commonNameRaw,
      ...nameValueRaw.split(/[\r\n,;\s]+/),
    ];

    const validSans = new Set();

    for (const candidate of candidates) {
      if (!candidate) continue;
      // Ignore email addresses or malformed strings
      if (candidate.includes('@') || candidate.includes('/')) continue;

      const normalizedHost = normalizeDomain(candidate);
      if (!isValidDomain(normalizedHost)) continue;
      if (!isSubdomainOf(normalizedHost, cleanRoot)) continue;

      validSans.add(normalizedHost);
    }

    for (const normalizedHost of validSans) {
      if (!subdomainMap.has(normalizedHost)) {
        subdomainMap.set(normalizedHost, {
          subdomain: normalizedHost,
          rootDomain: cleanRoot,
          source: 'crt.sh',
          certificateCount: 1,
          firstObservedCertNotBefore: notBefore,
          latestCertNotAfter: notAfter,
          issuers: issuerName ? [issuerName] : [],
        });
      } else {
        const existing = subdomainMap.get(normalizedHost);
        existing.certificateCount += 1;
        if (issuerName && !existing.issuers.includes(issuerName) && existing.issuers.length < 5) {
          existing.issuers.push(issuerName);
        }
      }
    }

    if (certId && validSans.size > 0 && !certificateMap.has(certId)) {
      const normalizedCommon = normalizeDomain(commonNameRaw);
      certificateMap.set(certId, {
        certificateId: certId,
        commonName: isValidDomain(normalizedCommon) ? normalizedCommon : Array.from(validSans)[0],
        subjectAlternativeNames: Array.from(validSans),
        issuerName,
        serialNumber,
        notBefore,
        notAfter,
        source: 'crt.sh',
      });
    }
  }

  return {
    subdomains: Array.from(subdomainMap.values()).sort((a, b) =>
      a.subdomain.localeCompare(b.subdomain)
    ),
    certificates: Array.from(certificateMap.values()).slice(0, 250),
  };
}

/**
 * Query crt.sh Certificate Transparency logs for a validated domain.
 */
async function discoverCertificates(domain, options = {}) {
  const cleanDomain = normalizeDomain(domain);
  if (!isValidDomain(cleanDomain)) {
    throw new Error(`Invalid target domain for crt.sh discovery: "${domain}"`);
  }

  const cacheKey = `crtsh:${cleanDomain}`;
  if (!options.bypassCache) {
    const cached = getCached(cacheKey);
    if (cached) {
      recordCacheHit('crtsh');
      return {
        ...cached.data,
        fromCache: true,
        cachedAt: cached.cachedAt,
      };
    }
  }

  const queryVariants = [
    `${config.providers.crtsh.baseUrl}/?q=${encodeURIComponent(`%.${cleanDomain}`)}&output=json`,
    `${config.providers.crtsh.baseUrl}/?q=${encodeURIComponent(cleanDomain)}&output=json`,
    `${config.providers.crtsh.baseUrl}/?Identity=${encodeURIComponent(cleanDomain)}&output=json`,
  ];
  const retrievedAt = new Date().toISOString();

  try {
    let response = null;
    let lastErr = null;
    for (const candidateUrl of queryVariants) {
      try {
        response = await fetchWithRetry(candidateUrl, {
          providerKey: 'crtsh',
          timeoutMs: options.timeoutMs || config.providers.crtsh.timeoutMs,
          maxRetries: options.maxRetries ?? config.providers.crtsh.maxRetries,
          headers: {
            Accept: 'application/json',
          },
          fetchImpl: options.fetchImpl,
        });
        break;
      } catch (variantErr) {
        lastErr = variantErr;
        if (options.fetchImpl) break;
      }
    }
    if (!response) {
      throw lastErr || new Error('crt.sh query failed across all query variants');
    }

    const trimmed = (response.text || '').trim();
    if (!trimmed) {
      const emptyResult = {
        provider: 'crt.sh',
        status: 'success',
        domain: cleanDomain,
        retrievedAt,
        latencyMs: response.latencyMs,
        subdomains: [
          {
            subdomain: cleanDomain,
            rootDomain: cleanDomain,
            source: 'target-root',
            certificateCount: 0,
            issuers: [],
          },
        ],
        certificates: [],
        rawEntryCount: 0,
        fromCache: false,
      };
      setCached(cacheKey, emptyResult, config.providers.crtsh.cacheTtlMinutes);
      return emptyResult;
    }

    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (parseErr) {
      throw new Error(`Invalid JSON returned by crt.sh: ${parseErr.message}`);
    }

    const normalized = normalizeCrtshEntries(parsed, cleanDomain);

    // Ensure root domain itself is always included in the subdomain list for downstream DNS resolution
    const hasRoot = normalized.subdomains.some((s) => s.subdomain === cleanDomain);
    if (!hasRoot) {
      normalized.subdomains.unshift({
        subdomain: cleanDomain,
        rootDomain: cleanDomain,
        source: 'target-root',
        certificateCount: 0,
        issuers: [],
      });
    }

    const result = {
      provider: 'crt.sh',
      status: 'success',
      domain: cleanDomain,
      retrievedAt,
      latencyMs: response.latencyMs,
      subdomains: normalized.subdomains,
      certificates: normalized.certificates,
      rawEntryCount: Array.isArray(parsed) ? parsed.length : 0,
      fromCache: false,
    };

    setCached(cacheKey, result, config.providers.crtsh.cacheTtlMinutes);
    return result;
  } catch (err) {
    return {
      provider: 'crt.sh',
      status: 'failed',
      domain: cleanDomain,
      retrievedAt,
      error: err.message,
      // Even when crt.sh fails or times out, return root domain so DNS resolution can proceed gracefully
      subdomains: [
        {
          subdomain: cleanDomain,
          rootDomain: cleanDomain,
          source: 'fallback-root',
          certificateCount: 0,
          issuers: [],
        },
      ],
      certificates: [],
      rawEntryCount: 0,
      fromCache: false,
    };
  }
}

module.exports = {
  normalizeCrtshEntries,
  discoverCertificates,
};
