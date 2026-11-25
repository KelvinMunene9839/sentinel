const config = require('../../config');
const { validatePublicIp, isValidCveId } = require('../../validators/network.validator');
const {
  getCached,
  setCached,
  recordCacheHit,
  fetchWithRetry,
} = require('./http.client');

/**
 * Normalize raw Shodan InternetDB JSON payload.
 */
function normalizeInternetDbPayload(ip, payload, retrievedAt) {
  const ports = Array.isArray(payload?.ports)
    ? payload.ports
        .map((p) => parseInt(p, 10))
        .filter((p) => !Number.isNaN(p) && p > 0 && p <= 65535)
        .sort((a, b) => a - b)
    : [];

  const hostnames = Array.isArray(payload?.hostnames)
    ? payload.hostnames.map((h) => String(h).trim().toLowerCase()).filter(Boolean)
    : [];

  const cpes = Array.isArray(payload?.cpes)
    ? payload.cpes.map((c) => String(c).trim()).filter(Boolean)
    : [];

  const vulnsRaw = Array.isArray(payload?.vulns) ? payload.vulns : [];
  const cves = Array.from(
    new Set(
      vulnsRaw
        .map((v) => String(v).trim().toUpperCase())
        .filter((v) => isValidCveId(v))
    )
  ).sort();

  const tags = Array.isArray(payload?.tags)
    ? payload.tags.map((t) => String(t).trim()).filter(Boolean)
    : [];

  return {
    ip,
    openPorts: Array.from(new Set(ports)),
    hostnames: Array.from(new Set(hostnames)),
    cpes: Array.from(new Set(cpes)),
    cves,
    tags: Array.from(new Set(tags)),
    source: 'Shodan InternetDB',
    licenseNotice: config.providers.shodan.licenseNotice,
    retrievedAt,
  };
}

/**
 * Query Shodan InternetDB for a validated public IP address.
 */
async function enrichPublicIp(ipInput, options = {}) {
  const validation = validatePublicIp(ipInput);
  if (!validation.valid) {
    return {
      provider: 'Shodan InternetDB',
      status: 'rejected',
      ip: String(ipInput || ''),
      error: validation.reason,
      openPorts: [],
      hostnames: [],
      cpes: [],
      cves: [],
      tags: [],
      retrievedAt: new Date().toISOString(),
    };
  }

  const cleanIp = validation.ip;
  const cacheKey = `shodan:${cleanIp}`;

  if (!options.bypassCache) {
    const cached = getCached(cacheKey);
    if (cached) {
      recordCacheHit('shodan');
      return {
        ...cached.data,
        fromCache: true,
        cachedAt: cached.cachedAt,
      };
    }
  }

  const url = `${config.providers.shodan.internetDbUrl}/${encodeURIComponent(cleanIp)}`;
  const retrievedAt = new Date().toISOString();

  try {
    // InternetDB returns 404 when no open ports or data are indexed for an IP
    const response = await fetchWithRetry(url, {
      providerKey: 'shodan',
      timeoutMs: options.timeoutMs || config.providers.shodan.timeoutMs,
      maxRetries: options.maxRetries ?? config.providers.shodan.maxRetries,
      acceptStatuses: [200, 404],
      headers: {
        Accept: 'application/json',
      },
      fetchImpl: options.fetchImpl,
    });

    if (response.status === 404) {
      const notIndexedResult = {
        provider: 'Shodan InternetDB',
        status: 'not_indexed',
        ip: cleanIp,
        openPorts: [],
        hostnames: [],
        cpes: [],
        cves: [],
        tags: [],
        source: 'Shodan InternetDB',
        licenseNotice: config.providers.shodan.licenseNotice,
        latencyMs: response.latencyMs,
        retrievedAt,
        fromCache: false,
      };
      setCached(cacheKey, notIndexedResult, config.providers.shodan.cacheTtlMinutes);
      return notIndexedResult;
    }

    let parsed;
    try {
      parsed = JSON.parse(response.text);
    } catch (err) {
      throw new Error(`Invalid JSON from Shodan InternetDB: ${err.message}`);
    }

    const normalized = normalizeInternetDbPayload(cleanIp, parsed, retrievedAt);
    const result = {
      provider: 'Shodan InternetDB',
      status: 'success',
      latencyMs: response.latencyMs,
      ...normalized,
      fromCache: false,
    };

    setCached(cacheKey, result, config.providers.shodan.cacheTtlMinutes);
    return result;
  } catch (err) {
    return {
      provider: 'Shodan InternetDB',
      status: 'failed',
      ip: cleanIp,
      openPorts: [],
      hostnames: [],
      cpes: [],
      cves: [],
      tags: [],
      source: 'Shodan InternetDB',
      licenseNotice: config.providers.shodan.licenseNotice,
      error: err.message,
      retrievedAt,
      fromCache: false,
    };
  }
}

module.exports = {
  normalizeInternetDbPayload,
  enrichPublicIp,
};
