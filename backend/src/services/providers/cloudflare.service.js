const config = require('../../config');
const { normalizeDomain, isValidDomain } = require('../../validators/network.validator');
const {
  getCached,
  setCached,
  recordCacheHit,
  fetchWithRetry,
} = require('./http.client');

const SUPPORTED_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'CAA', 'SOA'];

const DNS_TYPE_CODE_TO_NAME = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  257: 'CAA',
};

const RCODE_MAP = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
};

function cleanDnsValue(recordType, rawData) {
  if (typeof rawData !== 'string') return String(rawData || '');
  const trimmed = rawData.trim();

  if (recordType === 'CNAME' || recordType === 'NS') {
    return trimmed.replace(/\.$/, '').toLowerCase();
  }
  if (recordType === 'MX') {
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      return `${parts[0]} ${parts[1].replace(/\.$/, '').toLowerCase()}`;
    }
    return trimmed.replace(/\.$/, '').toLowerCase();
  }
  if (recordType === 'TXT') {
    return trimmed.replace(/^"|"$/g, '');
  }
  return trimmed;
}

/**
 * Normalize a single Cloudflare DoH JSON response for a (hostname, recordType) query.
 */
function normalizeDohResponse(hostname, requestedType, payload, retrievedAt) {
  const cleanHost = normalizeDomain(hostname);
  const rcode = typeof payload?.Status === 'number' ? payload.Status : -1;
  const rcodeName = RCODE_MAP[rcode] || `RCODE_${rcode}`;
  const answers = Array.isArray(payload?.Answer) ? payload.Answer : [];

  const records = [];
  for (const ans of answers) {
    if (!ans || typeof ans !== 'object') continue;
    const typeName = DNS_TYPE_CODE_TO_NAME[ans.type] || requestedType;
    const value = cleanDnsValue(typeName, ans.data);
    records.push({
      hostname: normalizeDomain(ans.name || cleanHost),
      queriedHostname: cleanHost,
      recordType: typeName,
      value,
      ttl: typeof ans.TTL === 'number' ? ans.TTL : null,
      provider: 'Cloudflare DoH',
      resolutionStatus: rcodeName,
      retrievedAt,
    });
  }

  return {
    hostname: cleanHost,
    requestedType,
    status: rcodeName,
    rcode,
    records,
    retrievedAt,
  };
}

/**
 * Query Cloudflare DoH for a specific record type.
 */
async function queryDnsRecordType(hostname, recordType = 'A', options = {}) {
  const cleanHost = normalizeDomain(hostname);
  if (!isValidDomain(cleanHost)) {
    throw new Error(`Invalid hostname for DNS query: "${hostname}"`);
  }
  const upperType = String(recordType).toUpperCase();
  if (!SUPPORTED_RECORD_TYPES.includes(upperType)) {
    throw new Error(`Unsupported DNS record type: "${recordType}"`);
  }

  const cacheKey = `doh:${cleanHost}:${upperType}`;
  if (!options.bypassCache) {
    const cached = getCached(cacheKey);
    if (cached) {
      recordCacheHit('cloudflare');
      return {
        ...cached.data,
        fromCache: true,
        cachedAt: cached.cachedAt,
      };
    }
  }

  const url = `${config.providers.cloudflare.dohUrl}?name=${encodeURIComponent(cleanHost)}&type=${encodeURIComponent(upperType)}`;
  const retrievedAt = new Date().toISOString();

  try {
    const response = await fetchWithRetry(url, {
      providerKey: 'cloudflare',
      timeoutMs: options.timeoutMs || config.providers.cloudflare.timeoutMs,
      maxRetries: options.maxRetries ?? config.providers.cloudflare.maxRetries,
      headers: {
        Accept: 'application/dns-json',
      },
      fetchImpl: options.fetchImpl,
    });

    let parsed;
    try {
      parsed = JSON.parse(response.text);
    } catch (err) {
      throw new Error(`Invalid JSON from Cloudflare DoH: ${err.message}`);
    }

    const normalized = normalizeDohResponse(cleanHost, upperType, parsed, retrievedAt);
    const result = {
      provider: 'Cloudflare DoH',
      queryStatus: 'success',
      latencyMs: response.latencyMs,
      ...normalized,
      fromCache: false,
    };

    setCached(cacheKey, result, config.providers.cloudflare.cacheTtlMinutes);
    return result;
  } catch (err) {
    return {
      provider: 'Cloudflare DoH',
      queryStatus: 'failed',
      hostname: cleanHost,
      requestedType: upperType,
      status: 'ERROR',
      rcode: -1,
      records: [],
      error: err.message,
      retrievedAt,
      fromCache: false,
    };
  }
}

/**
 * Resolve a comprehensive DNS profile for a hostname across supported record types.
 */
async function resolveHostnameProfile(hostname, options = {}) {
  const cleanHost = normalizeDomain(hostname);
  if (!isValidDomain(cleanHost)) {
    throw new Error(`Invalid hostname for DNS profile resolution: "${hostname}"`);
  }

  const recordTypes = options.recordTypes || SUPPORTED_RECORD_TYPES;
  const queryResults = await Promise.all(
    recordTypes.map((type) => queryDnsRecordType(cleanHost, type, options))
  );

  const allRecords = [];
  const seenKeys = new Set();
  const ipv4Addresses = new Set();
  const ipv6Addresses = new Set();
  const cnameTargets = new Set();
  const mailServers = new Set();
  const nameServers = new Set();
  const txtRecords = [];
  const caaRecords = [];
  const soaRecords = [];

  let anySuccess = false;
  let isNxDomain = false;
  const errors = [];

  for (const res of queryResults) {
    if (res.queryStatus === 'success') {
      anySuccess = true;
      if (res.status === 'NXDOMAIN') {
        isNxDomain = true;
      }
    } else if (res.error) {
      errors.push(`${res.requestedType}: ${res.error}`);
    }

    for (const rec of res.records) {
      const dedupKey = `${rec.hostname}|${rec.recordType}|${rec.value}`;
      if (!seenKeys.has(dedupKey)) {
        seenKeys.add(dedupKey);
        allRecords.push(rec);
      }

      if (rec.recordType === 'A') ipv4Addresses.add(rec.value);
      if (rec.recordType === 'AAAA') ipv6Addresses.add(rec.value);
      if (rec.recordType === 'CNAME') cnameTargets.add(rec.value);
      if (rec.recordType === 'MX') mailServers.add(rec.value);
      if (rec.recordType === 'NS') nameServers.add(rec.value);
      if (rec.recordType === 'TXT' && !txtRecords.includes(rec.value)) txtRecords.push(rec.value);
      if (rec.recordType === 'CAA' && !caaRecords.includes(rec.value)) caaRecords.push(rec.value);
      if (rec.recordType === 'SOA' && !soaRecords.includes(rec.value)) soaRecords.push(rec.value);
    }
  }

  // Verify whether CNAME targets themselves resolve if CNAME exists but no A/AAAA was returned
  let cnameTargetResolves = ipv4Addresses.size > 0 || ipv6Addresses.size > 0;
  let cnameResolutionStatus = cnameTargetResolves ? 'NOERROR' : 'UNRESOLVED';

  if (cnameTargets.size > 0 && !cnameTargetResolves) {
    const primaryCname = Array.from(cnameTargets)[0];
    if (isValidDomain(primaryCname)) {
      const targetACheck = await queryDnsRecordType(primaryCname, 'A', options);
      cnameResolutionStatus = targetACheck.status;
      for (const rec of targetACheck.records) {
        if (rec.recordType === 'A') {
          ipv4Addresses.add(rec.value);
          cnameTargetResolves = true;
        }
      }
    }
  }

  const resolves = ipv4Addresses.size > 0 || ipv6Addresses.size > 0;
  let resolutionStatus = 'NOERROR';
  if (!anySuccess) {
    resolutionStatus = 'PROVIDER_ERROR';
  } else if (isNxDomain && allRecords.length === 0) {
    resolutionStatus = 'NXDOMAIN';
  } else if (cnameTargets.size > 0 && !cnameTargetResolves) {
    resolutionStatus = 'DANGLING_CNAME';
  } else if (!resolves && allRecords.length === 0) {
    resolutionStatus = 'NODATA';
  }

  return {
    provider: 'Cloudflare DoH',
    status: anySuccess ? 'success' : 'failed',
    hostname: cleanHost,
    resolves,
    resolutionStatus,
    ipv4Addresses: Array.from(ipv4Addresses),
    ipv6Addresses: Array.from(ipv6Addresses),
    cnameTargets: Array.from(cnameTargets),
    cnameTargetResolves,
    cnameResolutionStatus,
    mailServers: Array.from(mailServers),
    nameServers: Array.from(nameServers),
    txtRecords,
    caaRecords,
    soaRecords,
    records: allRecords,
    errors,
    retrievedAt: new Date().toISOString(),
  };
}

module.exports = {
  SUPPORTED_RECORD_TYPES,
  normalizeDohResponse,
  queryDnsRecordType,
  resolveHostnameProfile,
};
