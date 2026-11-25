const logger = require('../../utils/logger');

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024; // 8 MB safety ceiling for external responses

const providerState = {
  crtsh: {
    name: 'crt.sh Certificate Transparency',
    status: 'operational',
    lastSuccessAt: null,
    lastFailureAt: null,
    lastError: null,
    consecutiveFailures: 0,
    totalRequests: 0,
    cacheHits: 0,
  },
  cloudflare: {
    name: 'Cloudflare DNS-over-HTTPS',
    status: 'operational',
    lastSuccessAt: null,
    lastFailureAt: null,
    lastError: null,
    consecutiveFailures: 0,
    totalRequests: 0,
    cacheHits: 0,
  },
  shodan: {
    name: 'Shodan InternetDB',
    status: 'operational',
    lastSuccessAt: null,
    lastFailureAt: null,
    lastError: null,
    consecutiveFailures: 0,
    totalRequests: 0,
    cacheHits: 0,
  },
  nvd: {
    name: 'NIST National Vulnerability Database',
    status: 'operational',
    lastSuccessAt: null,
    lastFailureAt: null,
    lastError: null,
    consecutiveFailures: 0,
    totalRequests: 0,
    cacheHits: 0,
  },
};

const memoryCache = new Map();

function getCached(cacheKey) {
  const entry = memoryCache.get(cacheKey);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    memoryCache.delete(cacheKey);
    return null;
  }
  return entry;
}

function setCached(cacheKey, data, ttlMinutes) {
  const now = Date.now();
  memoryCache.set(cacheKey, {
    data,
    cachedAt: new Date(now).toISOString(),
    expiresAt: now + ttlMinutes * 60 * 1000,
  });
}

function clearProviderCache() {
  memoryCache.clear();
}

function recordProviderSuccess(providerKey, latencyMs) {
  const st = providerState[providerKey];
  if (!st) return;
  st.status = 'operational';
  st.lastSuccessAt = new Date().toISOString();
  st.lastLatencyMs = latencyMs;
  st.consecutiveFailures = 0;
  st.totalRequests += 1;
}

function recordProviderFailure(providerKey, errorMsg) {
  const st = providerState[providerKey];
  if (!st) return;
  st.lastFailureAt = new Date().toISOString();
  st.lastError = errorMsg;
  st.consecutiveFailures += 1;
  st.totalRequests += 1;
  st.status = st.consecutiveFailures >= 3 ? 'degraded' : 'operational';
}

function recordCacheHit(providerKey) {
  const st = providerState[providerKey];
  if (st) {
    st.cacheHits += 1;
  }
}

function getProvidersHealthStatus() {
  return Object.entries(providerState).map(([key, value]) => ({
    providerKey: key,
    ...value,
  }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Perform an HTTP GET request with timeout, response size cap, and bounded exponential backoff retries.
 */
async function fetchWithRetry(url, options = {}) {
  const {
    providerKey = 'unknown',
    timeoutMs = 10000,
    maxRetries = 2,
    headers = {},
    acceptStatuses = [200],
    fetchImpl = global.fetch,
  } = options;

  let lastError = null;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const startTime = Date.now();

    try {
      const response = await fetchImpl(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'SENTINEL-AttackSurfacePlatform/1.0 (Passive-Security-Reconnaissance)',
          ...headers,
        },
        signal: controller.signal,
      });

      clearTimeout(timer);
      const latencyMs = Date.now() - startTime;

      if (acceptStatuses.includes(response.status)) {
        const text = await response.text();
        if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
          throw new Error(`Response from ${providerKey} exceeded maximum allowed size (${MAX_RESPONSE_BYTES} bytes)`);
        }
        recordProviderSuccess(providerKey, latencyMs);
        return {
          status: response.status,
          text,
          latencyMs,
          headers: response.headers,
        };
      }

      // Non-retryable client errors (except 429 rate limit)
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        const err = new Error(`HTTP ${response.status} from ${providerKey}`);
        err.statusCode = response.status;
        err.retryable = false;
        recordProviderFailure(providerKey, err.message);
        throw err;
      }

      // Retryable 429 or 5xx
      lastError = new Error(`HTTP ${response.status} from ${providerKey}`);
      lastError.statusCode = response.status;
      lastError.retryable = true;
    } catch (err) {
      clearTimeout(timer);
      if (err.retryable === false) {
        throw err;
      }
      if (err.name === 'AbortError') {
        lastError = new Error(`Request timeout after ${timeoutMs}ms contacting ${providerKey}`);
        lastError.code = 'ETIMEDOUT';
      } else {
        lastError = err;
      }
    }

    if (attempt < maxRetries) {
      const backoffMs = Math.min(500 * Math.pow(2, attempt), 4000);
      logger.warn(`Retrying ${providerKey} request (attempt ${attempt + 1}/${maxRetries})`, {
        error: lastError.message,
        backoffMs,
      });
      await sleep(backoffMs);
    }
  }

  recordProviderFailure(providerKey, lastError ? lastError.message : 'Unknown error');
  throw lastError;
}

module.exports = {
  getCached,
  setCached,
  clearProviderCache,
  recordCacheHit,
  recordProviderSuccess,
  recordProviderFailure,
  getProvidersHealthStatus,
  fetchWithRetry,
  sleep,
};
