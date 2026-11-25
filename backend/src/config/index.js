const path = require('path');
const dotenv = require('dotenv');

// Load .env from project root or backend folder
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  serverId: process.env.SERVER_ID || 'web01',
  appVersion: process.env.APP_VERSION || '1.0.0',

  db: {
    mode: process.env.DB_MODE || (process.env.DATABASE_URL ? 'pg' : 'pglite'),
    databaseUrl: process.env.DATABASE_URL || 'postgresql://sentinel:sentinel_password@localhost:5432/sentinel',
    pgliteDataDir:
      process.env.PGLITE_DATA_DIR === 'memory://'
        ? 'memory://'
        : path.resolve(
            __dirname,
            '../../',
            process.env.PGLITE_DATA_DIR || '../.sentinel_pgdata'
          ),
  },

  security: {
    sessionSecret: process.env.SESSION_SECRET || 'sentinel_dev_secret_key_change_in_prod_987654321',
    sessionCookieName: process.env.SESSION_COOKIE_NAME || 'sentinel_sid',
    sessionTtlHours: parseInt(process.env.SESSION_TTL_HOURS || '12', 10),
    corsAllowedOrigins: (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000')
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean),
  },

  defaultAuthorizedDomains: (
    process.env.DEFAULT_AUTHORIZED_DOMAINS ||
    'example.com,iana.org,nist.gov,cloudflare.com,shodan.io'
  )
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean),

  providers: {
    crtsh: {
      baseUrl: process.env.CRTSH_BASE_URL || 'https://crt.sh',
      timeoutMs: parseInt(process.env.CRTSH_TIMEOUT_MS || '15000', 10),
      maxRetries: 1,
      cacheTtlMinutes: 30,
    },
    cloudflare: {
      dohUrl: process.env.CLOUDFLARE_DOH_URL || 'https://cloudflare-dns.com/dns-query',
      timeoutMs: parseInt(process.env.CLOUDFLARE_TIMEOUT_MS || '8000', 10),
      maxRetries: 2,
      cacheTtlMinutes: 15,
    },
    shodan: {
      internetDbUrl: process.env.SHODAN_INTERNETDB_URL || 'https://internetdb.shodan.io',
      timeoutMs: parseInt(process.env.SHODAN_TIMEOUT_MS || '8000', 10),
      maxRetries: 2,
      cacheTtlMinutes: 30,
      licenseNotice:
        'Shodan InternetDB is free for non-commercial use only. Commercial deployment requires a separate Shodan commercial license.',
    },
    nvd: {
      baseUrl: process.env.NVD_API_BASE_URL || 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      apiKey: process.env.NVD_API_KEY || '',
      timeoutMs: parseInt(process.env.NVD_TIMEOUT_MS || '12000', 10),
      rateLimitDelayMs: parseInt(process.env.NVD_RATE_LIMIT_DELAY_MS || '1500', 10),
      maxRetries: 2,
      cacheTtlMinutes: 120,
    },
  },
};

module.exports = config;
