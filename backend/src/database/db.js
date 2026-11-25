const { Pool } = require('pg');
const { PGlite } = require('@electric-sql/pglite');
const fs = require('fs');
const path = require('path');
const config = require('../config');
const logger = require('../utils/logger');

let pgPool = null;
let pgliteInstance = null;
let isInitialized = false;

async function initDb() {
  if (isInitialized) return;

  if (config.db.mode === 'pg') {
    pgPool = new Pool({
      connectionString: config.db.databaseUrl,
      max: 15,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    await pgPool.query('SELECT 1');
    logger.info('Connected to external PostgreSQL database', { mode: 'pg' });
  } else {
    const dataDir = config.db.pgliteDataDir;
    if (dataDir !== 'memory://') {
      fs.mkdirSync(path.dirname(dataDir), { recursive: true });
    }
    pgliteInstance = new PGlite(dataDir === 'memory://' ? undefined : dataDir);
    await pgliteInstance.waitReady;
    logger.info('Initialized embedded PostgreSQL (PGlite) database', {
      mode: 'pglite',
      dataDir,
    });
  }

  isInitialized = true;
}

async function query(text, params = []) {
  if (!isInitialized) {
    await initDb();
  }
  if (config.db.mode === 'pg') {
    return pgPool.query(text, params);
  }
  return pgliteInstance.query(text, params);
}

async function exec(sqlText) {
  if (!isInitialized) {
    await initDb();
  }
  if (config.db.mode === 'pg') {
    return pgPool.query(sqlText);
  }
  return pgliteInstance.exec(sqlText);
}

async function withTransaction(fn) {
  if (!isInitialized) {
    await initDb();
  }
  if (config.db.mode === 'pg') {
    const client = await pgPool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } else {
    await pgliteInstance.query('BEGIN');
    try {
      const clientShim = {
        query: (t, p) => pgliteInstance.query(t, p),
      };
      const result = await fn(clientShim);
      await pgliteInstance.query('COMMIT');
      return result;
    } catch (err) {
      await pgliteInstance.query('ROLLBACK');
      throw err;
    }
  }
}

async function checkHealth() {
  try {
    const start = Date.now();
    await query('SELECT 1 AS ok');
    return {
      healthy: true,
      mode: config.db.mode,
      latencyMs: Date.now() - start,
    };
  } catch (err) {
    return {
      healthy: false,
      mode: config.db.mode,
      error: err.message,
    };
  }
}

async function closeDb() {
  if (pgPool) {
    await pgPool.end();
    pgPool = null;
  }
  if (pgliteInstance) {
    await pgliteInstance.close();
    pgliteInstance = null;
  }
  isInitialized = false;
}

module.exports = {
  initDb,
  query,
  exec,
  withTransaction,
  checkHealth,
  closeDb,
};
