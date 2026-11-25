const app = require('./app');
const config = require('./config');
const { initDb, closeDb } = require('./database/db');
const { runMigrations } = require('./database/migrate');
const logger = require('./utils/logger');

let server = null;

async function startServer() {
  try {
    await initDb();
    await runMigrations();
    server = app.listen(config.port, () => {
      logger.info(`SENTINEL backend started on port ${config.port}`, {
        port: config.port,
        serverId: config.serverId,
        env: config.env,
      });
    });
    return server;
  } catch (err) {
    logger.error('Failed to start SENTINEL backend', { error: err.message });
    process.exit(1);
  }
}

async function shutdown(signal) {
  logger.info(`Received ${signal}. Gracefully shutting down...`);
  if (server) {
    server.close(async () => {
      await closeDb();
      process.exit(0);
    });
  } else {
    await closeDb();
    process.exit(0);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

if (require.main === module) {
  startServer();
}

module.exports = { startServer };
