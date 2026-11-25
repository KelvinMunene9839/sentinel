const config = require('../config');

function formatLog(level, message, meta = {}) {
  const payload = {
    timestamp: new Date().toISOString(),
    level,
    serverId: config.serverId,
    message,
    ...meta,
  };
  return JSON.stringify(payload);
}

const logger = {
  info(message, meta) {
    if (config.env !== 'test') {
      console.log(formatLog('INFO', message, meta));
    }
  },
  warn(message, meta) {
    if (config.env !== 'test') {
      console.warn(formatLog('WARN', message, meta));
    }
  },
  error(message, meta) {
    console.error(formatLog('ERROR', message, meta));
  },
  debug(message, meta) {
    if (config.env === 'development') {
      console.debug(formatLog('DEBUG', message, meta));
    }
  },
};

module.exports = logger;
