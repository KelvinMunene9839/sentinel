const { query } = require('../database/db');
const config = require('../config');

async function recordAuditLog({
  userId = null,
  username = 'anonymous',
  action,
  resourceType = null,
  resourceId = null,
  details = {},
  ipAddress = null,
}) {
  try {
    await query(
      `INSERT INTO audit_logs (user_id, username, action, resource_type, resource_id, details_json, ip_address, server_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        userId,
        username,
        action,
        resourceType,
        resourceId,
        JSON.stringify(details || {}),
        ipAddress,
        config.serverId,
      ]
    );
  } catch (err) {
    // Non-fatal logging fallback
  }
}

module.exports = { recordAuditLog };
