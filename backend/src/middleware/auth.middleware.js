const config = require('../config');
const { query } = require('../database/db');
const { hashSessionToken } = require('../utils/crypto');

function parseCookies(cookieHeader = '') {
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return cookies;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      const key = part.slice(0, idx).trim();
      const val = decodeURIComponent(part.slice(idx + 1).trim());
      cookies[key] = val;
    }
  }
  return cookies;
}

async function attachSession(req, res, next) {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const rawToken = cookies[config.security.sessionCookieName];
    if (!rawToken) {
      req.user = null;
      return next();
    }

    const tokenHash = hashSessionToken(rawToken);
    const resDb = await query(
      `SELECT s.token_hash, s.csrf_token, s.expires_at,
              u.id AS user_id, u.username, u.email, u.is_active,
              r.name AS role
       FROM user_sessions s
       JOIN users u ON u.id = s.user_id
       JOIN roles r ON r.id = u.role_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
      [tokenHash]
    );

    if (resDb.rows.length === 0 || !resDb.rows[0].is_active) {
      req.user = null;
      return next();
    }

    const row = resDb.rows[0];
    req.user = {
      id: row.user_id,
      username: row.username,
      email: row.email,
      role: row.role,
    };
    req.session = {
      tokenHash: row.token_hash,
      csrfToken: row.csrf_token,
      expiresAt: row.expires_at,
    };
    next();
  } catch (err) {
    req.user = null;
    next();
  }
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required. Please log in.',
    });
  }
  next();
}

function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required.',
      });
    }
    if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Insufficient permissions. Required role: ${allowedRoles.join(' or ')}.`,
      });
    }
    next();
  };
}

function verifyCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  if (!req.session) {
    return next();
  }
  const clientToken = req.headers['x-csrf-token'];
  if (!clientToken || clientToken !== req.session.csrfToken) {
    return res.status(403).json({
      error: 'CSRFValidationFailed',
      message: 'Invalid or missing CSRF token header (X-CSRF-Token).',
    });
  }
  next();
}

module.exports = {
  parseCookies,
  attachSession,
  requireAuth,
  requireRole,
  verifyCsrf,
};
