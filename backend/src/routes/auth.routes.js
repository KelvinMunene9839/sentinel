const express = require('express');
const config = require('../config');
const { query } = require('../database/db');
const {
  verifyPassword,
  generateSessionToken,
  hashSessionToken,
} = require('../utils/crypto');
const { recordAuditLog } = require('../utils/audit');
const { requireAuth, verifyCsrf } = require('../middleware/auth.middleware');
const { createRateLimiter } = require('../middleware/rateLimit.middleware');

const router = express.Router();
const loginLimiter = createRateLimiter({ windowMs: 60000, maxRequests: 25 });

// POST /api/v1/auth/login
router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({
        error: 'ValidationError',
        message: 'Username and password are required.',
      });
    }

    const userRes = await query(
      `SELECT u.id, u.username, u.email, u.password_hash, u.is_active, r.name AS role
       FROM users u
       JOIN roles r ON r.id = u.role_id
       WHERE LOWER(u.username) = LOWER($1)`,
      [String(username).trim()]
    );

    if (userRes.rows.length === 0 || !verifyPassword(password, userRes.rows[0].password_hash)) {
      await recordAuditLog({
        username: String(username).trim(),
        action: 'AUTH_LOGIN_FAILED',
        ipAddress: req.ip,
      });
      return res.status(401).json({
        error: 'InvalidCredentials',
        message: 'Invalid username or password.',
      });
    }

    const user = userRes.rows[0];
    if (!user.is_active) {
      return res.status(403).json({
        error: 'AccountDisabled',
        message: 'User account is disabled.',
      });
    }

    const rawToken = generateSessionToken();
    const tokenHash = hashSessionToken(rawToken);
    const csrfToken = generateSessionToken();
    const ttlMs = config.security.sessionTtlHours * 3600 * 1000;
    const expiresAt = new Date(Date.now() + ttlMs).toISOString();

    await query(
      `INSERT INTO user_sessions (token_hash, user_id, csrf_token, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [tokenHash, user.id, csrfToken, req.ip, req.headers['user-agent'] || '', expiresAt]
    );

    await query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);

    const cookieFlags = [
      `${config.security.sessionCookieName}=${encodeURIComponent(rawToken)}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${config.security.sessionTtlHours * 3600}`,
    ];
    if (config.env === 'production') {
      cookieFlags.push('Secure');
    }
    res.setHeader('Set-Cookie', cookieFlags.join('; '));

    await recordAuditLog({
      userId: user.id,
      username: user.username,
      action: 'AUTH_LOGIN_SUCCESS',
      ipAddress: req.ip,
    });

    res.status(200).json({
      status: 'authenticated',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
      csrfToken,
      expiresAt,
      serverId: config.serverId,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/v1/auth/logout
router.post('/logout', requireAuth, verifyCsrf, async (req, res, next) => {
  try {
    if (req.session && req.session.tokenHash) {
      await query('DELETE FROM user_sessions WHERE token_hash = $1', [req.session.tokenHash]);
    }
    res.setHeader(
      'Set-Cookie',
      `${config.security.sessionCookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`
    );

    await recordAuditLog({
      userId: req.user.id,
      username: req.user.username,
      action: 'AUTH_LOGOUT',
      ipAddress: req.ip,
    });

    res.status(200).json({ status: 'logged_out' });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/auth/me
router.get('/me', async (req, res) => {
  if (!req.user) {
    return res.status(200).json({
      authenticated: false,
      user: null,
      serverId: config.serverId,
    });
  }
  res.status(200).json({
    authenticated: true,
    user: req.user,
    csrfToken: req.session ? req.session.csrfToken : null,
    serverId: config.serverId,
  });
});

module.exports = router;
