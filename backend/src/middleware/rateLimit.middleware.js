const buckets = new Map();

function createRateLimiter({ windowMs = 60000, maxRequests = 120 } = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const key = `${ip}:${req.baseUrl || ''}`;
    const now = Date.now();
    const record = buckets.get(key);

    if (!record || now > record.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    record.count += 1;
    if (record.count > maxRequests) {
      res.setHeader('Retry-After', Math.ceil((record.resetAt - now) / 1000));
      return res.status(429).json({
        error: 'TooManyRequests',
        message: 'Rate limit exceeded. Please wait before sending additional requests.',
      });
    }
    next();
  };
}

module.exports = { createRateLimiter };
