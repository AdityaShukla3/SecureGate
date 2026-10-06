const redis = require('../config/redis');

module.exports = ({ limit = 100, windowMs = 60000, name = 'global' } = {}) =>
  async (req, res, next) => {
    try {
      const now = Date.now();
      const allowed = await redis.slidingWindow(
        `rl:${name}:${req.ip}`,
        now,
        windowMs,
        limit,
        `${now}-${Math.random()}`
      );
      if (!allowed) {
        res.set('Retry-After', Math.ceil(windowMs / 1000));
        return res.status(429).json({ error: 'Too many requests' });
      }
    } catch (e) {
      console.error('rate limiter: redis unavailable, failing open');
    }
    next();
  };
