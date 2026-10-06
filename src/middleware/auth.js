const jwt = require('jsonwebtoken');
const redis = require('../config/redis');

module.exports = async (req, res, next) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (payload.type !== 'access') return res.status(401).json({ error: 'Wrong token type' });

  try {
    if (await redis.exists(`bl:${payload.jti}`)) {
      return res.status(401).json({ error: 'Token revoked' });
    }
  } catch (e) {
    // Cannot verify revocation: fail CLOSED, security matters more than availability here.
    return res.status(503).json({ error: 'Auth backend unavailable' });
  }

  req.user = payload;
  next();
};