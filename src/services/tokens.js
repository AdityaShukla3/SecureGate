const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const redis = require('../config/redis');

const sign = (user, type, expiresIn) =>
  jwt.sign(
    { sub: user.id, role: user.role, type, jti: randomUUID() },
    process.env.JWT_SECRET,
    { expiresIn }
  );

// Access token: short life. Refresh token: long life, stored in Redis so it can be revoked.
async function issuePair(user) {
  const access = sign(user, 'access', '15m');
  const refresh = sign(user, 'refresh', '7d');
  const { jti } = jwt.decode(refresh);
  await redis.set(`rt:${jti}`, user.id, 'EX', 7 * 24 * 3600);
  return { access, refresh };
}

module.exports = { issuePair };
