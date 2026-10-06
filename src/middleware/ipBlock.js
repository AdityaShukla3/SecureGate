const redis = require('../config/redis');
const audit = require('../services/audit');

module.exports = async (req, res, next) => {
  try {
    if (await redis.exists(`blip:${req.ip}`)) {
      audit({ ip: req.ip, action: 'blocked_request', status: 'denied' });
      return res.status(403).json({ error: 'IP blocked' });
    }
  } catch (e) {
    console.error('ipBlock: redis unavailable, failing open');
  }
  next();
};
