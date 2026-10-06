const db = require('../config/db');
const redis = require('../config/redis');
const audit = require('../services/audit');

// Role -> permissions, cached in Redis for 5 minutes.
async function permsFor(role) {
  const key = `perms:${role}`;
  let perms = await redis.smembers(key);
  if (!perms.length) {
    const { rows } = await db.query(
      `SELECT p.name FROM permissions p
       JOIN role_permissions rp ON rp.permission_id = p.id
       JOIN roles r ON r.id = rp.role_id WHERE r.name = $1`,
      [role]
    );
    perms = rows.map((r) => r.name);
    if (perms.length) {
      await redis.sadd(key, ...perms);
      await redis.expire(key, 300);
    }
  }
  return perms;
}

// perm can be a string, or a function(req) that returns the permission for this request.
module.exports = (perm) => async (req, res, next) => {
  const needed = typeof perm === 'function' ? perm(req) : perm;
  const allowed = needed && (await permsFor(req.user.role)).includes(needed);
  if (!allowed) {
    audit({
      userId: req.user.sub,
      ip: req.ip,
      action: 'access_denied',
      status: 'denied',
      meta: { method: req.method, path: req.originalUrl, needed },
    });
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};
