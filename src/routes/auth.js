const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const db = require('../config/db');
const redis = require('../config/redis');
const audit = require('../services/audit');
const auth = require('../middleware/auth');
const { issuePair } = require('../services/tokens');

const creds = z.object({ email: z.string().email(), password: z.string().min(8) });

router.post('/register', async (req, res) => {
  const { email, password } = creds.parse(req.body);
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await db.query(
    `INSERT INTO users(email, password_hash, role_id)
     SELECT $1, $2, id FROM roles WHERE name='viewer' RETURNING id`,
    [email, hash]
  );
  audit({ userId: rows[0].id, ip: req.ip, action: 'register', status: 'success' });
  res.status(201).json({ id: rows[0].id, email, role: 'viewer' });
});

router.post('/login', async (req, res) => {
  const { email, password } = creds.parse(req.body);
  if (await redis.exists(`lock:${email}`)) {
    audit({ ip: req.ip, action: 'login', status: 'locked', meta: { email } });
    return res.status(429).json({ error: 'Account temporarily locked' });
  }

  const { rows } = await db.query(
    `SELECT u.id, u.password_hash, r.name AS role FROM users u
     JOIN roles r ON r.id = u.role_id WHERE u.email = $1`,
    [email]
  );
  const user = rows[0];
  const ok = user && (await bcrypt.compare(password, user.password_hash));

  if (!ok) {
    const fails = await redis.incr(`fail:${email}`);
    if (fails === 1) await redis.expire(`fail:${email}`, 900);
    if (fails >= 5) await redis.set(`lock:${email}`, 1, 'EX', 900);

    // Credential stuffing: one IP failing against many different accounts.
    await redis.sadd(`stuff:${req.ip}`, email);
    await redis.expire(`stuff:${req.ip}`, 600);
    if ((await redis.scard(`stuff:${req.ip}`)) >= 10) {
      await redis.set(`blip:${req.ip}`, 'auto', 'EX', 3600);
      audit({
        ip: req.ip,
        action: 'auto_block',
        status: 'denied',
        meta: { reason: 'credential stuffing' },
      });
    }

    audit({ ip: req.ip, action: 'login', status: 'failed', meta: { email } });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  await redis.del(`fail:${email}`);
  audit({ userId: user.id, ip: req.ip, action: 'login', status: 'success' });
  res.json(await issuePair(user));
});

// Refresh-token rotation: each refresh token can be used exactly once.
router.post('/refresh', async (req, res) => {
  let p;
  try {
    p = jwt.verify(req.body?.refreshToken, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  if (p.type !== 'refresh' || !(await redis.get(`rt:${p.jti}`))) {
    return res.status(401).json({ error: 'Refresh token revoked' });
  }

  await redis.del(`rt:${p.jti}`);
  res.json(await issuePair({ id: p.sub, role: p.role }));
});

router.post('/logout', auth, async (req, res) => {
  const ttl = req.user.exp - Math.floor(Date.now() / 1000); // time left on the token
  if (ttl > 0) await redis.set(`bl:${req.user.jti}`, 1, 'EX', ttl);
  const r = req.body?.refreshToken && jwt.decode(req.body.refreshToken);
  if (r && r.jti) await redis.del(`rt:${r.jti}`);
  audit({ userId: req.user.sub, ip: req.ip, action: 'logout', status: 'success' });
  res.json({ ok: true });
});

module.exports = router;