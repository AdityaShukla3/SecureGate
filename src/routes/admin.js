const router = require('express').Router();
const net = require('net');
const { z } = require('zod');
const db = require('../config/db');
const redis = require('../config/redis');
const audit = require('../services/audit');
const requirePermission = require('../middleware/rbac');

const ipSchema = z.object({
  ip: z.string().refine((v) => net.isIP(v), 'Invalid IP'),
  reason: z.string().max(200).optional(),
});

router.post('/ips/block', requirePermission('ips:manage'), async (req, res) => {
  const { ip, reason } = ipSchema.parse(req.body);
  await db.query(
    'INSERT INTO blocked_ips(ip, reason) VALUES($1,$2) ON CONFLICT DO NOTHING',
    [ip, reason]
  );
  await redis.set(`blip:${ip}`, 'manual');
  audit({
    userId: req.user.sub,
    ip: req.ip,
    action: 'ip_block',
    status: 'success',
    meta: { target: ip, reason },
  });
  res.status(201).json({ blocked: ip });
});

router.delete('/ips/:ip', requirePermission('ips:manage'), async (req, res) => {
  await db.query('DELETE FROM blocked_ips WHERE ip=$1', [req.params.ip]);
  await redis.del(`blip:${req.params.ip}`);
  audit({
    userId: req.user.sub,
    ip: req.ip,
    action: 'ip_unblock',
    status: 'success',
    meta: { target: req.params.ip },
  });
  res.json({ unblocked: req.params.ip });
});

router.patch('/users/:id/role', requirePermission('users:manage'), async (req, res) => {
  const { role } = z.object({ role: z.enum(['viewer', 'analyst', 'admin']) }).parse(req.body);
  const r = await db.query(
    'UPDATE users SET role_id=(SELECT id FROM roles WHERE name=$1) WHERE id=$2 RETURNING id',
    [role, req.params.id]
  );
  if (!r.rowCount) return res.status(404).json({ error: 'User not found' });
  audit({
    userId: req.user.sub,
    ip: req.ip,
    action: 'role_change',
    status: 'success',
    meta: { target: Number(req.params.id), role },
  });
  res.json({ id: r.rows[0].id, role });
});

router.get('/audit', requirePermission('audit:read'), async (req, res) => {
  const { action, status, limit = 50 } = req.query;
  const { rows } = await db.query(
    `SELECT * FROM audit_logs
     WHERE ($1::text IS NULL OR action = $1) AND ($2::text IS NULL OR status = $2)
     ORDER BY created_at DESC LIMIT $3`,
    [action || null, status || null, Math.min(Number(limit) || 50, 200)]
  );
  res.json(rows);
});

module.exports = router;
