require('dotenv').config();
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const db = require('../config/db');

const roles = {
  viewer: ['inventory:read'],
  analyst: ['inventory:read', 'logs:read', 'audit:read'],
  admin: [
    'inventory:read',
    'inventory:write',
    'logs:read',
    'audit:read',
    'users:manage',
    'ips:manage'
  ]
};

(async () => {
  try {
    await db.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));

    for (const p of new Set(Object.values(roles).flat())) {
      await db.query('INSERT INTO permissions(name) VALUES($1) ON CONFLICT DO NOTHING', [p]);
    }

    for (const [role, perms] of Object.entries(roles)) {
      await db.query('INSERT INTO roles(name) VALUES($1) ON CONFLICT DO NOTHING', [role]);
      for (const p of perms) {
        await db.query(
          `INSERT INTO role_permissions(role_id, permission_id)
           SELECT r.id, p.id FROM roles r, permissions p
           WHERE r.name=$1 AND p.name=$2 ON CONFLICT DO NOTHING`,
          [role, p]
        );
      }
    }

    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'Admin@12345', 10);
    await db.query(
      `INSERT INTO users(email, password_hash, role_id)
       SELECT 'admin@securegate.dev', $1, id FROM roles WHERE name='admin'
       ON CONFLICT DO NOTHING`,
      [hash]
    );

    console.log('database ready');
    process.exit(0);
  } catch (err) {
    console.error('database init failed:', err);
    process.exit(1);
  }
})();