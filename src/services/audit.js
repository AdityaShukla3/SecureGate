const db = require('../config/db');

// Audit logging must never break a request, so errors are swallowed and logged.
module.exports = async function audit({ userId = null, ip = null, action, status, meta = {} }) {
  try {
    await db.query(
      'INSERT INTO audit_logs(user_id, ip, action, status, meta) VALUES($1,$2,$3,$4,$5)',
      [userId, ip, action, status, meta]
    );
  } catch (e) {
    console.error('audit failed:', e.message);
  }
};
