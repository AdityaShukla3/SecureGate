const app = require('./app');
const db = require('./config/db');
const redis = require('./config/redis');

(async () => {
  // Rebuild the Redis blocklist from Postgres (the source of truth) on every start.
  try {
    const { rows } = await db.query('SELECT ip FROM blocked_ips');
    for (const r of rows) {
      await redis.set(`blip:${r.ip}`, 'manual');
    }
  } catch (err) {
    console.error('Failed to load blocked IPs from Postgres into Redis:', err.message);
  }

  const port = process.env.PORT || 8080;
  app.listen(port, () => console.log(`SecureGate listening on ${port}`));
})();