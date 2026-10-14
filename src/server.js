const app = require('./app');
const db = require('./config/db');
const redis = require('./config/redis');
const initDb = require('./db/init');

(async () => {
  // Guarantee database schema and seeds are initialized on startup
  try {
    await initDb();
  } catch (err) {
    console.warn('Initial schema setup notice:', err.message);
  }

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
  const server = app.listen(port, () => console.log(`SecureGate listening on ${port}`));

  const shutdown = (signal) => {
    console.log(`Received ${signal}. Shutting down gracefully...`);
    server.close(async () => {
      try {
        await redis.quit();
        await db.end();
      } catch {}
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
})();