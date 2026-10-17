const app = require('./app');
const db = require('./config/db');
const redis = require('./config/redis');
const initDb = require('./db/init');
const { startDummyService } = require('../services/dummy');

function parsePortFromUrl(urlStr, defaultPort) {
  try {
    const parsed = new URL(urlStr);
    const port = Number(parsed.port) || defaultPort;
    const isLocal = ['localhost', '127.0.0.1', '0.0.0.0'].includes(parsed.hostname);
    return { port, isLocal };
  } catch {
    return { port: defaultPort, isLocal: true };
  }
}

(async () => {
  // Automatically launch upstream mock microservices (inventory & logs)
  // for all-in-one / cloud deployments (Render, standalone container, dev)
  const dummyServers = [];
  if (process.env.NODE_ENV !== 'test' && process.env.START_INTERNAL_SERVICES !== 'false') {
    const logsInfo = parsePortFromUrl(process.env.LOGS_URL || 'http://127.0.0.1:4001', 4001);
    if (logsInfo.isLocal) {
      dummyServers.push(startDummyService('logs', logsInfo.port));
    }

    const invInfo = parsePortFromUrl(process.env.INVENTORY_URL || 'http://127.0.0.1:4002', 4002);
    if (invInfo.isLocal) {
      dummyServers.push(startDummyService('inventory', invInfo.port));
    }
  }

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
    for (const s of dummyServers) {
      try {
        s.close();
      } catch {}
    }
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