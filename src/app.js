require('dotenv').config({ quiet: true });
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const db = require('./config/db');
const redis = require('./config/redis');
const routes = require('./config/routes');
const ipBlock = require('./middleware/ipBlock');
const rateLimit = require('./middleware/rateLimit');
const auth = require('./middleware/auth');
const requirePermission = require('./middleware/rbac');
const makeProxy = require('./middleware/proxy');
const errorHandler = require('./middleware/errorHandler');

const app = express();

// Only trust X-Forwarded-For when really behind Nginx/a platform proxy, or clients can fake their IP.
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY));

app.use(helmet(), cors());

app.use(ipBlock);

app.get('/health', async (req, res) => {
  const s = { db: 'down', redis: 'down' };
  try {
    await db.query('SELECT 1');
    s.db = 'up';
  } catch {}
  try {
    await redis.ping();
    s.redis = 'up';
  } catch {}
  res.status(Object.values(s).every((v) => v === 'up') ? 200 : 503).json(s);
});

app.use(rateLimit({ limit: Number(process.env.RATE_LIMIT) || 100 }));

// express.json() only on gateway-owned routes: parsing the body here would consume it
// and break proxying of POST requests to the backends.
app.use('/auth', express.json(), rateLimit({ limit: 10, name: 'auth' }), require('./routes/auth'));
app.use('/admin', express.json(), auth, require('./routes/admin'));

// One entry per protected service: auth -> RBAC -> proxy.
for (const route of routes) {
  app.use(
    route.prefix,
    auth,
    requirePermission((req) => route.permission[req.method]),
    makeProxy(route)
  );
}

app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use(errorHandler);

module.exports = app;
