// A deliberately insecure-looking backend: it has NO auth code. The only protection is that
// it rejects any request that did not come through the gateway (shared secret header).
require('dotenv').config({ quiet: true });
const express = require('express');

function createDummyService(name) {
  const app = express();
  app.use(express.json());

  app.use((req, res, next) => {
    const expectedSecret = process.env.GATEWAY_SECRET;
    if (expectedSecret && req.headers['x-gateway-secret'] !== expectedSecret) {
      return res.status(403).json({ error: 'Direct access not allowed' });
    }
    next();
  });

  const inventoryItems = [
    { id: 1, item: 'Quantum Encryption Module', category: 'Hardware', stock: 42, status: 'Active' },
    { id: 2, item: 'Neural Firewall Chipset', category: 'Hardware', stock: 18, status: 'Active' },
    { id: 3, item: 'Zero-Trust Protocol Suite', category: 'Software', stock: 150, status: 'Deployed' },
    { id: 4, item: 'Biometric Gateway Sensor', category: 'Perimeter', stock: 27, status: 'Maintenance' },
    { id: 5, item: 'Cyber-Sensor-X1', category: 'Telemetry', stock: 85, status: 'Active' },
  ];

  const logItems = [
    { id: 1, event: 'SEC_EDGE_ALLOW', source: 'Gateway-Proxy', timestamp: new Date().toISOString() },
    { id: 2, event: 'TLS_HANDSHAKE_ESTABLISHED', source: 'Core-Router', timestamp: new Date().toISOString() },
    { id: 3, event: 'RBAC_EVALUATION_PASS', source: 'Policy-Engine', timestamp: new Date().toISOString() },
  ];

  app.use((req, res) => {
    const isInv = name === 'inventory';
    const store = isInv ? inventoryItems : logItems;

    if (req.method === 'POST') {
      const payload = req.body && Object.keys(req.body).length ? req.body : { item: 'New-Item' };
      const newItem = { id: store.length + 1, ...payload, created_at: new Date().toISOString() };
      store.push(newItem);
      return res.status(201).json({
        service: name,
        method: req.method,
        path: req.url,
        calledBy: { id: req.headers['x-user-id'], role: req.headers['x-user-role'] },
        created: newItem,
        data: store,
      });
    }

    res.json({
      service: name,
      method: req.method,
      path: req.url,
      calledBy: { id: req.headers['x-user-id'], role: req.headers['x-user-role'] },
      data: store,
    });
  });

  return app;
}

function startDummyService(name, port) {
  const app = createDummyService(name);
  const server = app.listen(port, '0.0.0.0', () => {
    console.log(`[Upstream Mock] ${name} service listening on 0.0.0.0:${port}`);
  });
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`[Upstream Mock] Port ${port} is already in use; using existing ${name} service.`);
    } else {
      console.warn(`[Upstream Mock] Warning starting ${name} service:`, err.message);
    }
  });
  return server;
}

if (require.main === module) {
  const name = process.argv[2] || 'inventory';
  const port = Number(process.argv[3]) || Number(process.env.PORT) || 4002;
  startDummyService(name, port);
}

module.exports = { createDummyService, startDummyService };

