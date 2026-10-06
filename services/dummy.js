// A deliberately insecure-looking backend: it has NO auth code. The only protection is that
// it rejects any request that did not come through the gateway (shared secret header).
require('dotenv').config({ quiet: true });
const express = require('express');

const name = process.argv[2];
const port = Number(process.argv[3]) || Number(process.env.PORT);
const app = express();

app.use((req, res, next) => {
  if (req.headers['x-gateway-secret'] !== process.env.GATEWAY_SECRET) {
    return res.status(403).json({ error: 'Direct access not allowed' });
  }
  next();
});

app.use((req, res) =>
  res.json({
    service: name,
    method: req.method,
    path: req.url,
    calledBy: { id: req.headers['x-user-id'], role: req.headers['x-user-role'] },
    data: [{ id: 1, name: `${name}-item-1` }, { id: 2, name: `${name}-item-2` }],
  })
);

app.listen(port, () => console.log(`${name} service on ${port}`));
