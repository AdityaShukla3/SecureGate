process.env.TRUST_PROXY = '1';
// Point the gateway at a tiny fake backend (port 4999) and a dead one (port 4998) for these tests.
process.env.INVENTORY_URL = 'http://127.0.0.1:4999';
process.env.LOGS_URL = 'http://127.0.0.1:4998';
const http = require('http');
const request = require('supertest');
const app = require('../src/app');
const redis = require('../src/config/redis');
const db = require('../src/config/db');

const email = `user${Date.now()}@test.dev`;
const pw = 'Passw0rd!';
const login = (e, p, ip) =>
  request(app).post('/auth/login').set('X-Forwarded-For', ip).send({ email: e, password: p });

let viewerToken;
let viewerRefreshToken;

beforeAll(async () => {
  await request(app)
    .post('/auth/register')
    .set('X-Forwarded-For', '10.0.0.1')
    .send({ email, password: pw });

  const loginRes = await login(email, pw, '10.0.0.1');
  viewerToken = loginRes.body.access;
  viewerRefreshToken = loginRes.body.refresh;
});

let fakeBackend;
beforeAll((done) => {
  fakeBackend = http
    .createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          path: req.url,
          userId: req.headers['x-user-id'],
          role: req.headers['x-user-role'],
          sawToken: Boolean(req.headers.authorization),
        })
      );
    })
    .listen(4999, done);
});

afterAll(async () => {
  await new Promise((r) => fakeBackend.close(r));
  await redis.quit();
  await db.end();
});

test('no token gets 401', async () => {
  const r = await request(app).get('/api/inventory').set('X-Forwarded-For', '10.0.0.2');
  expect(r.status).toBe(401);
});

test('viewer lacks logs:read, gets 403 before reaching the service', async () => {
  const r = await request(app)
    .get('/api/logs')
    .set('X-Forwarded-For', '10.0.0.3')
    .set('Authorization', `Bearer ${viewerToken}`);
  expect(r.status).toBe(403);
});

test('viewer cannot read the audit log', async () => {
  const r = await request(app)
    .get('/admin/audit')
    .set('X-Forwarded-For', '10.0.0.4')
    .set('Authorization', `Bearer ${viewerToken}`);
  expect(r.status).toBe(403);
});

test('account locks after 5 failed logins', async () => {
  const e = `lock${Date.now()}@test.dev`;
  await request(app)
    .post('/auth/register')
    .set('X-Forwarded-For', '10.0.0.5')
    .send({ email: e, password: pw });
  for (let i = 0; i < 5; i++) await login(e, 'wrong-password', '10.0.0.5');
  const r = await login(e, pw, '10.0.0.5'); // correct password, still locked
  expect(r.status).toBe(429);
});

test('blocked IP gets 403', async () => {
  await redis.set('blip:9.9.9.9', 'manual');
  const r = await request(app).get('/health').set('X-Forwarded-For', '9.9.9.9');
  expect(r.status).toBe(403);
  await redis.del('blip:9.9.9.9');
});

test('rate limiter returns 429 after the limit', async () => {
  let last;
  for (let i = 0; i < 11; i++) last = await login('x@y.dev', 'whatever12', '10.0.0.6');
  expect(last.status).toBe(429); // /auth limit is 10 per minute
});

test('logout revokes the access token', async () => {
  const t = (await login(email, pw, '10.0.0.7')).body.access;
  await request(app)
    .post('/auth/logout')
    .set('X-Forwarded-For', '10.0.0.7')
    .set('Authorization', `Bearer ${t}`)
    .send({});
  const r = await request(app)
    .get('/admin/audit')
    .set('X-Forwarded-For', '10.0.0.7')
    .set('Authorization', `Bearer ${t}`);
  expect(r.status).toBe(401);
});

test('wrong-token-type (refresh used as access) is rejected', async () => {
  const r = await request(app)
    .get('/api/inventory')
    .set('X-Forwarded-For', '10.0.0.8')
    .set('Authorization', `Bearer ${viewerRefreshToken}`);
  expect(r.status).toBe(401);
  expect(r.body.error).toBe('Wrong token type');
});

test('refresh token works only once (rotation enforcement)', async () => {
  const initial = await login(email, pw, '10.0.0.9');
  const firstUse = await request(app)
    .post('/auth/refresh')
    .set('X-Forwarded-For', '10.0.0.9')
    .send({ refreshToken: initial.body.refresh });
  expect(firstUse.status).toBe(200);
  expect(firstUse.body).toHaveProperty('access');

  // Second use of the same refresh token must fail
  const secondUse = await request(app)
    .post('/auth/refresh')
    .set('X-Forwarded-For', '10.0.0.9')
    .send({ refreshToken: initial.body.refresh });
  expect(secondUse.status).toBe(401);
  expect(secondUse.body.error).toBe('Refresh token revoked');
});

test('admin can block an IP and that IP is subsequently blocked', async () => {
  const adminLogin = await login('admin@securegate.dev', 'Admin@12345', '10.0.0.10');
  const adminToken = adminLogin.body.access;

  const targetIp = '198.51.100.42';
  const blockRes = await request(app)
    .post('/admin/ips/block')
    .set('X-Forwarded-For', '10.0.0.10')
    .set('Authorization', `Bearer ${adminToken}`)
    .send({ ip: targetIp, reason: 'malicious activity' });
  expect(blockRes.status).toBe(201);

  const blockedReq = await request(app)
    .get('/health')
    .set('X-Forwarded-For', targetIp);
  expect(blockedReq.status).toBe(403);

  // Clean up
  await request(app)
    .delete(`/admin/ips/${targetIp}`)
    .set('X-Forwarded-For', '10.0.0.10')
    .set('Authorization', `Bearer ${adminToken}`);
});

test('proxy forwards the request, fixes the path, and overwrites fake identity headers', async () => {
  const adminToken = (await login('admin@securegate.dev', 'Admin@12345', '10.0.0.20')).body.access;
  const r = await request(app)
    .get('/api/inventory/items/5?x=1')
    .set('X-Forwarded-For', '10.0.0.20')
    .set('Authorization', `Bearer ${adminToken}`)
    .set('x-user-role', 'viewer'); // client tries to lie about its role
  expect(r.status).toBe(200);
  expect(r.body.path).toBe('/items/5?x=1'); // prefix /api/inventory removed
  expect(r.body.role).toBe('admin'); // gateway's value, not the fake one
  expect(r.body.sawToken).toBe(false); // backend never sees the JWT
});

test('gateway returns 502 when the backend is down', async () => {
  const adminToken = (await login('admin@securegate.dev', 'Admin@12345', '10.0.0.21')).body.access;
  const r = await request(app)
    .get('/api/logs') // LOGS_URL points to a port with nothing running
    .set('X-Forwarded-For', '10.0.0.21')
    .set('Authorization', `Bearer ${adminToken}`);
  expect(r.status).toBe(502);
});

test('one IP failing logins for 10 different accounts gets auto-blocked', async () => {
  for (let i = 0; i < 10; i++) {
    await login(`victim${i}-${Date.now()}@x.dev`, 'wrongpass1', '10.0.0.30');
  }
  const r = await request(app).get('/health').set('X-Forwarded-For', '10.0.0.30');
  expect(r.status).toBe(403);
  await redis.del('blip:10.0.0.30'); // clean up
});

test('admin can change a role and it appears in the audit log', async () => {
  const reg = await request(app)
    .post('/auth/register')
    .set('X-Forwarded-For', '10.0.0.40')
    .send({ email: `promote${Date.now()}@test.dev`, password: pw });
  const adminToken = (await login('admin@securegate.dev', 'Admin@12345', '10.0.0.41')).body.access;
  const r = await request(app)
    .patch(`/admin/users/${reg.body.id}/role`)
    .set('X-Forwarded-For', '10.0.0.41')
    .set('Authorization', `Bearer ${adminToken}`)
    .send({ role: 'analyst' });
  expect(r.status).toBe(200);
  const audit = await request(app)
    .get('/admin/audit?action=role_change')
    .set('X-Forwarded-For', '10.0.0.41')
    .set('Authorization', `Bearer ${adminToken}`);
  expect(audit.body.length).toBeGreaterThan(0);
});

test('logout with no body does not crash, and bad JSON gives 400', async () => {
  const t = (await login(email, pw, '10.0.0.50')).body.access;
  const out = await request(app)
    .post('/auth/logout')
    .set('X-Forwarded-For', '10.0.0.50')
    .set('Authorization', `Bearer ${t}`);
  expect(out.status).toBe(200);
  const bad = await request(app)
    .post('/auth/login')
    .set('X-Forwarded-For', '10.0.0.51')
    .set('Content-Type', 'application/json')
    .send('{bad');
  expect(bad.status).toBe(400);
});
