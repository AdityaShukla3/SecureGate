const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = (route) =>
  createProxyMiddleware({
    target: route.target,
    changeOrigin: true,
    proxyTimeout: 5000,
    timeout: 5000,
    // Strip the gateway prefix: /api/logs/x?y=1 -> /x?y=1
    pathRewrite: (path) => {
      const p = path.replace(route.prefix, '');
      return p.startsWith('/') ? p : '/' + p;
    },
    on: {
      proxyReq: (proxyReq, req) => {
        proxyReq.removeHeader('authorization'); // backend never sees the JWT
        proxyReq.setHeader('x-user-id', req.user.sub); // overrides anything the client sent
        proxyReq.setHeader('x-user-role', req.user.role);
        proxyReq.setHeader('x-gateway-secret', process.env.GATEWAY_SECRET);
      },
      error: (err, req, res) => {
        if (!res.writeHead || res.headersSent) return;
        const down = err.code === 'ECONNREFUSED';
        res.writeHead(down ? 502 : 504, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: down ? 'Upstream service unavailable' : 'Upstream timeout',
          })
        );
      },
    },
  });
