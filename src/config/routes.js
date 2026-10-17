// Called after dotenv has loaded. permission maps an HTTP method to the permission needed.
module.exports = [
  {
    prefix: '/api/logs',
    target: process.env.LOGS_URL || 'http://127.0.0.1:4001',
    permission: { GET: 'logs:read' }
  },
  {
    prefix: '/api/inventory',
    target: process.env.INVENTORY_URL || 'http://127.0.0.1:4002',
    permission: {
      GET: 'inventory:read',
      POST: 'inventory:write',
      DELETE: 'inventory:write'
    }
  },
];
