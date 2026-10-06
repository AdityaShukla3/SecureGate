// Called after dotenv has loaded. permission maps an HTTP method to the permission needed.
module.exports = [
  {
    prefix: '/api/logs',
    target: process.env.LOGS_URL,
    permission: { GET: 'logs:read' }
  },
  {
    prefix: '/api/inventory',
    target: process.env.INVENTORY_URL,
    permission: {
      GET: 'inventory:read',
      POST: 'inventory:write',
      DELETE: 'inventory:write'
    }
  },
];
