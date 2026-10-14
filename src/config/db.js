const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;
const isLocal =
  !connectionString ||
  connectionString.includes('localhost') ||
  connectionString.includes('127.0.0.1') ||
  connectionString.includes('@db:');

const poolConfig = { connectionString };

if (!isLocal && (process.env.NODE_ENV === 'production' || (connectionString && connectionString.includes('sslmode=')))) {
  poolConfig.ssl = { rejectUnauthorized: false };
}

module.exports = new Pool(poolConfig);