const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: 2,
});
redis.on('error', (e) => console.error('redis error:', e.message));

// Sliding-window rate limit, executed atomically inside Redis.
// Returns 1 if the request is allowed, 0 if the limit is reached.
redis.defineCommand('slidingWindow', {
  numberOfKeys: 1,
  lua: `
    local key, now, window, limit, id =
      KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), ARGV[4]
    redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
    if redis.call('ZCARD', key) >= limit then return 0 end
    redis.call('ZADD', key, now, id)
    redis.call('PEXPIRE', key, window)
    return 1`,
});

module.exports = redis;