const { ZodError } = require('zod');

module.exports = (err, req, res, next) => {
  if (err instanceof ZodError) {
    return res.status(400).json({ error: 'Validation failed', details: err.issues });
  }
  if (err.code === '23505') {
    return res.status(409).json({ error: 'Already exists' });
  }
  if (err.status && err.status < 500) return res.status(err.status).json({ error: 'Bad request' });
  console.error(err);
  res.status(500).json({ error: 'Internal error' });
};
