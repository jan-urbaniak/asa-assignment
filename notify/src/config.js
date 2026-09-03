const serviceKey = process.env.NOTIFY_SERVICE_KEY;

if (!serviceKey) {
  throw new Error('NOTIFY_SERVICE_KEY must be set');
}

module.exports = {
  PORT: process.env.PORT || 3001,
  PYTHON_API_URL: process.env.PYTHON_API_URL || 'http://localhost:8000',

  SERVICE_KEY: serviceKey,

  RETRY_ATTEMPTS: 3,
  TIMEOUT_MS: 5000,
};
