const test = require('node:test');
const assert = require('node:assert/strict');
process.env.NOTIFY_SERVICE_KEY = 'test-notify-service-key';
const axios = require('axios');
const app = require('../src/index');
const config = require('../src/config');
const { dispatch } = require('../src/dispatcher');

const BASE_URL = `http://localhost:${config.PORT}`;
let server;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(config.PORT, resolve);
  });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

const serviceHeaders = { 'X-Service-Key': config.SERVICE_KEY };

async function post(path, body, headers = serviceHeaders) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function get(path, headers = serviceHeaders) {
  const res = await fetch(`${BASE_URL}${path}`, { headers });
  return { status: res.status, body: await res.json() };
}

async function del(path, headers = serviceHeaders) {
  const res = await fetch(`${BASE_URL}${path}`, { method: 'DELETE', headers });
  return { status: res.status };
}


test('GET /health returns ok', async () => {
  const { status, body } = await get('/health');
  assert.equal(status, 200);
  assert.equal(body.status, 'ok');
});

test('POST /webhooks registers a webhook', async () => {
  const { status, body } = await post('/webhooks', {
    url: 'https://example.com/hook',
    events: ['scan.created'],
  });
  assert.equal(status, 201);
  assert.ok(body.id);
  assert.equal(body.url, 'https://example.com/hook');
});


test('webhook management and notification require a service key', async () => {
  const registration = await post('/webhooks', {
    url: 'https://example.com/hook',
    events: ['scan.created'],
  }, {});
  const webhooks = await get('/webhooks', {});
  const deletion = await del('/webhooks/non-existent-id', {});
  const notification = await post('/notify', { event: 'scan.created', payload: {} }, {});
  const invalidKey = await get('/webhooks', { 'X-Service-Key': 'incorrect-key' });

  assert.equal(registration.status, 401);
  assert.equal(webhooks.status, 401);
  assert.equal(deletion.status, 401);
  assert.equal(notification.status, 401);
  assert.equal(invalidKey.status, 401);
});

test('POST /webhooks rejects non-HTTPS and private destinations', async () => {
  const httpTarget = await post('/webhooks', {
    url: 'http://example.com/hook',
    events: ['scan.created'],
  });
  const loopbackTarget = await post('/webhooks', {
    url: 'https://127.0.0.1/hook',
    events: ['scan.created'],
  });
  const metadataTarget = await post('/webhooks', {
    url: 'https://169.254.169.254/latest/meta-data',
    events: ['scan.created'],
  });

  assert.equal(httpTarget.status, 400);
  assert.equal(loopbackTarget.status, 400);
  assert.equal(metadataTarget.status, 400);
});


test('dispatch does not forward the internal service key to webhook recipients', async () => {
  const originalPost = axios.post;
  let request;
  axios.post = async (url, payload, options) => {
    request = { url, payload, options };
  };

  try {
    const result = await dispatch({ id: 'webhook-id', url: 'https://example.com/hook' }, { event: 'scan.created' });
    assert.deepEqual(result, { webhookId: 'webhook-id', success: true, attempt: 1 });
    assert.equal(request.url, 'https://example.com/hook');
    assert.equal(request.options.headers['X-Service-Key'], undefined);
    assert.equal(request.options.maxRedirects, 0);
  } finally {
    axios.post = originalPost;
  }
});

test('POST /webhooks rejects missing url', async () => {
  const { status } = await post('/webhooks', { events: ['scan.created'] });
  assert.equal(status, 400);
});

test('POST /webhooks rejects empty events array', async () => {
  const { status } = await post('/webhooks', { url: 'https://example.com', events: [] });
  assert.equal(status, 400);
});

test('GET /webhooks lists registered webhooks', async () => {
  const { status, body } = await get('/webhooks');
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.webhooks));
});

test('DELETE /webhooks/:id removes a webhook', async () => {
  const { body } = await post('/webhooks', {
    url: 'https://example.com/deleteme',
    events: ['scan.updated'],
  });
  const { status } = await del(`/webhooks/${body.id}`);
  assert.equal(status, 204);
});

test('DELETE /webhooks/:id returns 404 for unknown id', async () => {
  const { status } = await del('/webhooks/non-existent-id');
  assert.equal(status, 404);
});

test('POST /notify requires event and payload', async () => {
  const { status } = await post('/notify', { event: 'scan.created' });
  assert.equal(status, 400);
});
