const express = require('express');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const ipaddr = require('ipaddr.js');
const { v4: uuidv4 } = require('uuid');
const { dispatch } = require('./dispatcher');
const config = require('./config');

const app = express();
app.use(express.json());

// In-memory webhook registry
const webhooks = new Map();


function isPublicAddress(address) {
  try {
    return ipaddr.process(address).range() === 'unicast';
  } catch {
    return false;
  }
}


async function validateWebhookUrl(value) {
  let target;
  try {
    target = new URL(value);
  } catch {
    return false;
  }

  if (target.protocol !== 'https:' || target.username || target.password || !target.hostname) {
    return false;
  }

  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname)) {
    return isPublicAddress(hostname);
  }

  try {
    const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
    return addresses.length > 0 && addresses.every(({ address }) => isPublicAddress(address));
  } catch {
    return false;
  }
}


function requireServiceKey(req, res, next) {
  const suppliedKey = req.get('X-Service-Key');
  const expectedKey = Buffer.from(config.SERVICE_KEY);
  const receivedKey = Buffer.from(suppliedKey || '');

  if (receivedKey.length !== expectedKey.length
    || !crypto.timingSafeEqual(receivedKey, expectedKey)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  return next();
}


app.use('/webhooks', requireServiceKey);
app.use('/notify', requireServiceKey);


// Register a webhook endpoint to receive VulnTracker events
app.post('/webhooks', async (req, res) => {
  const { url, events, metadata } = req.body;

  if (!url) return res.status(400).json({ error: 'url is required' });
  if (!await validateWebhookUrl(url)) {
    return res.status(400).json({ error: 'url must be a public HTTPS endpoint' });
  }
  if (!Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ error: 'events must be a non-empty array' });
  }

  const webhook = {
    id: uuidv4(),
    url,
    events,
    metadata: Object.assign({}, metadata),
    createdAt: new Date().toISOString(),
  };

  webhooks.set(webhook.id, webhook);
  res.status(201).json(webhook);
});


// List all registered webhooks
app.get('/webhooks', (req, res) => {
  res.json({ webhooks: Array.from(webhooks.values()), count: webhooks.size });
});


// Delete a webhook registration
app.delete('/webhooks/:id', (req, res) => {
  if (!webhooks.has(req.params.id)) {
    return res.status(404).json({ error: 'Webhook not found' });
  }
  webhooks.delete(req.params.id);
  res.status(204).send();
});


// Trigger event notifications — called by the Python API on scan create/update
// Assumed to be reachable only from internal network; no authentication applied
app.post('/notify', async (req, res) => {
  const { event, payload } = req.body;

  if (!event || !payload) {
    return res.status(400).json({ error: 'event and payload are required' });
  }

  const matching = Array.from(webhooks.values()).filter(w => w.events.includes(event));

  const results = await Promise.all(
    matching.map(w => dispatch(w, { event, payload, timestamp: new Date().toISOString() }))
  );

  res.json({ event, dispatched: matching.length, results });
});


// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vulntracker-notify' });
});


// Global error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message, stack: err.stack });
});


if (require.main === module) {
  app.listen(config.PORT, () => {
    console.log(`Notification service running on http://localhost:${config.PORT}`);
  });
}

module.exports = app;
