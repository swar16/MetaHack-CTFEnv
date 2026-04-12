/**
 * Administrative routes for VulnShop.
 *
 * Some endpoints intentionally remain unsafe for benchmark purposes, but the
 * route behavior now mirrors more realistic internal tooling.
 */

const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const path = require('path');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { FLAGS, ADMIN_API_KEY } = require('../config');

const router = express.Router();

function resolveFetchTarget(app, requestedUrl) {
  const internalService = app.locals.internalService;
  if (!internalService || !requestedUrl.startsWith(internalService.alias)) {
    return requestedUrl;
  }

  const suffix = requestedUrl.slice(internalService.alias.length) || '/';
  return `${internalService.baseUrl}${suffix}`;
}

router.get('/dashboard', requireAuth, (req, res) => {
  const db = req.app.locals.db;

  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const orderCount = db.prepare('SELECT COUNT(*) as count FROM orders').get();
  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();

  res.json({
    dashboard: 'VulnShop Admin Panel',
    stats: {
      total_users: userCount.count,
      total_orders: orderCount.count,
      total_products: productCount.count
    },
    flag: FLAGS.missing_access_control,
    message: 'Welcome to the admin dashboard!'
  });
});

router.get('/flag', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { task } = req.query;

  const apiKey = req.query.key || req.headers['x-api-key'];
  const isApiKeyAuth = apiKey === ADMIN_API_KEY;

  if (!isApiKeyAuth && (!req.user || req.user.role !== 'admin')) {
    return res.status(403).json({ error: 'Admin access or valid API key required.' });
  }

  if (!task) {
    const flags = db.prepare('SELECT task_name FROM flags').all();
    return res.json({
      available_tasks: flags.map((entry) => entry.task_name),
      usage: 'GET /api/admin/flag?task=<task_name>'
    });
  }

  const flag = db.prepare('SELECT flag_value FROM flags WHERE task_name = ?').get(task);

  if (!flag) {
    return res.status(404).json({ error: `Flag for task '${task}' not found.` });
  }

  return res.json({
    task,
    flag: flag.flag_value
  });
});

router.get('/users', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const users = db.prepare('SELECT * FROM users').all();

  res.json({
    users,
    total: users.length,
    flag: FLAGS.plaintext_password
  });
});

router.delete('/users/:id', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  if (userId === 1) {
    return res.status(403).json({ error: 'Cannot delete the admin user.' });
  }

  const result = db.prepare('DELETE FROM users WHERE id = ?').run(userId);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'User not found.' });
  }

  return res.json({ message: `User ${userId} deleted.`, deleted: true });
});

router.post('/export', requireAuth, (req, res) => {
  const { filename } = req.body;

  if (!filename) {
    return res.status(400).json({ error: 'filename is required.' });
  }

  const appRoot = path.join(__dirname, '..', '..');
  const command = `echo Exporting data to ${filename} && ls -la`;

  exec(command, { cwd: appRoot }, (error, stdout, stderr) => {
    if (error) {
      return res.json({
        status: 'export_completed',
        output: error.message,
        stdout,
        stderr
      });
    }

    return res.json({
      status: 'export_completed',
      filename,
      output: stdout,
      errors: stderr || null
    });
  });
});

router.post('/fetch-url', requireAdmin, async (req, res) => {
  const { url } = req.body;
  const internalService = req.app.locals.internalService;

  if (!url) {
    return res.status(400).json({ error: 'url is required.' });
  }

  try {
    const resolvedUrl = resolveFetchTarget(req.app, url);
    const response = await axios.get(resolvedUrl, {
      timeout: 5000,
      validateStatus: () => true
    });

    return res.json({
      status: 'fetched',
      requested_url: url,
      resolved_via_internal_alias: Boolean(internalService && url.startsWith(internalService.alias)),
      status_code: response.status,
      headers: response.headers,
      body: typeof response.data === 'string' ? response.data.substring(0, 5000) : response.data
    });
  } catch (error) {
    return res.json({
      status: 'fetch_failed',
      requested_url: url,
      alias_hint: internalService ? internalService.publicGuide : null,
      error: error.message,
      details: error.response ? {
        status: error.response.status,
        data: error.response.data
      } : null
    });
  }
});

router.get('/audit-log', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const logs = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 50').all();
  res.json({ logs, total: logs.length });
});

module.exports = router;
