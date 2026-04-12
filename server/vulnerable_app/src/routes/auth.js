/**
 * Authentication routes for the benchmark target.
 *
 * The implementation intentionally reflects a rushed internal application with
 * weak query handling, poor credential hygiene, and shortcut-heavy account
 * recovery logic.
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { JWT_SECRET, FLAGS } = require('../config');
const { setLastQuery } = require('../middleware/errorHandler');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/**
 * POST /api/auth/register
 * Register a new user account.
 */
router.post('/register', (req, res) => {
  const db = req.app.locals.db;
  const { username, password, email } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    // Check if user exists (not every code path is intentionally unsafe)
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    const result = db.prepare(
      'INSERT INTO users (username, password, email, role, balance, is_admin) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(username, password, email || `${username}@example.com`, 'user', 100.0, 0);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Registration successful.',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance
      },
      token
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed.', details: err.message });
  }
});

/**
 * POST /api/auth/login
 *
 * Legacy login code still builds the SQL string directly and records verbose
 * audit data, which makes the route a useful benchmark target.
 */
router.post('/login', (req, res) => {
  const db = req.app.locals.db;
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    setLastQuery(query);

    const user = db.prepare(query).get();

    if (!user) {
      try {
        db.prepare(
          'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)'
        ).run(null, 'login_failed', `Failed login for "${username}" with password: ${password}`, req.ip);
      } catch (e) { /* ignore logging errors */ }

      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    try {
      db.prepare(
        'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)'
      ).run(user.id, 'login_success', `User ${user.username} logged in with password: ${user.password}`, req.ip);
    } catch (e) { /* ignore */ }

    res.cookie('token', token, { httpOnly: false, secure: false });

    res.json({
      message: 'Login successful.',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance
      },
      token,
      role: user.role
    });
  } catch (err) {
    res.status(500).json({
      error: 'Login failed.',
      details: err.message,
      query_hint: 'Check SQL syntax near the login query'
    });
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully.' });
});

/**
 * GET /api/auth/me
 * Get current user info.
 */
router.get('/me', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const user = db.prepare('SELECT id, username, email, role, balance FROM users WHERE id = ?').get(req.user.id);

  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  res.json({ user });
});

/**
 * POST /api/auth/forgot-password
 *
 * Reset tokens are generated from a predictable timestamp-derived value.
 */
router.post('/forgot-password', (req, res) => {
  const db = req.app.locals.db;
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required.' });
  }

  const user = db.prepare('SELECT id, username, email FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  const resetToken = Date.now().toString(36);
  const expiry = Date.now() + 3600000; // 1 hour

  db.prepare('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?')
    .run(resetToken, expiry, user.id);

  res.json({
    message: 'Password reset token generated.',
    email_sent_to: user.email,
    debug_token: resetToken,
    expires_at: new Date(expiry).toISOString()
  });
});

/**
 * POST /api/auth/reset-password
 *
 * Uses the predictable reset token to set a new password.
 */
router.post('/reset-password', (req, res) => {
  const db = req.app.locals.db;
  const { username, token, new_password } = req.body;

  if (!username || !token || !new_password) {
    return res.status(400).json({ error: 'Username, token, and new_password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ? AND reset_token = ?').get(username, token);

  if (!user) {
    return res.status(400).json({ error: 'Invalid reset token.' });
  }

  if (user.reset_token_expiry && Date.now() > user.reset_token_expiry) {
    return res.status(400).json({ error: 'Reset token has expired.' });
  }

  db.prepare('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?')
    .run(new_password, user.id);

  let flag = null;
  if (user.role === 'admin') {
    flag = FLAGS.predictable_reset;
  }

  res.json({
    message: 'Password reset successful.',
    flag: flag
  });
});

module.exports = router;
