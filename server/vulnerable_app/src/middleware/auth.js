/**
 * Authentication middleware used across the benchmark target.
 *
 * The middleware intentionally accepts more credential shapes than it should,
 * which keeps multiple auth-related benchmark tasks grounded in realistic
 * implementation mistakes.
 */

const jwt = require('jsonwebtoken');
const { JWT_SECRET, ADMIN_API_KEY } = require('../config');

/**
 * Optional auth - attaches user to req if valid token present, but doesn't block.
 */
function optionalAuth(req, res, next) {
  const token = extractToken(req);
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
    } catch (err) {
      // Invalid token, continue without user
      req.user = null;
    }
  } else {
    req.user = null;
  }
  next();
}

/**
 * Required auth - blocks request if no valid token.
 */
function requireAuth(req, res, next) {
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (apiKey === ADMIN_API_KEY) {
    req.user = { id: 1, username: 'admin', role: 'admin' };
    return next();
  }

  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Provide a valid JWT token.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

/**
 * Admin-only middleware.
 */
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user && req.user.role === 'admin') {
      return next();
    }
    return res.status(403).json({ error: 'Admin access required.' });
  });
}

function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }

  if (req.query.token) {
    return req.query.token;
  }

  return null;
}

module.exports = { optionalAuth, requireAuth, requireAdmin };
