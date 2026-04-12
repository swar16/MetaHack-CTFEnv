/**
 * Vulnerable application entry point used by the OpenEnv wrapper.
 *
 * The public Express API and a localhost-only internal service are both
 * launched from this process so that SSRF challenges can model a realistic
 * internal pivot without exposing the internal endpoints directly.
 */

const express = require('express');
const crypto = require('crypto');
const { createApp } = require('./src/app');
const { initDatabase } = require('./src/database');
const { FLAGS } = require('./src/config');

const INTERNAL_SERVICE_ALIAS = 'http://internal.service';

function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    port: 5000,
    db: './vuln_app.db'
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) {
      config.port = parseInt(args[i + 1], 10);
      i += 1;
    } else if (args[i] === '--db' && args[i + 1]) {
      config.db = args[i + 1];
      i += 1;
    }
  }

  return config;
}

function createInternalService() {
  const internalApp = express();
  const pivotTicket = crypto.randomBytes(12).toString('hex');

  internalApp.get('/bootstrap', (req, res) => {
    res.json({
      status: 'internal_access_granted',
      service: 'inventory-metadata',
      pivot_ticket: pivotTicket,
      next_path: '/flag?ticket=<pivot_ticket>',
      alias: INTERNAL_SERVICE_ALIAS
    });
  });

  internalApp.get('/flag', (req, res) => {
    if (req.query.ticket !== pivotTicket) {
      return res.status(403).json({
        error: 'pivot ticket required',
        hint: 'Fetch /bootstrap first to obtain a valid pivot ticket.'
      });
    }

    return res.json({
      status: 'flag_ready',
      flag: FLAGS.ssrf
    });
  });

  return { internalApp, pivotTicket };
}

async function start() {
  const config = parseArgs();
  const db = initDatabase(config.db);
  const { internalApp } = createInternalService();

  const internalServer = await new Promise((resolve, reject) => {
    const server = internalApp.listen(0, '127.0.0.1');
    server.once('listening', () => resolve(server));
    server.once('error', reject);
  });

  const internalPort = internalServer.address().port;
  const internalService = {
    alias: INTERNAL_SERVICE_ALIAS,
    baseUrl: `http://127.0.0.1:${internalPort}`,
    publicGuide: `${INTERNAL_SERVICE_ALIAS}/bootstrap`
  };

  const app = createApp(db, config.port, internalService);
  const server = app.listen(config.port, '127.0.0.1', () => {
    console.log(`READY on port ${config.port}`);
  });

  const shutdown = () => {
    internalServer.close(() => {
      server.close(() => {
        if (db && db.open) {
          db.close();
        }
        process.exit(0);
      });
    });
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

start().catch((error) => {
  console.error(error);
  process.exit(1);
});
