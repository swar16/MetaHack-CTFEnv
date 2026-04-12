/**
 * Import routes.
 *
 * The import workflow stores the evaluated result as a retrievable job record,
 * which makes the unsafe processing path feel closer to a real back-office
 * import system while keeping the benchmark deterministic.
 */

const crypto = require('crypto');
const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

function createJobId() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return crypto.randomBytes(16).toString('hex');
}

router.post('/', requireAuth, (req, res) => {
  const { data, format } = req.body;
  const jobs = req.app.locals.importJobs;

  if (!data) {
    return res.status(400).json({
      error: 'data field is required.',
      usage: 'Send base64-encoded data in the "data" field.',
      supported_formats: ['json', 'csv', 'custom']
    });
  }

  try {
    const decoded = Buffer.from(data, 'base64').toString('utf8');
    let result;

    if (format === 'json') {
      try {
        result = JSON.parse(decoded);
      } catch (parseError) {
        result = eval(decoded); // eslint-disable-line no-eval
      }
    } else {
      result = eval(decoded); // eslint-disable-line no-eval
    }

    const jobId = createJobId();
    jobs.set(jobId, {
      id: jobId,
      ownerId: req.user.id,
      status: 'completed',
      format: format || 'auto',
      result: typeof result === 'object' ? result : String(result),
      recordsProcessed: typeof result === 'object' && Array.isArray(result) ? result.length : 1
    });

    return res.json({
      status: 'import_completed',
      format: format || 'auto',
      job_id: jobId,
      records_processed: jobs.get(jobId).recordsProcessed
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Import failed.',
      details: err.message,
      stack: err.stack
    });
  }
});

router.get('/jobs/:jobId', requireAuth, (req, res) => {
  const jobs = req.app.locals.importJobs;
  const job = jobs.get(req.params.jobId);

  if (!job) {
    return res.status(404).json({ error: 'Import job not found.' });
  }

  if (job.ownerId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'You do not have access to this import job.' });
  }

  return res.json({
    job_id: job.id,
    status: job.status,
    format: job.format,
    records_processed: job.recordsProcessed,
    result: job.result
  });
});

module.exports = router;
