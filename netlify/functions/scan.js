/**
 * scan.js — ACCI Security Group Free Scan Form Handler
 * Receives form submission and triggers scan-intake pipeline
 *
 * POST body: { company_name, email, domain }
 */

const { execSync } = require('child_process');
const https = require('https');

const PIPELINE_DIR = '/Users/minion1/.openclaw/workspace/pipeline';
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT  = '5181664803';

function notifyTelegram(text) {
  if (!TELEGRAM_TOKEN) return;
  const body = JSON.stringify({ chat_id: TELEGRAM_CHAT, text, parse_mode: 'Markdown' });
  const req = https.request({
    hostname: 'api.telegram.org',
    path: `/bot${TELEGRAM_TOKEN}/sendMessage`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
  }, res => res.resume());
  req.on('error', () => {});
  req.write(body); req.end();
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch(e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { company_name, email, domain } = body;
  if (!email || !domain) {
    return { statusCode: 400, body: JSON.stringify({ error: 'email and domain are required' }) };
  }

  const companyName = company_name || domain;
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  // Notify operator that a scan was requested
  notifyTelegram(`🔍 *New scan request*\nCompany: ${companyName}\nEmail: ${email}\nDomain: ${cleanDomain}`);

  // Trigger scan-intake asynchronously (fire and forget)
  try {
    const cmd = `cd ${PIPELINE_DIR} && node scan-intake.js ${JSON.stringify(companyName)} ${email} ${cleanDomain} &`;
    execSync(cmd, { timeout: 2000, stdio: 'ignore' });
  } catch(e) {
    // Process launched in background — error here is OK
  }

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify({ success: true, message: 'Scan started. Results will be in your inbox within 15 minutes.' })
  };
};
