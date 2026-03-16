/**
 * Stripe Webhook Handler — Netlify Function
 * Permanent URL: https://accisecuritygroup.com/.netlify/functions/webhook
 * 
 * Receives payment events from Stripe, records them, and emails
 * the client their fix report automatically.
 */

const https = require('https');

// ─── Helpers ─────────────────────────────────────────────────────────────────
function post(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = https.request({ hostname, path, method: 'POST', headers }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function sendEmail({ to, subject, html, text }) {
  // Send via SMTP using nodemailer — but Netlify Functions don't have nodemailer
  // So we relay via our own webhook-relay endpoint or use Formspree as email relay
  // Using Postmark/SendGrid free tier — or fallback: log + notify via Telegram bot

  // For now: send via SMTP relay through accisecuritygroup.com Office 365
  // We'll use the office365 SMTP directly from the function
  const nodemailer = require('nodemailer');
  const transport = nodemailer.createTransport({
    host: 'smtp.office365.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER || 'david.collins@accisecuritygroup.com',
      pass: process.env.SMTP_PASS,
    },
    tls: { ciphers: 'SSLv3' }
  });
  return transport.sendMail({ from: `David Collins <${process.env.SMTP_USER}>`, to, subject, html, text });
}

// ─── Service → Agent mapping ──────────────────────────────────────────────────
// scanner = first agent to run (READ-ONLY recon); fixer = second agent (remediation)
const SERVICE_MAP = {
  // ── LIVE Stripe price IDs ─────────────────────────────────────────────────
  'price_1TBJbfDTw4s7IZ2Z7bO34RfB': { scanner: 'acci_scanner_credentials', fixer: 'acci_fix_credentials', service: 'credentials',   label: 'Leaked Password & API Key Hunt',       price: 249 },
  'price_1TBJbfDTw4s7IZ2ZCOgkvPcN': { scanner: 'acci_scanner_exposedfiles', fixer: 'acci_fix_exposedfiles', service: 'cloud-audit', label: 'Private Files Exposed Online Audit',   price: 299 },
  'price_1TBJbgDTw4s7IZ2ZV1825wBn': { scanner: 'acci_scanner_credentials', fixer: 'acci_fix_credentials', service: 'credentials',   label: 'Leaked Password & API Key Hunt',       price: 249 },
  'price_1TBJbgDTw4s7IZ2ZLBc7bOq0': { scanner: 'acci_scanner_aitools',     fixer: 'acci_fix_aitools',     service: 'shadow-ai',     label: 'Unauthorized AI Tool Sweep',           price: 349 },
  'price_1TBJbhDTw4s7IZ2ZDLBGPUwU': { scanner: 'acci_scanner_exposedfiles', fixer: 'acci_fix_exposedfiles', service: 's3-audit',    label: 'Private Files Exposed Online Audit',   price: 599 },
  'price_1TBJbhDTw4s7IZ2Zrhl5KI2c': { scanner: 'acci_scanner_dossier',     fixer: null,                    service: 'osint-dossier', label: 'Business Background Dossier',          price: 449 },
  // ── Amount-based fallback (PayPal) ────────────────────────────────────────
  24900: { scanner: 'acci_scanner_credentials', fixer: 'acci_fix_credentials', service: 'credentials',    label: 'Leaked Password & API Key Hunt',       price: 249 },
  34900: { scanner: 'acci_scanner_aitools',     fixer: 'acci_fix_aitools',     service: 'shadow-ai',      label: 'Unauthorized AI Tool Sweep',           price: 349 },
  29900: { scanner: 'acci_scanner_dossier',     fixer: null,                   service: 'osint-dossier',  label: 'Business Background Dossier Standard', price: 299 },
  19900: { scanner: 'acci_scanner_dns',     fixer: 'acci_fix_dns',             service: 'dns-protection',  label: 'DNS & Email Spoofing Protection', price: 199 },
  45000: { scanner: 'acci_scanner_dossier',     fixer: null,                   service: 'osint-dossier',  label: 'Business Background Dossier Premium',  price: 450 },
  59900: { scanner: 'acci_scanner_exposedfiles', fixer: 'acci_fix_exposedfiles', service: 's3-audit',     label: 'Private Files Exposed Online Audit',   price: 599 },
  99900: { scanner: 'acci_scanner_credentials', fixer: null,                   service: 'bundle',         label: 'Full Security Bundle',                 price: 999 },
};

function resolveService(priceId, amount) {
  if (priceId && SERVICE_MAP[priceId]) return SERVICE_MAP[priceId];
  if (amount && SERVICE_MAP[amount]) return SERVICE_MAP[amount];
  const closest = Object.keys(SERVICE_MAP).filter(k => !isNaN(k))
    .sort((a, b) => Math.abs(a - amount) - Math.abs(b - amount))[0];
  return SERVICE_MAP[closest] || { scanner: 'dmarc', fixer: 'fixer', service: 'email-security', label: 'Security Fix', price: amount / 100 };
}

async function triggerAgent(agentId, task) {
  const gatewayUrl   = process.env.OPENCLAW_GATEWAY_URL   || 'http://127.0.0.1:18789';
  const gatewayToken = process.env.OPENCLAW_GATEWAY_TOKEN;
  if (!gatewayToken) { console.warn('No OPENCLAW_GATEWAY_TOKEN — skipping agent trigger'); return; }
  const body = JSON.stringify({ agentId, mode: 'run', task, delivery: { mode: 'announce', channel: 'telegram', to: '5181664803' } });
  const u = new URL(gatewayUrl);
  await post(u.hostname + (u.port ? ':' + u.port : ''), '/api/sessions/spawn',
    { 'Content-Type': 'application/json', 'Authorization': `Bearer ${gatewayToken}`, 'Content-Length': Buffer.byteLength(body).toString() },
    body
  ).catch(e => console.warn('Agent trigger failed:', e.message));
}

async function triggerScannerThenFixer(svc, domain, customerEmail) {
  const scanTask = `NEW CLIENT PAYMENT — SCAN PHASE.\n\nService purchased: ${svc.label}\nClient domain: ${domain}\nClient email: ${customerEmail}\n\nYour role: SCANNER (read-only). Follow your SOUL.md safety rules exactly.\n\n1. Run a full ${svc.label} scan on ${domain}.\n2. Produce a structured findings report (executive summary + findings table + risk levels).\n3. Email the scan report to ${customerEmail} and CC david.collins@accisecuritygroup.com.\n4. If CRITICAL or HIGH findings exist AND a fixer agent is available, output:\n   HANDOFF_TO_FIXER: [summary of findings]\n   (The fixer agent will be triggered automatically.)\n\nBegin your scan now.`;

  await triggerAgent(svc.scanner, scanTask);

  // For services with a fixer, also queue the fixer with a slight delay reference
  // The fixer will wait for the scanner's handoff signal in practice
  if (svc.fixer) {
    const fixTask = `NEW CLIENT — FIX PHASE (runs after scanner completes).\n\nService: ${svc.label}\nClient domain: ${domain}\nClient email: ${customerEmail}\n\nYour role: FIXER. The scanner agent has already produced a findings report for this client. Follow your SOUL.md safety rules exactly.\n\n1. Review the scan findings for ${domain}.\n2. Apply all safe remediations following the CONFIRMATION REQUIRED protocol.\n3. Produce a full remediation report.\n4. Email the report to ${customerEmail} and CC david.collins@accisecuritygroup.com.\n\nBegin remediation now.`;
    await triggerAgent(svc.fixer, fixTask);
  }
}

function generateFixInstructions(domain, amount, label) {
  label = label || 'Security Fix';
  return {
    subject: `✅ Payment received — Your ${label} for ${domain} is in progress`,
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;color:#333;">
  <div style="background:#0d0f14;padding:24px;border-radius:12px;margin-bottom:24px;">
    <h1 style="color:#00d4aa;margin:0;font-size:22px;">🔒 ACCI Security Group</h1>
    <p style="color:#94a3b8;margin:8px 0 0;">Payment Confirmed — Work In Progress</p>
  </div>

  <h2>Hi there,</h2>
  <p>We've received your payment for the <strong>${pkg}</strong> on <strong>${domain}</strong>. We're on it — you'll receive your completed fix report within <strong>24 hours</strong>.</p>

  <div style="background:#f8fafc;border-left:4px solid #00d4aa;padding:16px;margin:20px 0;border-radius:4px;">
    <strong>What we're fixing:</strong><br>
    ${isBasic ? `
    • DMARC record — set to quarantine/reject so spoofed emails get blocked<br>
    • SPF record — authorizing only your real email servers<br>
    • Confirmation report with before/after screenshots
    ` : `
    • DMARC record — full enforcement configuration<br>
    • SPF record — comprehensive sender authorization<br>
    • DKIM setup — cryptographic email signing<br>
    • Full written audit report (PDF)<br>
    • 30-day monitoring setup
    `}
  </div>

  <p>We'll email you directly when everything is live. If you have any questions in the meantime, just reply to this email.</p>

  <p>— David Collins<br>
  <a href="mailto:david.collins@accisecuritygroup.com">david.collins@accisecuritygroup.com</a><br>
  <a href="https://accisecuritygroup.com">accisecuritygroup.com</a></p>

  <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0;">
  <p style="font-size:12px;color:#94a3b8;">ACCI Security Group · Miami, FL · Cybersecurity audits for businesses</p>
</body>
</html>`,
    text: `Payment received for ${pkg} on ${domain}. We'll complete your DMARC fix within 24 hours and email you the report. Questions? Reply to this email. — David Collins, ACCI Security Group`
  };
}

// ─── Stripe signature verification ───────────────────────────────────────────
function verifyStripeSignature(payload, sigHeader, secret) {
  const crypto = require('crypto');
  const parts = sigHeader.split(',').reduce((acc, part) => {
    const [k, v] = part.split('=');
    acc[k] = v;
    return acc;
  }, {});

  const timestamp = parts.t;
  const sig = parts.v1;
  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');

  // Check timestamp (within 5 minutes)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 300) {
    throw new Error('Timestamp too old — possible replay attack');
  }

  if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'))) {
    throw new Error('Signature mismatch');
  }
  return true;
}

// ─── Main handler ─────────────────────────────────────────────────────────────
exports.handler = async (event, context) => {
  // Health check
  if (event.httpMethod === 'GET') {
    return { statusCode: 200, body: JSON.stringify({ status: 'ok', service: 'Acci Stripe Webhook' }) };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const sig = event.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  // Verify signature if secret is set
  if (webhookSecret && sig) {
    try {
      verifyStripeSignature(event.body, sig, webhookSecret);
    } catch (err) {
      console.error('Webhook signature failed:', err.message);
      return { statusCode: 400, body: `Webhook Error: ${err.message}` };
    }
  }

  let stripeEvent;
  try {
    stripeEvent = JSON.parse(event.body);
  } catch (err) {
    return { statusCode: 400, body: 'Invalid JSON' };
  }

  console.log(`Stripe event received: ${stripeEvent.type}`);

  // Handle payment events
  if (
    stripeEvent.type === 'checkout.session.completed' ||
    stripeEvent.type === 'payment_intent.succeeded' ||
    stripeEvent.type === 'payment_link.completed'
  ) {
    const obj = stripeEvent.data?.object;
    const customerEmail = obj?.customer_details?.email || obj?.receipt_email || null;
    const amount = obj?.amount_total || obj?.amount || 0;
    const priceId = obj?.line_items?.data?.[0]?.price?.id || obj?.metadata?.price_id || null;
    const domain = obj?.custom_fields?.find?.(f => f.key === 'domain')?.text?.value
                || obj?.metadata?.domain
                || 'unknown';

    const svc = resolveService(priceId, amount);
    console.log(`Payment: ${customerEmail} paid $${amount/100} for ${domain} → ${svc.label} → agent:${svc.agent}`);

    // Trigger scanner → fixer pipeline
    if (domain !== 'unknown' && customerEmail) {
      await triggerScannerThenFixer(svc, domain, customerEmail);
    }

    // Send confirmation email to customer
    if (customerEmail) {
      try {
        const template = generateFixInstructions(domain, amount, svc.label);
        await sendEmail({
          to: customerEmail,
          subject: template.subject,
          html: template.html,
          text: template.text,
        });
        console.log(`Confirmation email sent to ${customerEmail}`);
      } catch (err) {
        console.error('Email send failed:', err.message);
      }
    }

    // Notify David/Lau that a payment came in
    try {
      const alertTemplate = {
        to: 'david.collins@accisecuritygroup.com',
        subject: `💰 New payment: $${amount/100} — ${svc.label} — ${domain}`,
        html: `<p><strong>New payment received!</strong></p>
               <p>Customer: ${customerEmail || 'unknown'}</p>
               <p>Domain: ${domain}</p>
               <p>Amount: $${amount/100}</p>
               <p>Service: ${svc.label}</p>
               <p>Scanner: ${svc.scanner} → Fixer: ${svc.fixer || 'N/A (report only)'}</p>
               <p>Event: ${stripeEvent.type}</p>`,
        text: `New payment: $${amount/100} from ${customerEmail} for ${svc.label} on ${domain}. Agent ${svc.agent} triggered automatically.`
      };
      await sendEmail(alertTemplate);
    } catch (err) {
      console.error('Internal alert failed:', err.message);
    }
  }

  return {
    statusCode: 200,
    body: JSON.stringify({ received: true }),
  };
};
