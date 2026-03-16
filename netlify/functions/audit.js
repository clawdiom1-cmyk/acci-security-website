// audit.js — Free Security Scan Netlify Function
// GET /.netlify/functions/audit?domain=yourcompany.com

const dns   = require('dns');
const https = require('https');

// Promisify dns manually for compatibility
const resolveTxt = (host) => new Promise((res, rej) => dns.resolveTxt(host, (e, r) => e ? rej(e) : res(r)));
const resolveMx  = (host) => new Promise((res, rej) => dns.resolveMx(host,  (e, r) => e ? rej(e) : res(r)));

// ─── HTTP helper ──────────────────────────────────────────────────────────────
function httpGet(url, timeoutMs = 6000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (val) => { if (!settled) { settled = true; resolve(val); } };

    const timer = setTimeout(() => { try { req.destroy(); } catch {} done({ status: 0, headers: {}, body: '' }); }, timeoutMs);

    const req = https.get(url, { headers: { 'User-Agent': 'AcciSecurityScanner/1.0 (free-audit)' } }, (res) => {
      let body = '';
      res.on('data', c => { body += c; if (body.length > 40000) { try { req.destroy(); } catch {} } });
      res.on('end', () => { clearTimeout(timer); done({ status: res.statusCode, headers: res.headers, body }); });
      res.on('error', () => { clearTimeout(timer); done({ status: 0, headers: {}, body: '' }); });
    });
    req.on('error', () => { clearTimeout(timer); done({ status: 0, headers: {}, body: '' }); });
  });
}

// ─── Check 1: Email Security (DMARC + SPF) ───────────────────────────────────
async function checkEmail(domain) {
  let dmarc = null, spf = null;

  try {
    const recs = await resolveTxt(`_dmarc.${domain}`);
    dmarc = recs.flat().find(r => r.toLowerCase().startsWith('v=dmarc1')) || null;
  } catch {}

  try {
    const recs = await resolveTxt(domain);
    spf = recs.flat().find(r => r.toLowerCase().startsWith('v=spf1')) || null;
  } catch {}

  const noDmarc = !dmarc;
  const dmarcNone = dmarc && dmarc.toLowerCase().includes('p=none');
  const noSpf = !spf;
  const spfSoft = spf && spf.includes('~all');

  let status, finding, detail;

  if (noDmarc && noSpf) {
    status = 'critical';
    finding = 'No email authentication (DMARC or SPF)';
    detail = 'Anyone can send emails pretending to be your company right now — completely undetected.';
  } else if (noDmarc) {
    status = 'critical';
    finding = 'No DMARC record — spoofing unprotected';
    detail = 'Spoofed emails from your domain are delivered to inboxes. DMARC is the primary shield against impersonation.';
  } else if (dmarcNone) {
    status = 'warning';
    finding = 'DMARC set to monitor-only (p=none) — no protection';
    detail = 'Your DMARC record exists but doesn\'t block anything. It\'s like having a security camera with no alarm.';
  } else if (noSpf || spfSoft) {
    status = 'warning';
    finding = 'SPF record is weak or missing';
    detail = 'Without a strict SPF record, some spoofed emails may still get through.';
  } else {
    status = 'ok';
    finding = 'Email authentication configured';
    detail = 'DMARC and SPF are in place. Good baseline protection.';
  }

  return { status, finding, detail };
}

// ─── Check 2: Subdomains / Shadow IT ─────────────────────────────────────────
async function checkSubdomains(domain) {
  let count = 0;
  let subdomains = [];

  try {
    const r = await httpGet(`https://crt.sh/?q=%.${domain}&output=json`, 7000);
    if (r.status === 200 && r.body) {
      const certs = JSON.parse(r.body);
      const subs = new Set(
        certs.flatMap(c => (c.name_value || '').split('\n'))
          .map(s => s.trim().replace(/^\*\./, ''))
          .filter(s => s.endsWith(domain) && s !== domain && !s.includes('*'))
      );
      count = subs.size;
      subdomains = [...subs].slice(0, 5);
    }
  } catch {}

  let status, finding, detail;
  if (count >= 30) {
    status = 'warning';
    finding = `${count} subdomains found in public certificate logs`;
    detail = `Large attack surface. ${count} services running under your domain — each one is a potential entry point for attackers or unauthorized tools.`;
  } else if (count >= 10) {
    status = 'warning';
    finding = `${count} subdomains found`;
    detail = `Moderate surface area. We check each subdomain for unauthorized services and shadow IT tools.`;
  } else if (count >= 1) {
    status = 'info';
    finding = `${count} subdomain${count > 1 ? 's' : ''} found`;
    detail = 'Low subdomain count — shadow IT risk is lower but still worth a quick sweep.';
  } else {
    status = 'ok';
    finding = 'No public subdomains found';
    detail = 'Clean subdomain footprint.';
  }

  return { status, finding, detail, subdomains: subdomains.slice(0, 3) };
}

// ─── Check 3: Developer / Credential Exposure ────────────────────────────────
async function checkCredentials(domain) {
  const slug = domain.split('.')[0];
  let githubFound = false;
  let repoCount = 0;

  try {
    const r = await httpGet(`https://api.github.com/orgs/${slug}/repos?per_page=5`, 5000);
    if (r.status === 200) {
      githubFound = true;
      const repos = JSON.parse(r.body);
      repoCount = repos.length;
    }
  } catch {}

  if (!githubFound) {
    try {
      const r = await httpGet(`https://api.github.com/users/${slug}/repos?per_page=5`, 5000);
      if (r.status === 200) {
        githubFound = true;
        const repos = JSON.parse(r.body);
        repoCount = repos.length;
      }
    } catch {}
  }

  let status, finding, detail;
  if (githubFound && repoCount > 0) {
    status = 'warning';
    finding = `GitHub presence detected — ${repoCount}+ public repositor${repoCount === 1 ? 'y' : 'ies'}`;
    detail = 'Public repositories can contain accidentally exposed API keys, database credentials, or private configuration files.';
  } else if (githubFound) {
    status = 'info';
    finding = 'GitHub organization found';
    detail = 'We scan public repositories for accidentally committed secrets and credentials.';
  } else {
    status = 'ok';
    finding = 'No public code repositories detected';
    detail = 'No immediate developer credential exposure signals found.';
  }

  return { status, finding, detail };
}

// ─── Check 4: Security Headers / Web Posture ─────────────────────────────────
async function checkWebPosture(domain) {
  const r = await httpGet(`https://${domain}`, 6000);

  const headers = r.headers || {};
  const missing = [];

  if (!headers['strict-transport-security']) missing.push('HSTS (forces HTTPS)');
  if (!headers['x-frame-options'] && !headers['content-security-policy']) missing.push('Clickjacking protection');
  if (!headers['x-content-type-options']) missing.push('MIME sniffing protection');
  if (!headers['content-security-policy']) missing.push('Content Security Policy');
  if (!headers['referrer-policy']) missing.push('Referrer Policy');
  if (!headers['permissions-policy']) missing.push('Permissions Policy');

  let status, finding, detail;
  if (r.status === 0) {
    status = 'info';
    finding = 'Website unreachable during scan';
    detail = 'Could not reach the website to check security headers.';
  } else if (missing.length >= 4) {
    status = 'warning';
    finding = `${missing.length} security headers missing`;
    detail = `Missing: ${missing.slice(0, 3).join(', ')}${missing.length > 3 ? ` + ${missing.length - 3} more` : ''}. These headers protect against XSS, clickjacking, and data leaks.`;
  } else if (missing.length >= 2) {
    status = 'info';
    finding = `${missing.length} security headers could be improved`;
    detail = `Missing: ${missing.join(', ')}.`;
  } else {
    status = 'ok';
    finding = 'Security headers look solid';
    detail = 'Basic web security hardening is in place.';
  }

  return { status, finding, detail };
}

// ─── Check 5: MX / Email Infrastructure ──────────────────────────────────────
async function checkMXPosture(domain) {
  let mxRecords = [];
  try {
    mxRecords = await resolveMx(domain);
  } catch {}

  const mxList = mxRecords.map(r => r.exchange.toLowerCase());
  const hasEmail = mxList.length > 0;

  // Check for common providers
  const provider = mxList.some(m => m.includes('google') || m.includes('googlemail')) ? 'Google Workspace' :
    mxList.some(m => m.includes('outlook') || m.includes('microsoft')) ? 'Microsoft 365' :
    mxList.some(m => m.includes('protonmail')) ? 'ProtonMail' :
    mxList.some(m => m.includes('zoho')) ? 'Zoho Mail' :
    hasEmail ? 'Custom mail server' : null;

  // DMARC already checked in email check — here we flag missing MX
  if (!hasEmail) {
    return {
      status: 'info',
      finding: 'No MX records — domain may not send/receive email',
      detail: 'If your company uses email, missing MX records is worth investigating.'
    };
  }

  return {
    status: 'ok',
    finding: `Email hosted on ${provider || 'external provider'}`,
    detail: `Your MX records are configured${provider ? ` using ${provider}` : ''}.`
  };
}

// ─── Summary + score ─────────────────────────────────────────────────────────
function summarize(checks) {
  const counts = { critical: 0, warning: 0, info: 0, ok: 0 };
  for (const c of Object.values(checks)) counts[c.status] = (counts[c.status] || 0) + 1;

  const score = Math.max(0, 100
    - (counts.critical * 30)
    - (counts.warning * 12)
    - (counts.info * 3)
  );

  const grade = score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
  const issuesFound = counts.critical + counts.warning;

  return { counts, score, grade, issuesFound };
}

// ─── Handler ──────────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Cache-Control': 'no-store',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  let domain = (event.queryStringParameters?.domain || '').toLowerCase().trim();

  // Clean up domain
  domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

  if (!domain || !/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid domain. Please enter a domain like yourcompany.com' })
    };
  }

  // Run all checks in parallel
  const [email, subdomains, credentials, webPosture, mx] = await Promise.allSettled([
    checkEmail(domain),
    checkSubdomains(domain),
    checkCredentials(domain),
    checkWebPosture(domain),
    checkMXPosture(domain),
  ]);

  const checks = {
    email:       email.status       === 'fulfilled' ? email.value       : { status: 'info', finding: 'Check timed out', detail: '' },
    shadow:      subdomains.status  === 'fulfilled' ? subdomains.value  : { status: 'info', finding: 'Check timed out', detail: '' },
    credentials: credentials.status === 'fulfilled' ? credentials.value : { status: 'info', finding: 'Check timed out', detail: '' },
    webPosture:  webPosture.status  === 'fulfilled' ? webPosture.value  : { status: 'info', finding: 'Check timed out', detail: '' },
    mx:          mx.status          === 'fulfilled' ? mx.value          : { status: 'info', finding: 'Check timed out', detail: '' },
  };

  const summary = summarize(checks);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ domain, checks, summary })
  };
};
