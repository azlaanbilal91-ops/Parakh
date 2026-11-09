'use strict';

// All network lookups. Every call has a timeout and returns null/empty on failure,
// so one slow service never breaks the whole check.

const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || '';
const URLHAUS_KEY = process.env.URLHAUS_AUTH_KEY || '';

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise(function (_, reject) { timer = setTimeout(function () { reject(new Error('timeout')); }, ms); });
  return Promise.race([promise, timeout]).finally(function () { clearTimeout(timer); });
}

// Never let the server connect to its own network or private ranges (SSRF guard).
function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const a = parts[0], b = parts[1];
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    return x === '::1' || x === '::' || x.indexOf('fc') === 0 || x.indexOf('fd') === 0 || x.indexOf('fe8') === 0 ||
      x.indexOf('fe9') === 0 || x.indexOf('fea') === 0 || x.indexOf('feb') === 0 || x.indexOf('::ffff:') === 0;
  }
  return true;
}

async function resolveHost(host) {
  const bare = host.replace(/^\[|\]$/g, '');
  let ips;
  if (net.isIP(bare)) {
    ips = [bare];
  } else {
    try {
      const r = await withTimeout(dns.lookup(bare, { all: true }), 4000);
      ips = r.map(function (x) { return x.address; });
    } catch (e) {
      return { resolves: false, definitive: e && e.code === 'ENOTFOUND', ips: [], publicIps: [] };
    }
  }
  const publicIps = ips.filter(function (ip) { return !isPrivateIP(ip); });
  return { resolves: true, ips: ips, publicIps: publicIps, private: publicIps.length === 0 };
}

function sslInfo(host, ip) {
  return new Promise(function (resolve) {
    let done = false;
    let socket;
    const finish = function (value) {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch (e) { /* already closed */ }
      resolve(value);
    };
    socket = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false }, function () {
      const c = socket.getPeerCertificate() || {};
      const to = Date.parse(c.valid_to);
      const from = Date.parse(c.valid_from);
      finish({
        connected: true,
        ok: !!socket.authorized,
        error: socket.authorizationError ? String(socket.authorizationError) : null,
        issuer: c.issuer ? (c.issuer.O || c.issuer.CN || '') : '',
        daysLeft: isNaN(to) ? 0 : Math.round((to - Date.now()) / 864e5),
        ageDays: isNaN(from) ? undefined : Math.floor((Date.now() - from) / 864e5)
      });
    });
    socket.setTimeout(5000, function () { finish({ connected: false }); });
    socket.on('error', function () { finish({ connected: false }); });
  });
}

async function rdapAge(domain) {
  try {
    const r = await fetch('https://rdap.org/domain/' + encodeURIComponent(domain), {
      headers: { accept: 'application/rdap+json, application/json' },
      redirect: 'follow',
      signal: AbortSignal.timeout(6000)
    });
    if (!r.ok) return null;
    const j = await r.json();
    const ev = (j.events || []).find(function (e) { return e.eventAction === 'registration'; });
    if (!ev || !ev.eventDate) return null;
    const t = Date.parse(ev.eventDate);
    if (isNaN(t)) return null;
    return { registered: new Date(t).toISOString().slice(0, 10), days: Math.floor((Date.now() - t) / 864e5) };
  } catch (e) {
    return null;
  }
}

async function googleSafeBrowsing(url) {
  if (!GSB_KEY) return null;
  try {
    const r = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(GSB_KEY), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(6000),
      body: JSON.stringify({
        client: { clientId: 'parakh', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: url }]
        }
      })
    });
    if (!r.ok) return null;
    const j = await r.json();
    const threats = (j.matches || []).map(function (m) { return m.threatType; });
    return { source: 'Google Safe Browsing', threats: threats };
  } catch (e) {
    return null;
  }
}

async function urlhaus(host) {
  if (!URLHAUS_KEY) return null;
  try {
    const r = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'Auth-Key': URLHAUS_KEY },
      signal: AbortSignal.timeout(6000),
      body: 'host=' + encodeURIComponent(host.replace(/^\[|\]$/g, ''))
    });
    if (!r.ok) return null;
    const j = await r.json();
    if (j.query_status === 'no_results') return { source: 'URLhaus', threats: [] };
    if (j.query_status === 'ok') {
      return { source: 'URLhaus', threats: parseInt(j.urls_online, 10) > 0 ? ['MALWARE'] : [] };
    }
    return null;
  } catch (e) {
    return null;
  }
}

async function reputation(url, host) {
  const results = await Promise.all([googleSafeBrowsing(url), urlhaus(host)]);
  const out = { checked: [], threats: [] };
  results.forEach(function (x) {
    if (!x) return;
    out.checked.push(x.source);
    x.threats.forEach(function (t) { if (out.threats.indexOf(t) < 0) out.threats.push(t); });
  });
  return out;
}

module.exports = { resolveHost: resolveHost, sslInfo: sslInfo, rdapAge: rdapAge, reputation: reputation };
