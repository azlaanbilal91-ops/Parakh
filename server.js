'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { parseInput, analyze, regDomain } = require('./analyzer');
const { resolveHost, sslInfo, rdapAge, reputation } = require('./lookups');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml' };

const cache = new Map();   // url -> { t, data }, keeps repeat checks from using up API quota
const hits = new Map();    // ip -> [timestamps], simple rate limit
const CACHE_MS = 10 * 60 * 1000;
const LIMIT_PER_MIN = 20;

function rateLimited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter(function (t) { return now - t < 60000; });
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) hits.clear();
  return list.length > LIMIT_PER_MIN;
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function check(raw) {
  const p = parseInput(raw);
  if (!p) return null;
  const key = p.u.href;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.t < CACHE_MS) return hit.data;

  const ext = {};
  ext.dns = await resolveHost(p.host);
  const jobs = [];
  if (!ext.dns.private) {
    jobs.push(reputation(p.u.href, p.host).then(function (v) { ext.reputation = v; }));
    if (!p.isIP) {
      jobs.push(rdapAge(regDomain(p.host)).then(function (v) { ext.age = v; }));
      if (ext.dns.publicIps.length) {
        jobs.push(sslInfo(p.host, ext.dns.publicIps[0]).then(function (v) { ext.ssl = v; }));
      }
    }
  }
  await Promise.all(jobs);

  const data = analyze(p, ext);
  if (cache.size > 2000) cache.clear();
  cache.set(key, { t: Date.now(), data: data });
  return data;
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.join(PUBLIC_DIR, rel);
  if (file.indexOf(PUBLIC_DIR + path.sep) !== 0) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(file, function (err, buf) {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }); res.end('Nahi mila'); return; }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-cache' });
    res.end(buf);
  });
}

const server = http.createServer(async function (req, res) {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/healthz') { res.writeHead(200); res.end('ok'); return; }
    if (url.pathname === '/api/check') {
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'x';
      if (rateLimited(ip)) { sendJson(res, 429, { error: 'too_many' }); return; }
      const data = await check(url.searchParams.get('url'));
      if (!data) { sendJson(res, 400, { error: 'invalid' }); return; }
      sendJson(res, 200, data);
      return;
    }
    serveStatic(req, res, url.pathname);
  } catch (e) {
    sendJson(res, 500, { error: 'server' });
  }
});

server.listen(PORT, function () { console.log('Parakh chal raha hai, port ' + PORT); });
