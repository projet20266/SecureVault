'use strict';
// SecureVault HTTP server. The server stores encrypted vault blobs and credential hashes only.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PORT = Number(process.env.ADMIN_PORT || 3001);
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
const ADMIN = process.env.ADMIN_TOKEN || '';
const REQUIRE_SUB = process.env.REQUIRE_SUB === 'true';
const DAY = 86400000;
const HEX = /^[a-f0-9]{64}$/;
const MAX_BODY = 2 * 1024 * 1024;
const HISTORY_LIMIT = 10;
const RESET_KEY_TTL = 60 * 1000;

fs.mkdirSync(DATA, { recursive: true, mode: 0o700 });
const headers = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
};
const file = (id) => path.join(DATA, `${id}.json`);
const load = (id) => { try { return JSON.parse(fs.readFileSync(file(id), 'utf8')); } catch { return null; } };
function save(id, record) {
  const target = file(id);
  const temp = `${target}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(record), { mode: 0o600 });
  fs.renameSync(temp, target);
}
const sha = (s) => crypto.createHash('sha256').update(s).digest();
const hx = (s) => sha(s).toString('hex');
function same(value, hash) {
  if (typeof value !== 'string' || typeof hash !== 'string' || !HEX.test(hash)) return false;
  return crypto.timingSafeEqual(sha(value), Buffer.from(hash, 'hex'));
}
function validBlob(blob) {
  if (!blob || typeof blob.iv !== 'string' || typeof blob.d !== 'string') return null;
  if (!/^[A-Za-z0-9+/]{16}$/.test(blob.iv) || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob.d) || blob.d.length > MAX_BODY) return null;
  if (Buffer.from(blob.iv, 'base64').length !== 12 || !Buffer.from(blob.d, 'base64').length) return null;
  return { iv: blob.iv, d: blob.d };
}
const send = (res, status, value = {}) => {
  if (res.headersSent) return;
  res.writeHead(status, { ...headers, 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
};
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '', tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      data += chunk;
      if (data.length > MAX_BODY) { tooLarge = true; const e = new Error('too large'); e.statusCode = 413; reject(e); }
    });
    req.on('end', () => {
      if (tooLarge) return;
      try { resolve(JSON.parse(data || '{}')); }
      catch { const e = new Error('invalid JSON'); e.statusCode = 400; reject(e); }
    });
    req.on('error', reject);
  });
}
const active = (r) => !!r.life || (!!r.exp && r.exp > Date.now());
const subInfo = (r) => ({ life: !!r.life, exp: r.exp || null, active: active(r), daysLeft: r.life ? null : Math.max(0, Math.ceil(((r.exp || 0) - Date.now()) / DAY)) });
const failures = new Map();
const blocked = (id) => { const f = failures.get(id); return !!f && f.n >= 10 && Date.now() - f.t < 900000; };
const bad = (id) => { const f = failures.get(id) || { n: 0, t: 0 }; f.n++; f.t = Date.now(); failures.set(id, f); };
const registrations = [];

async function api(req, res) {
  const b = await readBody(req);
  const action = req.url.slice('/api/'.length).split('?')[0];
  const id = String(b.id || '');
  if (!HEX.test(id)) return send(res, 400, { error: 'invalid id' });
  if (blocked(id)) return send(res, 429, { error: 'rate limited' });
  const rec = load(id);

  if (action === 'register') {
    if (REQUIRE_SUB) return send(res, 403, { error: 'registration closed' });
    if (!HEX.test(String(b.token || ''))) return send(res, 400, { error: 'invalid token' });
    const now = Date.now();
    while (registrations.length && now - registrations[0] > 3600000) registrations.shift();
    if (registrations.length >= 30) return send(res, 429, { error: 'registration limit reached' });
    if (rec) return send(res, 409, { error: 'account already exists' });
    registrations.push(now);
    save(id, { th: hx(b.token), blob: null, version: 0, history: [], ref: null, life: false, exp: now + 30 * DAY, devices: [] });
    return send(res, 200, { ok: true });
  }
  if (!rec) return send(res, 404, { error: 'account not found' });

  // One-time administrative recovery. The recovery key is stored only as a hash and
  // redemption clears the old encrypted vault, because the server cannot re-encrypt it.
  if (action === 'recover-reset') {
    if (!rec.resetKeyHash || !Number.isFinite(rec.resetKeyExpiresAt) || Date.now() >= rec.resetKeyExpiresAt || !same(b.resetKey, rec.resetKeyHash)) {
      bad(id); return send(res, 401, { error: 'invalid or expired recovery key' });
    }
    if (!HEX.test(String(b.token || ''))) return send(res, 400, { error: 'invalid token' });
    rec.th = hx(b.token);
    rec.blob = null;
    rec.history = [];
    rec.version = (rec.version || 0) + 1;
    delete rec.rth; delete rec.rw; delete rec.dth; delete rec.dblob;
    delete rec.resetKeyHash; delete rec.resetKeyExpiresAt;
    rec.devices = [];
    save(id, rec);
    failures.delete(id);
    return send(res, 200, { ok: true, vaultReset: true, version: rec.version });
  }

  if (action === 'claim') {
    if (rec.th !== null && rec.th !== undefined) return send(res, 409, { error: 'account already activated' });
    if (!HEX.test(String(b.token || ''))) return send(res, 400, { error: 'invalid token' });
    rec.th = hx(b.token); save(id, rec); return send(res, 200, { ok: true });
  }
  if (action === 'recover') {
    if (!rec.rth || !same(b.rtoken, rec.rth)) { bad(id); return send(res, 401, { error: 'invalid recovery key' }); }
    failures.delete(id); return send(res, 200, { rw: rec.rw || null, blob: rec.blob || null, version: rec.version || 0 });
  }
  if (rec.th === null || rec.th === undefined) return send(res, 423, { error: 'account not activated' });

  const real = same(b.token, rec.th);
  const duress = !real && !!rec.dth && same(b.token, rec.dth);
  if (!real && !duress) { bad(id); return send(res, 401, { error: 'unauthorized' }); }
  failures.delete(id);

  if (action === 'get') return send(res, 200, { blob: duress ? rec.dblob || null : rec.blob || null, sub: subInfo(rec), version: rec.version || 0, historyCount: duress ? 0 : (rec.history || []).length });
  if (action === 'history') {
    if (!real) return send(res, 403, { error: 'unavailable' });
    return send(res, 200, { version: rec.version || 0, history: rec.history || [] });
  }
  if (action === 'put') {
    const blob = validBlob(b.blob);
    if (!blob) return send(res, 400, { error: 'invalid encrypted blob' });
    if (!active(rec)) return send(res, 402, { error: 'subscription expired' });
    const version = rec.version || 0;
    if (b.expectedVersion !== undefined && (!Number.isSafeInteger(b.expectedVersion) || b.expectedVersion !== version)) return send(res, 409, { error: 'vault changed on another device', version });
    if (duress) rec.dblob = blob;
    else {
      if (rec.blob) { rec.history = Array.isArray(rec.history) ? rec.history : []; rec.history.push({ version, savedAt: Date.now(), blob: rec.blob }); rec.history = rec.history.slice(-HISTORY_LIMIT); }
      rec.blob = blob; rec.version = version + 1;
    }
    save(id, rec); return send(res, 200, { ok: true, version: rec.version || version });
  }
  if (action === 'setrecovery') {
    const rw = validBlob(b.rw);
    if (!HEX.test(String(b.rtoken || '')) || !rw) return send(res, 400, { error: 'invalid recovery data' });
    rec.rth = hx(b.rtoken); rec.rw = rw; save(id, rec); return send(res, 200, { ok: true });
  }
  if (action === 'setduress') {
    const dblob = validBlob(b.dblob);
    if (!real || !HEX.test(String(b.dtoken || '')) || same(b.dtoken, rec.th) || !dblob) return send(res, 400, { error: 'invalid decoy setup' });
    rec.dth = hx(b.dtoken); rec.dblob = dblob; save(id, rec); return send(res, 200, { ok: true });
  }
  if (action === 'cleaduress') { if (!real) return send(res, 403); delete rec.dth; delete rec.dblob; save(id, rec); return send(res, 200, { ok: true }); }
  if (action === 'changepw') {
    const blob = validBlob(b.blob);
    if (!real || !HEX.test(String(b.newToken || '')) || !blob) return send(res, 400, { error: 'invalid password change' });
    if (!active(rec)) return send(res, 402, { error: 'subscription expired' });
    rec.th = hx(b.newToken); rec.blob = blob; rec.version = (rec.version || 0) + 1; delete rec.rth; delete rec.rw; save(id, rec);
    return send(res, 200, { ok: true, version: rec.version });
  }
  if (action === 'delete') { if (!real) return send(res, 403); fs.rmSync(file(id), { force: true }); return send(res, 200, { ok: true }); }
  if (action === 'device') {
    if (!/^[a-f0-9]{16,64}$/.test(String(b.deviceId || ''))) return send(res, 400);
    rec.devices = (rec.devices || []).filter((d) => Date.now() - d.seen < 180 * DAY);
    let device = rec.devices.find((d) => d.id === b.deviceId); const limit = active(rec) ? 5 : 3;
    if (!device && rec.devices.length >= limit) return send(res, 409, { devices: rec.devices, limit });
    if (!device) { device = { id: b.deviceId, name: 'Appareil', kind: b.kind === 'extension' ? 'extension' : 'site', seen: Date.now() }; rec.devices.push(device); }
    else { device.seen = Date.now(); if (b.kind) device.kind = b.kind; }
    save(id, rec); return send(res, 200, { name: device.name });
  }
  if (action === 'devices') return send(res, 200, { devices: rec.devices || [], limit: active(rec) ? 5 : 3 });
  if (action === 'removedevice') { if (!real) return send(res, 403); rec.devices = (rec.devices || []).filter((d) => d.id !== b.deviceId); save(id, rec); return send(res, 200, { ok: true }); }
  return send(res, 404, { error: 'unknown action' });
}

function admin(req, res) {
  return readBody(req).then((b) => {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!ADMIN || !crypto.timingSafeEqual(sha(token), sha(ADMIN))) return send(res, 401, { error: 'unauthorized' });
    const action = req.url.split('?')[0].replace(/^\/admin\//, '');
    if (action === 'stats') return send(res, 200, { accounts: fs.readdirSync(DATA).filter((name) => name.endsWith('.json')).length });
    if (action === 'create') {
      const count = Math.min(Math.max(Number(b.count) || 1, 1), 100), days = Math.min(Math.max(Number(b.days) || 30, 1), 36500), numbers = [];
      while (numbers.length < count) {
        const num = Array.from({ length: 4 }, () => String(crypto.randomInt(10000)).padStart(4, '0')).join(''), id = hx('silo-id:' + num);
        if (load(id)) continue;
        save(id, { th: null, blob: null, version: 0, history: [], life: !!b.lifetime, exp: b.lifetime ? null : Date.now() + days * DAY, devices: [] });
        numbers.push(num.replace(/(\d{4})(?=\d)/g, '$1 '));
      }
      return send(res, 200, { numbers });
    }
    const num = String(b.num || '').replace(/\D/g, '');
    if (!/^\d{16}$/.test(num)) return send(res, 400, { error: 'invalid account number' });
    const id = hx('silo-id:' + num), rec = load(id);
    if (!rec) return send(res, 404, { error: 'account not found' });
    if (action === 'recovery-key') {
      if (rec.th === null || rec.th === undefined) return send(res, 409, { error: 'account not activated' });
      const key = crypto.randomBytes(32).toString('base64url');
      rec.resetKeyHash = hx(key); rec.resetKeyExpiresAt = Date.now() + RESET_KEY_TTL; save(id, rec);
      return send(res, 200, { key, expiresAt: rec.resetKeyExpiresAt, ttlSeconds: 60, resetsVault: true });
    }
    if (action === 'extend') {
      if (b.lifetime) { rec.life = true; rec.exp = null; }
      else { const days = Number(b.days); if (!Number.isFinite(days) || days < 1 || days > 36500) return send(res, 400); rec.exp = Math.max(Date.now(), rec.exp || 0) + days * DAY; }
      save(id, rec); return send(res, 200, subInfo(rec));
    }
    if (action === 'reset') { save(id, { th: null, blob: null, version: 0, history: [], life: !!rec.life, exp: rec.exp || null, devices: [] }); return send(res, 200, { ok: true }); }
    if (action === 'delete') { fs.rmSync(file(id), { force: true }); return send(res, 200, { ok: true }); }
    return send(res, 404, { error: 'unknown action' });
  }).catch((e) => send(res, e.statusCode || 400, { error: 'invalid request' }));
}

function serve(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'method not allowed' });
  let requested;
  try { requested = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); } catch { return send(res, 400, { error: 'bad URL' }); }
  if (requested === '/') requested = '/home.html';
  if (requested === '/app' || requested === '/app/') requested = '/index.html';
  if (requested === '/suite.html') requested = '/home.html';
  const resolved = path.resolve(PUB, '.' + requested);
  if (!resolved.startsWith(PUB + path.sep)) return send(res, 404, { error: 'not found' });
  let stat; try { stat = fs.statSync(resolved); } catch { return send(res, 404, { error: 'not found' }); }
  if (!stat.isFile()) return send(res, 404, { error: 'not found' });
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
  res.writeHead(200, { ...headers, 'Content-Type': types[path.extname(resolved).toLowerCase()] || 'application/octet-stream' });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(resolved).on('error', () => { if (!res.headersSent) send(res, 500); else res.destroy(); }).pipe(res);
}
const publicServer = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url.split('?')[0] === '/health') { res.writeHead(200, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('ok'); }
  if (req.method === 'POST' && req.url.startsWith('/api/')) { api(req, res).catch((e) => send(res, e.statusCode || 400, { error: 'invalid request' })); return; }
  if (req.url.startsWith('/admin/')) return send(res, 404, { error: 'not found' });
  serve(req, res);
});
publicServer.listen(PORT, () => console.log(`SecureVault public server listening on port ${PORT}`));
if (ADMIN) {
  http.createServer((req, res) => {
    if (req.method !== 'POST' || !req.url.startsWith('/admin/')) return send(res, 404, { error: 'not found' });
    admin(req, res).catch((e) => send(res, e.statusCode || 400, { error: 'invalid request' }));
  }).listen(ADMIN_PORT, '127.0.0.1', () => console.log(`Admin API listening on 127.0.0.1:${ADMIN_PORT}`));
}
