// Silo : serveur sans dépendance et sans journal.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PORT = Number(process.env.ADMIN_PORT || 3001);
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
const ADMIN = process.env.ADMIN_TOKEN || '';
const DAY = 86400000;
const HEX = /^[a-f0-9]{64}$/;

fs.mkdirSync(DATA, { recursive: true });

const jsonHeaders = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
};

const file = (id) => path.join(DATA, `${id}.json`);
const load = (id) => {
  try {
    return JSON.parse(fs.readFileSync(file(id), 'utf8'));
  } catch (e) {
    return null;
  }
};
const save = (id, data) => fs.writeFileSync(file(id), JSON.stringify(data));
const sha = (s) => crypto.createHash('sha256').update(s).digest();
const hx = (s) => sha(s).toString('hex');
const same = (token, hash) => {
  try {
    return crypto.timingSafeEqual(sha(token), Buffer.from(hash, 'hex'));
  } catch (e) {
    return false;
  }
};
const okBlob = (b) => b && typeof b.iv === 'string' && typeof b.d === 'string' ? { iv: b.iv, d: b.d } : null;
const sendJSON = (res, status, obj = {}) => {
  res.writeHead(status, { ...jsonHeaders, 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};

const body = (req) => new Promise((resolve, reject) => {
  let data = '';
  req.on('data', (chunk) => {
    data += chunk;
    if (data.length > 2e6) {
      req.destroy();
      reject(new Error('payload too large'));
    }
  });
  req.on('end', () => {
    try {
      resolve(JSON.parse(data || '{}'));
    } catch (e) {
      resolve({});
    }
  });
});

const fails = new Map();
const blocked = (id) => {
  const f = fails.get(id);
  return !!f && f.n >= 10 && Date.now() - f.t < 900000;
};
const bad = (id) => {
  const f = fails.get(id) || { n: 0, t: 0 };
  f.n += 1;
  f.t = Date.now();
  fails.set(id, f);
};

const subInfo = (rec) => ({
  life: !!rec.life,
  exp: rec.exp || null,
  active: !!rec.life || (rec.exp && rec.exp > Date.now()),
  daysLeft: rec.life ? null : Math.max(0, Math.ceil(((rec.exp || 0) - Date.now()) / DAY))
});

function api(req, res) {
  return body(req).then(async (b) => {
    const url = req.url || '/';
    const act = url.startsWith('/api/') ? url.slice(5) : url;
    const id = String(b.id || '');

    if (act === 'health') {
      res.writeHead(200, { ...jsonHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('ok');
      return;
    }

    if (!HEX.test(id)) {
      sendJSON(res, 400, { error: 'invalid id' });
      return;
    }

    if (blocked(id)) {
      sendJSON(res, 429, { error: 'blocked' });
      return;
    }

    const rec = load(id);

    if (act === 'register') {
      if (!HEX.test(String(b.token || '')) || rec) {
        sendJSON(res, 403, { error: 'register forbidden' });
        return;
      }
      const now = Date.now();
      save(id, {
        th: hx(String(b.token)),
        blob: null,
        ref: b.ref || null,
        createdAt: now,
        refGiven: false,
        life: false,
        exp: now + 30 * DAY,
        devices: []
      });
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (!rec) {
      sendJSON(res, 404, { error: 'not found' });
      return;
    }

    if (act === 'claim') {
      if (rec.th && rec.th !== null) {
        sendJSON(res, 409, { error: 'already claimed' });
        return;
      }
      if (!HEX.test(String(b.token || ''))) {
        sendJSON(res, 400, { error: 'invalid token' });
        return;
      }
      rec.th = hx(String(b.token));
      if (b.ref && b.ref !== id && load(b.ref)) {
        rec.ref = b.ref;
      }
      save(id, rec);
      sendJSON(res, 200, { ok: true });
      return;
    }

    const isReal = HEX.test(String(b.token || '')) && same(b.token, rec.th || '');
    const isDuress = !isReal && !!rec.dth && HEX.test(String(b.token || '')) && same(b.token, rec.dth || '');

    if (!isReal && !isDuress) {
      bad(id);
      sendJSON(res, 401, { error: 'unauthorized' });
      return;
    }

    fails.delete(id);

    if (act === 'get') {
      sendJSON(res, 200, {
        blob: isDuress ? rec.dblob || null : rec.blob || null,
        sub: subInfo(rec)
      });
      return;
    }

    if (act === 'put') {
      const nb = okBlob(b.blob);
      if (!nb) {
        sendJSON(res, 400, { error: 'invalid blob' });
        return;
      }
      if (!rec.life && rec.exp && rec.exp <= Date.now()) {
        sendJSON(res, 402, { error: 'subscription expired' });
        return;
      }
      if (isDuress) {
        rec.dblob = nb;
      } else {
        rec.blob = nb;
      }
      save(id, rec);
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (act === 'setrecovery') {
      if (!HEX.test(String(b.rtoken || ''))) {
        sendJSON(res, 400, { error: 'invalid rtoken' });
        return;
      }
      const nw = okBlob(b.rw);
      if (!nw) {
        sendJSON(res, 400, { error: 'invalid recovery blob' });
        return;
      }
      rec.rth = hx(String(b.rtoken));
      rec.rw = nw;
      save(id, rec);
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (act === 'recover') {
      if (!rec.rth || !HEX.test(String(b.rtoken || '')) || !same(b.rtoken, rec.rth)) {
        bad(id);
        sendJSON(res, 401, { error: 'bad recovery token' });
        return;
      }
      sendJSON(res, 200, { rw: rec.rw, blob: rec.blob });
      return;
    }

    if (act === 'reset') {
      if (!rec.rth || !HEX.test(String(b.rtoken || '')) || !same(b.rtoken, rec.rth)) {
        sendJSON(res, 401, { error: 'bad recovery token' });
        return;
      }
      const nb = okBlob(b.blob);
      const nw = okBlob(b.rw);
      if (!HEX.test(String(b.token || '')) || !nb || !nw) {
        sendJSON(res, 400, { error: 'invalid reset payload' });
        return;
      }
      rec.th = hx(String(b.token));
      rec.blob = nb;
      rec.rw = nw;
      delete rec.rth;
      save(id, rec);
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (act === 'changepw') {
      if (!HEX.test(String(b.newToken || ''))) {
        sendJSON(res, 400, { error: 'invalid token' });
        return;
      }
      const nb = okBlob(b.blob);
      if (!nb) {
        sendJSON(res, 400, { error: 'invalid blob' });
        return;
      }
      if (!rec.life && rec.exp && rec.exp <= Date.now()) {
        sendJSON(res, 402, { error: 'subscription expired' });
        return;
      }
      rec.th = hx(String(b.newToken));
      rec.blob = nb;
      delete rec.rth;
      delete rec.rw;
      save(id, rec);
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (act === 'device') {
      const deviceId = String(b.deviceId || '');
      if (!/^[a-f0-9]{16,64}$/.test(deviceId)) {
        sendJSON(res, 400, { error: 'bad device id' });
        return;
      }
      rec.devices = rec.devices || [];
      const now = Date.now();
      rec.devices = rec.devices.filter((d) => now - d.seen < 180 * DAY);
      let d = rec.devices.find((x) => x.id === deviceId);
      const limit = rec.life ? 5 : 3;
      if (!d) {
        if (rec.devices.length >= limit) {
          sendJSON(res, 409, { devices: rec.devices, limit });
          return;
        }
        d = { id: deviceId, name: 'Appareil', kind: b.kind || 'site', seen: now };
        rec.devices.push(d);
      } else {
        d.seen = now;
        if (b.kind) d.kind = b.kind;
      }
      save(id, rec);
      sendJSON(res, 200, { ok: true, name: d.name });
      return;
    }

    if (act === 'devices') {
      rec.devices = (rec.devices || []).filter((d) => Date.now() - d.seen < 180 * DAY);
      save(id, rec);
      sendJSON(res, 200, { devices: rec.devices, limit: rec.life ? 5 : 3 });
      return;
    }

    if (act === 'removedevice') {
      rec.devices = (rec.devices || []).filter((d) => d.id !== String(b.deviceId || ''));
      save(id, rec);
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (act === 'delete') {
      fs.unlinkSync(file(id));
      sendJSON(res, 200, { ok: true });
      return;
    }

    sendJSON(res, 404, { error: 'not found' });
  });
}

function admin(req, res) {
  return body(req).then(async (b) => {
    const url = req.url || '/';
    const act = url.startsWith('/admin/') ? url.slice(7) : url;
    const auth = (req.headers.authorization || '').replace(/^Bearer /, '');

    if (!ADMIN || auth !== ADMIN) {
      sendJSON(res, 401, { error: 'unauthorized' });
      return;
    }

    if (act === 'stats') {
      const files = fs.readdirSync(DATA).filter((f) => f.endsWith('.json'));
      sendJSON(res, 200, { accounts: files.length });
      return;
    }

    if (act === 'create') {
      const count = Math.min(Math.max(Number(b.count || 1), 1), 100);
      const days = Number(b.days || 30);
      const out = [];
      for (let i = 0; i < count; i++) {
        let num = Array.from({ length: 4 }, () => String(Math.floor(Math.random() * 10000)).padStart(4, '0')).join(' ');
        const idNum = hx(`silo-id:${num.replace(/\s/g, '')}`);
        if (load(idNum)) {
          i--; continue;
        }
        save(idNum, { th: null, blob: null, life: !!b.lifetime, exp: b.lifetime ? null : Date.now() + days * DAY, createdAt: Date.now(), devices: [] });
        out.push(num);
      }
      sendJSON(res, 200, { numbers: out });
      return;
    }

    if (act === 'extend') {
      const num = String(b.num || '').replace(/\D/g, '');
      const id = hx(`silo-id:${num}`);
      const rec = load(id);
      if (!rec) {
        sendJSON(res, 404, { error: 'not found' });
        return;
      }
      if (b.lifetime) {
        rec.life = true;
        rec.exp = null;
      } else {
        const value = Number(b.days || 30);
        rec.exp = Math.max(Date.now(), rec.exp || Date.now()) + value * DAY;
        rec.life = false;
      }
      save(id, rec);
      sendJSON(res, 200, subInfo(rec));
      return;
    }

    if (act === 'reset') {
      const num = String(b.num || '').replace(/\D/g, '');
      const id = hx(`silo-id:${num}`);
      const rec = load(id);
      if (!rec) {
        sendJSON(res, 404, { error: 'not found' });
        return;
      }
      save(id, { th: null, blob: null, life: rec.life || false, exp: rec.exp || null, createdAt: Date.now(), devices: [] });
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (act === 'delete') {
      const num = String(b.num || '').replace(/\D/g, '');
      const id = hx(`silo-id:${num}`);
      if (load(id)) {
        fs.unlinkSync(file(id));
      }
      sendJSON(res, 200, { ok: true });
      return;
    }

    sendJSON(res, 404, { error: 'unknown admin action' });
  });
}

const safeServe = (req, res) => {
  const raw = req.url.split('?')[0];
  let requested = raw === '/' ? '/home.html' : raw;
  if (requested === '/app') requested = '/index.html';
  if (requested === '/app/') requested = '/index.html';
  if (requested === '/suite.html') requested = '/home.html';

  const normalized = path.normalize(path.join(PUB, requested));
  if (!normalized.startsWith(PUB + path.sep) && normalized !== PUB) {
    sendJSON(res, 404, { error: 'not found' });
    return;
  }

  const ext = path.extname(normalized).toLowerCase();
  const typeMap = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.json': 'application/json; charset=utf-8'
  };

  if (!fs.existsSync(normalized) || fs.statSync(normalized).isDirectory()) {
    sendJSON(res, 404, { error: 'not found' });
    return;
  }

  res.writeHead(200, { ...jsonHeaders, 'Content-Type': typeMap[ext] || 'application/octet-stream' });
  fs.createReadStream(normalized).pipe(res);
};

http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url.startsWith('/api/')) {
      await api(req, res);
      return;
    }
    if (req.url === '/health') {
      res.writeHead(200, { ...jsonHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('ok');
      return;
    }
    if (req.method === 'POST' && req.url.startsWith('/admin/')) {
      await admin(req, res);
      return;
    }
    safeServe(req, res);
  } catch (e) {
    sendJSON(res, 500, { error: 'internal server error' });
  }
}).listen(PORT, () => {
  console.log(`SecureVault running on http://localhost:${PORT}`);
});

if (ADMIN) {
  http.createServer(async (req, res) => {
    try {
      if (req.method === 'POST' && req.url.startsWith('/admin/')) {
        await admin(req, res);
        return;
      }
      sendJSON(res, 404, { error: 'not found' });
    } catch (e) {
      sendJSON(res, 500, { error: 'internal server error' });
    }
  }).listen(ADMIN_PORT, '127.0.0.1', () => {
    console.log(`Admin API listening on http://127.0.0.1:${ADMIN_PORT}`);
  });
}
