const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.WEBHOOK_PORT || 3002);
const BTCPAY_WEBHOOK_SECRET = process.env.BTCPAY_WEBHOOK_SECRET || 'COLLE_LE_SECRET_DONNE_PAR_BTCPAY_ICI';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-moi';
const ADMIN_URL = process.env.ADMIN_URL || 'http://127.0.0.1:3001';
const SITE_URL = process.env.SITE_URL || 'http://localhost:3000';
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const PLANS = { '30': { days: 30 }, '90': { days: 90 }, 'vie': { lifetime: true } };

const adm = (action, payload = {}) => fetch(`${ADMIN_URL}/admin/${action}`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${ADMIN_TOKEN}`
  },
  body: JSON.stringify(payload)
}).then((r) => r.json());

const validSignature = (body, sigHeader) => {
  if (!sigHeader || !sigHeader.startsWith('sha256=')) return false;
  const expected = crypto.createHmac('sha256', BTCPAY_WEBHOOK_SECRET).update(body).digest('hex');
  const given = sigHeader.slice(7);
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given));
  } catch (e) {
    return false;
  }
};

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomPassword = (len = 22) => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[crypto.randomInt(chars.length)];
  return out;
};

async function deliver(planKey) {
  const plan = PLANS[planKey];
  const result = await adm('create', plan.lifetime ? { lifetime: true, count: 1 } : { days: plan.days, count: 1 });
  if (!result.numbers) return null;
  const num = result.numbers[0].replace(/\s/g, '');
  const mp = randomPassword();
  const token = crypto.pbkdf2Sync(mp, `auth:${num}`, 600000, 32, 'sha256').toString('hex');
  const claim = await fetch(`${SITE_URL}/api/claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: sha256(`silo-id:${num}`), token })
  }).then((r) => r.json());
  return claim ? { num: result.numbers[0], mp } : null;
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST' || req.url !== '/webhook/btcpay') {
    res.writeHead(404);
    res.end('not found');
    return;
  }

  let body = '';
  req.on('data', (chunk) => { body += chunk; if (body.length > 1e6) req.destroy(); });
  req.on('end', async () => {
    if (!validSignature(body, req.headers['btcpay-sig'])) {
      res.writeHead(401);
      res.end('signature invalide');
      return;
    }

    try {
      const evt = JSON.parse(body);
      const key = evt.metadata && evt.metadata.orderId;
      const delivered = await deliver(key);
      res.writeHead(200);
      res.end('ok');
      if (delivered) {
        console.log('Paiement reçu → compte livré:', delivered.num, delivered.mp);
      }
    } catch (e) {
      res.writeHead(400);
      res.end('bad json');
    }
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`Webhook listening on 127.0.0.1:${PORT}`));
