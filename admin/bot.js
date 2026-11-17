const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const BOT_TOKEN = process.env.BOT_TOKEN || 'COLLE_TON_TOKEN_BOTFATHER_ICI';
const ALLOWED_CHAT = process.env.ALLOWED_CHAT || 'COLLE_TON_IDENTIFIANT_TELEGRAM_ICI';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-moi';
const ADMIN_URL = process.env.ADMIN_URL || 'http://127.0.0.1:3001';
const SITE_URL = process.env.SITE_URL || 'http://localhost:3000';
const BANNER_PATH = path.join(__dirname, 'panel-banner.png');

if (BOT_TOKEN.startsWith('COLLE_') || ALLOWED_CHAT.startsWith('COLLE_')) {
  console.error('Configure BOT_TOKEN et ALLOWED_CHAT avant de lancer le bot.');
  process.exit(1);
}

const tg = (method, body = {}) => fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
}).then((r) => r.json());

const adm = (action, payload = {}) => fetch(`${ADMIN_URL}/admin/${action}`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${ADMIN_TOKEN}`
  },
  body: JSON.stringify(payload)
}).then((r) => r.json());

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const authToken = (mp, num) => crypto.pbkdf2Sync(mp, `auth:${num}`, 600000, 32, 'sha256').toString('hex');
const params = { '30': { days: 30, label: '30 jours', price: '2,99€' }, '90': { days: 90, label: '90 jours', price: '7,99€' } };

async function sell(key, count = 1) {
  const plan = params[key];
  if (!plan) return 'Forfait inconnu.';
  const r = await adm('create', { days: plan.days, count });
  if (!r.numbers) return 'Erreur de création.';
  const lines = r.numbers.map((num) => {
    const safeNum = num.replace(/\s/g, '');
    const mp = crypto.randomBytes(16).toString('hex');
    const token = authToken(mp, safeNum);
    return `Numéro : ${num}\nMot de passe : ${mp}\nJeton : ${token}`;
  });
  return lines.join('\n\n');
}

async function start() {
  const me = await tg('getMe');
  if (!me.ok) {
    console.error('Token invalide');
    process.exit(1);
  }
  console.log('Bot actif', me.result.username);

  let offset = 0;
  while (true) {
    const updates = await tg('getUpdates', { offset, timeout: 30 });
    if (!updates.ok) continue;
    for (const item of updates.result || []) {
      offset = item.update_id + 1;
      const msg = item.message;
      if (!msg || !msg.text) continue;
      if (String(msg.chat.id) !== String(ALLOWED_CHAT)) continue;
      const text = msg.text.trim();
      if (text === '/start') {
        await tg('sendMessage', { chat_id: msg.chat.id, text: 'SecureVault — panel de vente\n/vendre 30 1\n/vendre 90 1' });
        continue;
      }
      if (text.startsWith('/vendre')) {
        const [, key, count] = text.split(/\s+/);
        const res = await sell(key || '30', Number(count || 1));
        await tg('sendMessage', { chat_id: msg.chat.id, text: res });
      }
    }
  }
}

start();
