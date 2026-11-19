'use strict';
// Private Telegram admin helper. It can issue a one-minute reset key, never read vault contents.
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ALLOWED_CHAT = process.env.ALLOWED_CHAT || '';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const ADMIN_URL = process.env.ADMIN_URL || 'http://127.0.0.1:3001';

async function tg(method, body) {
  const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await r.json();
  if (!r.ok || !data.ok) throw new Error('Telegram API request failed');
  return data;
}
async function admin(action, payload) {
  const r = await fetch(`${ADMIN_URL}/admin/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ADMIN_TOKEN}` }, body: JSON.stringify(payload) });
  return { status: r.status, ...(await r.json().catch(() => ({}))) };
}
async function issueResetKey(accountNumber) {
  const number = String(accountNumber || '').replace(/\D/g, '');
  if (!/^\d{16}$/.test(number)) return { error: 'Le numéro doit contenir 16 chiffres.' };
  const result = await admin('recovery-key', { num: number });
  if (result.status !== 200) return { error: result.status === 404 ? 'Compte introuvable.' : 'Impossible de créer une clé (compte non activé ou erreur serveur).' };
  return { key: result.key, expiresAt: result.expiresAt, ttlSeconds: result.ttlSeconds };
}
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function start() {
  if (!BOT_TOKEN || !ALLOWED_CHAT || !ADMIN_TOKEN) throw new Error('Configure BOT_TOKEN, ALLOWED_CHAT et ADMIN_TOKEN dans l’environnement.');
  const me = await tg('getMe', {});
  console.log(`Bot SecureVault actif (@${me.result.username}).`);
  let offset = 0;
  while (true) {
    try {
      const updates = await tg('getUpdates', { offset, timeout: 25 });
      for (const update of updates.result || []) {
        offset = update.update_id + 1;
        const m = update.message;
        if (!m || !m.text) continue;
        // Deny group use and require both the private chat and sender to match the configured owner.
        if (m.chat.type !== 'private' || String(m.chat.id) !== String(ALLOWED_CHAT) || String(m.from && m.from.id) !== String(ALLOWED_CHAT)) continue;
        const [command, account] = m.text.trim().split(/\s+/);
        if (command === '/start' || command === '/help') {
          await tg('sendMessage', { chat_id: m.chat.id, text: 'SecureVault — récupération administrée\n\n/who <numéro> génère une clé de réinitialisation valable 60 secondes.\n\nLa validation efface définitivement le coffre chiffré existant : le serveur ne peut pas le déchiffrer. Le bot ne révèle jamais de mots de passe.' });
        } else if (command === '/who') {
          const result = await issueResetKey(account);
          const text = result.key
            ? `Clé temporaire (valide 60 secondes) :\n${result.key}\n\nÀ transmettre uniquement au titulaire. S'il l'utilise sur /recover.html, son mot de passe sera remplacé et l'ancien coffre sera effacé. Cette clé ne permet pas de lire les mots de passe.`
            : result.error;
          await tg('sendMessage', { chat_id: m.chat.id, text });
        } else {
          await tg('sendMessage', { chat_id: m.chat.id, text: 'Commande inconnue. Utilise /who <numéro> ou /help.' });
        }
      }
    } catch (error) {
      console.error('Erreur temporaire du bot Telegram.');
      await wait(3000);
    }
  }
}

if (require.main === module) start().catch((error) => { console.error(error.message); process.exitCode = 1; });
module.exports = { issueResetKey, start };
