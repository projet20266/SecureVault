const dec = new TextDecoder();
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32 = (s) => {
  let bits = '';
  for (const c of s.replace(/[\s=-]/g, '').toUpperCase()) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error('invalid base32');
    bits += i.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
};

async function totp(secret, t = Date.now()) {
  const key = await crypto.subtle.importKey('raw', b32(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const c = Math.floor(t / 30000);
  const dv = new DataView(new ArrayBuffer(8));
  dv.setUint32(0, Math.floor(c / 4294967296));
  dv.setUint32(4, c >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, dv.buffer));
  const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1000000).padStart(6, '0');
}

async function vault(server, id, token, ek) {
  const resp = await fetch(`${server.replace(/\/$/, '')}/api/get`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, token })
  });
  if (!resp.ok) return null;
  const { blob } = await resp.json();
  if (!blob) return { items: [] };
  const key = await crypto.subtle.importKey('raw', Uint8Array.from(ek.match(/../g), (x) => parseInt(x, 16)), 'AES-GCM', false, ['decrypt']);
  const raw = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.d))));
  return Array.isArray(raw) ? { items: raw } : raw;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'need') {
    chrome.storage.session.get(['ctx']).then(async ({ ctx }) => {
      if (!ctx) return sendResponse({});
      const v = await vault(ctx.server, ctx.id, ctx.token, ctx.ek).catch(() => null);
      const items = v?.items || [];
      const host = new URL(sender.url).hostname.replace(/^www\./, '');
      const match = items.find((x) => x.n && new URL('https://' + x.n).hostname === host || x.n === host);
      if (match) sendResponse({ u: match.u, p: match.p, submit: true });
      else sendResponse({});
    });
    return true;
  }
  return false;
});
