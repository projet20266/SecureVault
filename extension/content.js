const BTN = /connexion|se connecter|log in|sign in|continuer|suivant|validation|vérifier|verifier|submit|envoyer/i;
const match = (site, host) => {
  const s = site.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
  const h = host.toLowerCase().replace(/^www\./, '');
  return s === h || h.endsWith('.' + s);
};

const fill = (user, pass) => {
  const inputs = [...document.querySelectorAll('input')].filter((e) => {
    const style = getComputedStyle(e);
    return e.type !== 'hidden' && style.display !== 'none' && style.visibility !== 'hidden';
  });
  const pw = inputs.find((i) => i.type === 'password');
  const userField = inputs.find((i) => ['text', 'email', 'tel'].includes(i.type) && /user|login|mail|email|username|ident/i.test((i.name || '') + (i.id || '') + (i.placeholder || '')));
  if (userField) userField.value = user;
  if (pw) pw.value = pass;
};

function submitNearest(el) {
  const form = el.closest('form');
  if (form) {
    const btn = form.querySelector('button[type="submit"], input[type="submit"]');
    if (btn) btn.click();
    else form.requestSubmit?.();
    return;
  }
  const btn = [...document.querySelectorAll('button, input[type="button"]')].find((b) => BTN.test((b.textContent || b.value || '')));
  if (btn) btn.click();
}

(async () => {
  const send = (payload) => chrome.runtime.sendMessage(payload);
  const now = () => new Date().toLocaleTimeString();

  const interval = setInterval(async () => {
    try {
      const { ctx } = await chrome.storage.session.get('ctx');
      if (!ctx || !document.body) return;
      const items = (ctx.items || []).filter(Boolean);
      const host = location.hostname.replace(/^www\./, '');
      const matchItem = items.find((x) => match(x.n, host));
      if (!matchItem) return;

      const all = [...document.querySelectorAll('input')].filter((i) => {
        const s = getComputedStyle(i);
        return i.type !== 'hidden' && s.display !== 'none' && s.visibility !== 'hidden';
      });
      const password = all.find((i) => i.type === 'password');
      if (password) {
        fill(matchItem.u, matchItem.p);
        const note = document.createElement('div');
        note.textContent = 'SecureVault : identifiants remplis';
        note.style.position = 'fixed';
        note.style.bottom = '16px';
        note.style.right = '16px';
        note.style.background = '#1f2f46';
        note.style.color = '#fff';
        note.style.padding = '8px 12px';
        note.style.borderRadius = '10px';
        note.style.fontSize = '12px';
        note.style.zIndex = '999999';
        document.body.appendChild(note);
        setTimeout(() => note.remove(), 2000);
        submitNearest(password);
      }
    } catch (e) {
      // no-op
    }
  }, 1500);

  window.addEventListener('beforeunload', () => clearInterval(interval));
})();
