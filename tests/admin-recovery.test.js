const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securevault-recovery-'));
const port = 39000 + Math.floor(Math.random() * 500);
const adminPort = port + 700;
const child = spawn(process.execPath, ['server.js'], { cwd: path.join(__dirname, '..'), env: { ...process.env, PORT: String(port), ADMIN_PORT: String(adminPort), DATA_DIR: dir, ADMIN_TOKEN: 'test-secret', REQUIRE_SUB: 'false' }, stdio: 'ignore' });
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');
const post = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
(async () => {
 try {
  let ready = false; for (let i=0;i<60;i++){try{ready=(await fetch(`http://127.0.0.1:${port}/health`)).ok}catch{}if(ready)break;await wait(100)}
  assert.ok(ready, 'server starts');
  const number='1234567890123456', id=hash('silo-id:'+number), oldToken=hash('old'), newToken=hash('new');
  assert.equal((await post(`http://127.0.0.1:${port}/api/register`,{id,token:oldToken})).status,200);
  const iv=Buffer.alloc(12,7).toString('base64'), ciphertext=Buffer.from('encrypted-only').toString('base64');
  await post(`http://127.0.0.1:${port}/api/put`,{id,token:oldToken,blob:{iv,d:ciphertext}});
  const issued=await post(`http://127.0.0.1:${adminPort}/admin/recovery-key`,{num:number},{Authorization:'Bearer test-secret'});
  assert.equal(issued.status,200);const {key}=await issued.json();assert.ok(key);
  const redeemed=await post(`http://127.0.0.1:${port}/api/recover-reset`,{id,resetKey:key,token:newToken});
  assert.equal(redeemed.status,200);
  const login=await post(`http://127.0.0.1:${port}/api/get`,{id,token:newToken}).then(r=>r.json());assert.equal(login.blob,null,'reset destroys encrypted vault, not decrypts it');
  assert.equal((await post(`http://127.0.0.1:${port}/api/recover-reset`,{id,resetKey:key,token:hash('another')})).status,401,'key is single-use');
  assert.equal((await post(`http://127.0.0.1:${port}/api/get`,{id,token:oldToken})).status,401,'old password revoked');
  assert.equal((await post(`http://127.0.0.1:${port}/admin/recovery-key`,{num},{Authorization:'Bearer test-secret'})).status,404,'admin API hidden on public port');
  console.log('SecureVault admin recovery tests passed');
 } catch(e) { console.error(e); process.exitCode=1; }
 finally { child.kill(); fs.rmSync(dir,{recursive:true,force:true}); }
})();
