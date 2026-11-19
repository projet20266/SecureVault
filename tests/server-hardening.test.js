const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securevault-test-'));
const port = 38000 + Math.floor(Math.random() * 1000);
const adminPort = port + 1001;
const server = spawn(process.execPath, ['server.js'], {
  cwd: path.join(__dirname, '..'),
  env: { ...process.env, PORT: String(port), ADMIN_PORT: String(adminPort), DATA_DIR: dir, ADMIN_TOKEN: 'test-secret', REQUIRE_SUB: 'false' },
  stdio: 'ignore'
});
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
const post = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

(async () => {
  try {
    let ready = false;
    for (let i = 0; i < 50; i++) {
      try { ready = (await fetch(`http://127.0.0.1:${port}/health`)).ok; } catch {}
      if (ready) break;
      await wait(100);
    }
    assert.equal(ready, true, 'server starts');
    const id = sha('test-account'), token = sha('test-token');
    assert.equal((await post(`http://127.0.0.1:${port}/api/register`, { id, token })).status, 200);
    const blob1 = { iv: Buffer.alloc(12, 1).toString('base64'), d: Buffer.from('ciphertext-a').toString('base64') };
    let put = await post(`http://127.0.0.1:${port}/api/put`, { id, token, blob: blob1, expectedVersion: 0 });
    assert.equal(put.status, 200); assert.equal((await put.json()).version, 1);
    const blob2 = { iv: Buffer.alloc(12, 2).toString('base64'), d: Buffer.from('ciphertext-b').toString('base64') };
    put = await post(`http://127.0.0.1:${port}/api/put`, { id, token, blob: blob2, expectedVersion: 0 });
    assert.equal(put.status, 409, 'stale version is rejected');
    const history = await post(`http://127.0.0.1:${port}/api/history`, { id, token });
    assert.equal(history.status, 200); assert.equal((await history.json()).history.length, 0);
    put = await post(`http://127.0.0.1:${port}/api/put`, { id, token, blob: blob2, expectedVersion: 1 });
    assert.equal(put.status, 200);
    const versions = await post(`http://127.0.0.1:${port}/api/history`, { id, token }).then((r) => r.json());
    assert.equal(versions.history.length, 1); assert.deepEqual(versions.history[0].blob, blob1);
    assert.equal((await post(`http://127.0.0.1:${port}/admin/stats`, {})).status, 404, 'admin is not exposed on public port');
    assert.equal((await post(`http://127.0.0.1:${adminPort}/admin/stats`, {}, { Authorization: 'Bearer test-secret' })).status, 200);
    console.log('SecureVault API tests passed');
  } catch (error) {
    console.error(error); process.exitCode = 1;
  } finally {
    server.kill(); fs.rmSync(dir, { recursive: true, force: true });
  }
})();
