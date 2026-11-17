const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const WAIT = 600;
const tmp = '/tmp/silo-server-test';
fs.rmSync(tmp, { recursive: true, force: true });

const srv = spawn('node', ['server.js'], {
  env: { ...process.env, PORT: '3211', ADMIN_PORT: '3212', DATA_DIR: tmp, ADMIN_TOKEN: 'secret' },
  cwd: path.join(__dirname, '..')
});

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  await wait(WAIT);
  const r = await fetch('http://localhost:3211/health');
  console.log('health', r.status, await r.text());
  srv.kill();
})();
