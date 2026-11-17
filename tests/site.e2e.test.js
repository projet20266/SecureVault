const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const tmp = '/tmp/silo-e2e';
fs.rmSync(tmp, { recursive: true, force: true });

const srv = spawn('node', ['server.js'], {
  env: { ...process.env, PORT: '3411', DATA_DIR: tmp },
  cwd: path.join(__dirname, '..')
});

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  await wait(700);
  const r = await fetch('http://localhost:3411/health');
  console.log('status', r.status);
  srv.kill();
})();
