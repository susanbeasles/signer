import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { request } from 'node:http';
import { once } from 'node:events';

test('preview serves only fixed loopback assets and rejects writes, rebinding and filesystem paths', { timeout: 10000 }, async () => {
  const reserve = createServer(); await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const child = spawn(process.execPath, [new URL('../cli.mjs', import.meta.url).pathname, 'preview', '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin' } });
  const exited = once(child, 'exit');
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(Error('preview startup deadline')), 5000);
      child.stdout.once('data', () => { clearTimeout(timer); resolve(); });
      child.once('exit', () => { clearTimeout(timer); reject(Error('preview exited before ready')); });
    });
    const call = (path, method = 'GET', host = `127.0.0.1:${port}`) => new Promise((resolve, reject) => {
      const req = request({ hostname: '127.0.0.1', port, path, method, headers: { host }, timeout: 2000 }, response => {
        const parts = []; response.on('data', part => parts.push(part));
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text: Buffer.concat(parts).toString('utf8') }));
      });
      req.on('error', reject); req.on('timeout', () => req.destroy(Error('request timeout'))); req.end();
    });
    const page = await call('/'); assert.equal(page.status, 200); assert.match(page.text, /Apply disabled/);
    assert.match(page.headers['content-security-policy'], /connect-src 'none'/); assert.equal(page.headers['cache-control'], 'no-store');
    assert.equal((await call('/plan.mjs')).status, 200);
    const parser = await call('/src/service/op-reference.mjs');
    assert.equal(parser.status, 200); assert.match(parser.text, /parseSSHKeyReference/);
    assert.equal((await call('/src/service/source.mjs')).status, 404);
    assert.equal((await call('/../package.json')).status, 404);
    assert.equal((await call('/plan.mjs?input=anything')).status, 404);
    assert.equal((await call('/', 'POST')).status, 403);
    assert.equal((await call('/', 'GET', 'outside.example')).status, 403);
    assert.equal((await call('/', 'HEAD')).text, '');
  } finally { child.kill('SIGTERM'); await exited; }
});
