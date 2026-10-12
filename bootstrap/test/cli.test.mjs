import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { exampleInput } from '../example.mjs';
import { compilePlan } from '../plan.mjs';
const cli = new URL('../cli.mjs', import.meta.url).pathname;
const run = args => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 5000, env: { PATH: '/usr/bin:/bin' } });

test('CLI emits exact local artifacts and never overwrites prior output', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'signing-bootstrap-test-'));
  try {
    const input = join(temp, 'public.json'), out = join(temp, 'plan');
    await writeFile(input, JSON.stringify(exampleInput()));
    const result = run(['plan', '--input', input, '--out', out]);
    assert.equal(result.status, 0, result.stderr);
    const compiled = await compilePlan(exampleInput());
    assert.deepEqual(JSON.parse(await readFile(join(out, 'bootstrap-plan.json'), 'utf8')), compiled);
    assert.deepEqual((await readdir(out)).sort(), ['bootstrap-plan.json', 'image-runtime-config.json', 'public-runtime-config.json', 'wrangler.bootstrap.json']);
    for (const [file, artifact] of [['wrangler.bootstrap.json', 'wrangler'], ['public-runtime-config.json', 'publicRuntimeConfig'], ['image-runtime-config.json', 'imageRuntimeConfig']]) {
      assert.equal(createHash('sha256').update(await readFile(join(out, file))).digest('hex'), compiled.artifactDigests[artifact]);
    }
    assert.notEqual(run(['plan', '--input', input, '--out', out]).status, 0);
    assert.deepEqual(JSON.parse(await readFile(join(out, 'bootstrap-plan.json'), 'utf8')), compiled);
    assert.notEqual(run(['apply', '--input', input]).status, 0);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('CLI refuses invalid public input without printing input or JSON parse errors', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'signing-bootstrap-test-'));
  try {
    const input = join(temp, 'public.json');
    await writeFile(input, '{"secret":"do-not-echo-me",}');
    const result = run(['plan', '--input', input, '--out', join(temp, 'plan')]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Public configuration is invalid/);
    assert.doesNotMatch(result.stdout + result.stderr, /do-not-echo-me|SyntaxError/);
    assert.deepEqual(await readdir(temp), ['public.json']);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('CLI makes a single digest-bound review request and self-contained offline UI', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'signing-bootstrap-test-'));
  try {
    const input = join(temp, 'public.json'), review = join(temp, 'review.json'), html = join(temp, 'review.html');
    await writeFile(input, JSON.stringify(exampleInput()));
    const plan = await compilePlan(exampleInput());
    const result = run(['review', '--input', input, '--plan-digest', plan.digest, '--operation', 'github.ssh-signing-key.register', '--out', review]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(await readFile(review)).kind, 'unauthenticated-review-request');
    assert.equal(run(['render', '--out', html]).status, 0);
    const body = await readFile(html, 'utf8');
    assert.match(body, /connect-src 'none'/);
    assert.doesNotMatch(body, /<script[^>]+src=|<link[^>]+href=|import .*from/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});
