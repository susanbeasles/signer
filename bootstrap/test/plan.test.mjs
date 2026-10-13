import test from 'node:test';
import assert from 'node:assert/strict';
import { compilePlan, createReviewRequest, canonicalJson, parsePublicInput, publicKeyFingerprint } from '../plan.mjs';
import { exampleInput } from '../example.mjs';

test('disabled public input compiles deterministically without provider access', async () => {
  const first = await compilePlan(exampleInput());
  const second = await compilePlan(JSON.parse(JSON.stringify(exampleInput())));
  assert.deepEqual(first, second);
  assert.equal(first.mode, 'dry-run');
  assert.equal(first.execution, 'unavailable');
  assert.equal(first.operations.length, 7);
  assert.ok(first.blockers.length > 0);
  assert.equal(first.artifacts.wrangler.workers_dev, false);
  assert.equal(first.artifacts.wrangler.preview_urls, false);
  assert.deepEqual(first.artifacts.wrangler.routes, []);
  assert.equal(first.artifacts.wrangler.vars.ENABLED, 'false');
  assert.deepEqual(Object.keys(JSON.parse(first.artifacts.wrangler.vars.SIGNING_CONTROL_CONFIG_JSON)).sort(), ['platform', 'runtime', 'services']);
});

test('Cloudflare feature commissioning does not require later promotion capabilities or local custody', async () => {
  const plan = await compilePlan(exampleInput());
  assert.ok(plan.blockers.includes('unconfigured-private-binding:SOURCE_POLICY'));
  assert.ok(plan.blockers.includes('required:depot-producer-OIDC-admission'));
  assert.ok(plan.blockers.includes('required:live-resource-and-isolation-readback'));
  for (const name of ['OWNER_HARDWARE', 'SOURCE_CI', 'SOURCE_SCANS', 'SOURCE_REVIEW', 'SOURCE_INVENTORY', 'SOURCE_PUBLISHER', 'SOURCE_READ_CREDENTIAL']) {
    assert.ok(!plan.blockers.includes(`unconfigured-private-binding:${name}`));
    assert.ok(plan.promotionPrerequisites.includes(`unconfigured-private-binding:${name}`));
  }
  assert.ok(!plan.blockers.some(value => /local-source-tree|promotion-history|initial-source-commit-signing-capability/.test(value)));
  assert.ok(plan.promotionPrerequisites.includes('required:accepted-durable-promotion-history-custody'));
  const container = plan.operations.find(value => value.id === 'cloudflare.container.configure');
  assert.ok(!container.prerequisites.some(value => /local-source-tree|promotion-history/.test(value)));
});

test('canonical digest binds every public input without depending on object key order', async () => {
  const input = exampleInput();
  const first = await compilePlan(input);
  input.source.artifactSha256 = 'a'.repeat(64);
  assert.notEqual((await compilePlan(input)).digest, first.digest);
  const reversed = Object.fromEntries(Object.entries(input).reverse());
  assert.equal((await compilePlan(input)).digest, (await compilePlan(reversed)).digest);
  assert.equal(canonicalJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
});

test('closed public schema rejects secret-shaped fields and values without reflecting them', async () => {
  for (const mutate of [
    x => { x.token = 'do-not-echo-this'; },
    x => { x.onePassword.serviceAccountToken = 'do-not-echo-this'; },
    x => { x.source.repository = 'github_pat_do-not-echo-this'; },
    x => { x.github.publicKey = '-----BEGIN OPENSSH PRIVATE KEY-----do-not-echo-this'; },
  ]) {
    const input = exampleInput(); mutate(input);
    await assert.rejects(compilePlan(input), error => !error.message.includes('do-not-echo-this') && error.code === 'invalid-public-input');
  }
});

test('rejects changed account, domain, source repository and public routes', async () => {
  for (const mutate of [
    x => { x.accountID = 'f'.repeat(32); },
    x => { x.ownerOrigin = 'https://signer.vespoli.me'; },
    x => { x.source.repository = 'someone/signing-control'; },
    x => { x.source.repository = 'susanbeasles/signing-control'; },
    x => { x.routes = ['*']; },
    x => { x.runtime.enabled = true; },
    x => { x.runtime.platform.qualified = true; },
  ]) {
    const input = exampleInput(); mutate(input);
    await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
  }
});

test('review requests are operation-specific, digest-bound intents without approval authority', async () => {
  const input = exampleInput();
  const plan = await compilePlan(input);
  const request = await createReviewRequest(input, plan.digest, 'github.ssh-signing-key.register');
  assert.equal(request.kind, 'unauthenticated-review-request');
  assert.equal(request.planDigest, plan.digest);
  assert.equal(request.operationDigest, plan.operations.at(-1).digest);
  assert.equal(Object.hasOwn(request, 'approved'), false);
  assert.equal(Object.hasOwn(request, 'authorization'), false);
  assert.equal(Object.hasOwn(request, 'owner'), false);
  assert.equal(Object.hasOwn(request, 'signature'), false);
  input.source.artifactSha256 = 'b'.repeat(64);
  await assert.rejects(createReviewRequest(input, plan.digest, request.operationID), { code: 'plan-changed' });
  await assert.rejects(createReviewRequest(exampleInput(), plan.digest, 'all'), { code: 'unknown-operation' });
});

test('public key parser verifies SSH wire type and canonical encoding', async () => {
  const keyBytes = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
  const wire = Buffer.concat([Buffer.from('0000000b7373682d6564323535313900000020', 'hex'), keyBytes]);
  const key = `ssh-ed25519 ${wire.toString('base64')}`;
  const fingerprint = await publicKeyFingerprint(key);
  assert.match(fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);
  await assert.rejects(publicKeyFingerprint(key + ' comment'), { code: 'invalid-public-input' });
  await assert.rejects(publicKeyFingerprint('ssh-rsa ' + wire.toString('base64')), { code: 'invalid-public-input' });
  const bad = Buffer.from(wire); bad.writeUInt32BE(31, 15);
  await assert.rejects(publicKeyFingerprint('ssh-ed25519 ' + bad.toString('base64')), { code: 'invalid-public-input' });
});

test('malformed and oversized JSON errors do not reflect source', () => {
  for (const text of ['{"token":"do-not-echo-this",}', ' '.repeat(65537), '{"__proto__":{}}']) {
    assert.throws(() => parsePublicInput(text), error => !error.message.includes('do-not-echo-this') && error.code === 'invalid-public-input');
  }
});

test('dedicated runtime references, SSH fingerprint and approved origins must match exactly', async () => {
  const input = exampleInput();
  input.onePassword.vaultID = 'a'.repeat(26); input.onePassword.itemID = 'b'.repeat(26);
  await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
  input.runtime.runtime.opRef = `op://${input.onePassword.vaultID}/${input.onePassword.itemID}/private_key?ssh-format=openssh`;
  assert.ok((await compilePlan(input)).digest);
  for (const origin of ['http://team.1password.com', 'https://team.1password.com:443', 'https://github.com', 'https://signing-control.internal', 'https://127.0.0.1', 'https://team.1password.com/extra', 'https://u:p@team.1password.com']) {
    input.runtime.runtime.opOrigins = [origin];
    await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
  }
  input.runtime.runtime.opOrigins = ['https://synthetic.1password.com'];
  assert.ok((await compilePlan(input)).digest);
  input.runtime.services[0].signer.keyID = 'SHA256:' + 'a'.repeat(43);
  await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
});
