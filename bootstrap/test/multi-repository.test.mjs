import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { exampleInput } from '../example.mjs';
import { canonicalJson, compilePlan, createReviewRequest } from '../plan.mjs';
import { completePublicFixture } from './public-fixture.mjs';

test('one disabled image covers the seven explicitly recorded target repository identities', async () => {
  const input = exampleInput();
  assert.deepEqual(input.runtime.services.map(({ repository, repositoryID }) => [repository, repositoryID]), [
    ['susanbeasles/ProsRUs',1412827677], ['susanbeasles/personal-control',1408909065],
    ['susanbeasles/backup-control',1407276404], ['susanbeasles/ghcaretaker',1405513776],
    ['susanbeasles/workflow_depot',1405415683], ['susanbeasles/delivery_control',1405415291],
    ['susanbeasles/repoctl',1404914851],
  ]);
  const plan = await compilePlan(input);
  assert.deepEqual(plan.artifacts.imageRuntimeConfig, { services: input.runtime.services, runtime: input.runtime.runtime });
  assert.deepEqual(plan.artifacts.publicRuntimeConfig, input.runtime);
  assert.equal(plan.artifacts.wrangler.vars.ENABLED, 'false');
  assert.equal(input.source.repositoryID, null);
});

test('installation and each projected repository job digest bind the exact service allowlist', async () => {
  const input = await completePublicFixture(), first = await compilePlan(input);
  assert.equal(first.configDigest, createHash('sha256').update(canonicalJson(input.runtime)).digest('hex'));
  for (const service of input.runtime.services) {
    const projected = { service, runtime: input.runtime.runtime, platform: input.runtime.platform };
    assert.equal(first.repositoryConfigDigests[String(service.repositoryID)], createHash('sha256').update(canonicalJson(projected)).digest('hex'));
  }
  input.runtime.services[1].git.maxObjects--;
  const changed = await compilePlan(input);
  assert.notEqual(changed.configDigest, first.configDigest);
  assert.notEqual(changed.artifactDigests.imageRuntimeConfig, first.artifactDigests.imageRuntimeConfig);
  assert.notEqual(changed.repositoryConfigDigests[String(input.runtime.services[1].repositoryID)], first.repositoryConfigDigests[String(input.runtime.services[1].repositoryID)]);
  await assert.rejects(createReviewRequest(input, first.digest, 'cloudflare.container.configure'), { code: 'plan-changed' });
});

test('duplicate, unbounded, foreign and differently keyed repository entries fail closed', async () => {
  for (const change of [
    x => { x.runtime.services = []; },
    x => { x.runtime.services.push(structuredClone(x.runtime.services[0])); },
    x => { x.runtime.services[1].repositoryID = x.runtime.services[0].repositoryID; },
    x => { x.runtime.services[1].repository = x.runtime.services[0].repository; },
    x => { x.runtime.services[1].signer.keyID = 'SHA256:' + 'A'.repeat(43); },
    x => { x.runtime.services[1].repository = 'unapproved/repository'; },
    x => { x.runtime.services[1].repositoryID = '1408909065'; },
    x => { x.runtime.services[1].extra = true; },
    x => { x.runtime.services = Array.from({length:33}, (_, i) => ({...x.runtime.services[0], repositoryID:i+1, repository:'susanbeasles/fixture-'+i})); },
  ]) {
    const input = await completePublicFixture(); change(input);
    await assert.rejects(compilePlan(input), { code:'invalid-public-input' });
  }
});
