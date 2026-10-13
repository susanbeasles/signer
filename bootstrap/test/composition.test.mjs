import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { posix } from 'node:path';
import { completePublicFixture } from './public-fixture.mjs';
import { canonicalJson, compilePlan } from '../plan.mjs';
import { validateConfiguration, configDigest } from '../../cloudflare/controller.mjs';
import { validateSignerConfig } from '../../runtime/op-git-signer.mjs';
import { validateImageConfiguration, validateImageService } from '../../runtime/handoff.mjs';
import { validateGitConfig } from '../../src/service/source.mjs';


test('compiled public config composes with actual controller and signer validators', async () => {
  const input = await completePublicFixture();
  const plan = await compilePlan(input);
  const config = plan.artifacts.publicRuntimeConfig;
  for (const service of config.services) {
    const selected = { service, runtime: config.runtime, platform: config.platform };
    assert.deepEqual(validateConfiguration(selected), selected);
    assert.deepEqual(validateImageService(selected, plan.artifacts.imageRuntimeConfig), selected);
    assert.equal(configDigest(selected), plan.repositoryConfigDigests[String(service.repositoryID)]);
    assert.deepEqual(validateGitConfig(service.git), service.git);
  }
  assert.deepEqual(validateImageConfiguration(plan.artifacts.imageRuntimeConfig), plan.artifacts.imageRuntimeConfig);
  assert.deepEqual(validateSignerConfig(config.runtime), config.runtime);
  assert.deepEqual(JSON.parse(plan.artifacts.wrangler.vars.SIGNING_CONTROL_CONFIG_JSON), config);
  assert.deepEqual(plan.artifacts.imageRuntimeConfig, { services: config.services, runtime: config.runtime });
  assert.equal(Object.hasOwn(plan.artifacts.imageRuntimeConfig, 'platform'), false);
  assert.equal(plan.artifacts.wrangler.vars.ENABLED, 'false');
  assert.ok(plan.blockers.includes('required:depot-producer-OIDC-admission'));
  assert.ok(plan.blockers.some(value => value.startsWith('unconfigured-private-binding:')));
  assert.equal(plan.blockers.some(value => value.startsWith('missing:')), false);
});
test('target ID is numeric and distinct from source metadata; reject lossy conversions and wrong reference IDs', async () => {
  const input = await completePublicFixture();
  input.runtime.services[0].repository = 'susanbeasles/fixture'; input.runtime.services[0].repositoryID = 123456;
  assert.ok((await compilePlan(input)).digest);
  for (const id of ['1405513776', 0, -1, Number.MAX_SAFE_INTEGER + 1]) {
    input.runtime.services[0].repositoryID = id;
    await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
  }
  input.runtime.services[0].repositoryID = 123456;
  for (const service of input.runtime.services) service.git.authenticated = false;
  assert.equal((await compilePlan(input)).promotionPrerequisites.includes('unconfigured-private-binding:SOURCE_READ_CREDENTIAL'), false);
  input.runtime.services[0].git.authenticated = true;
  input.onePassword.vaultID = '0'.repeat(26);
  await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
});

test('generated deployment shape matches the maintained private Wrangler configuration', async () => {
  const input = await completePublicFixture();
  const plan = await compilePlan(input);
  const maintained = JSON.parse(await readFile(new URL('../../cloudflare/wrangler.jsonc', import.meta.url), 'utf8'));
  const expected = {
    ...maintained,
    main: posix.join('cloudflare', maintained.main),
    account_id: input.accountID,
    vars: { ...maintained.vars, SIGNING_CONTROL_CONFIG_JSON: canonicalJson(input.runtime) },
    containers: maintained.containers.map(container => ({ ...container, image: `registry.cloudflare.com/${input.accountID}/signing-control@${input.runtime.platform.imageDigest}` })),
  };
  assert.deepEqual(plan.artifacts.wrangler, expected);
});
