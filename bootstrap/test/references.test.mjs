import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { compilePlan, createReviewRequest, publicKeyFingerprint, validatePublicInput } from '../plan.mjs';
import { validateSignerConfig } from '../../runtime/op-git-signer.mjs';
import { completePublicFixture } from './public-fixture.mjs';

const reference = (vault, item, field = 'private_key', section = null) => `op://${vault}/${item}/${section ? section + '/' : ''}${field}?ssh-format=openssh`;
async function fixture() {
  const input = await completePublicFixture();
  input.onePassword.vaultName = 'Reviewed runtime vault';
  input.onePassword.itemName = 'gh-signing-key';
  input.runtime.runtime.opRef = reference(input.onePassword.vaultID, input.onePassword.itemID);
  return input;
}

test('configurable vault and vendor-scope-credentialType item names remain display metadata', async () => {
  const input = await fixture(), first = await compilePlan(input);
  assert.deepEqual(validateSignerConfig(first.artifacts.publicRuntimeConfig.runtime), input.runtime.runtime);
  assert.equal(first.operations.find(x => x.id === 'onepassword.item-reference.bind').payload.itemName, 'gh-signing-key');
  input.onePassword.vaultName = 'Second reviewed vault label'; input.onePassword.itemName = 'github-source-signing-key';
  const renamed = await compilePlan(input);
  assert.notEqual(renamed.digest, first.digest);
  assert.equal(renamed.configDigest, first.configDigest);
  for (const itemName of ['', 'gh-key', 'gh signing key', '-gh-signing-key', 'gh--signing-key', 'GH-signing-key']) {
    input.onePassword.itemName = itemName;
    await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
  }
});

test('explicit field and optional section identifiers compose with the actual runtime validator', async () => {
  const input = await fixture();
  for (const [section, field] of [[null, 'private_key'], [null, 'd'.repeat(26)], ['extraDetails', 'private_key'], ['e'.repeat(26), 'f'.repeat(26)]]) {
    input.runtime.runtime.opRef = reference(input.onePassword.vaultID, input.onePassword.itemID, field, section);
    const plan = await compilePlan(input);
    assert.equal(validateSignerConfig(plan.artifacts.publicRuntimeConfig.runtime).opRef, input.runtime.runtime.opRef);
  }
  for (const suffix of ['private key?ssh-format=openssh', 'private_key', 'private_key?ssh-format=pem', 'private_key?ssh-format=openssh&x=1', '../private_key?ssh-format=openssh', '%70rivate_key?ssh-format=openssh', 'a/b/c?ssh-format=openssh', '/private_key?ssh-format=openssh', 'private_key?ssh-format=openssh#x']) {
    input.runtime.runtime.opRef = `op://${input.onePassword.vaultID}/${input.onePassword.itemID}/${suffix}`;
    await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
    assert.throws(() => validateSignerConfig(input.runtime.runtime));
  }
});

test('vault, item, field and section rebindings invalidate config and operation review digests', async () => {
  const original = await fixture(), first = await compilePlan(original);
  for (const identity of ['vaultID', 'itemID', 'field', 'section']) {
    const input = structuredClone(original);
    if (['vaultID', 'itemID'].includes(identity)) {
      input.onePassword[identity] = 'g'.repeat(26);
      await assert.rejects(compilePlan(input), { code: 'invalid-public-input' });
    }
    input.runtime.runtime.opRef = reference(input.onePassword.vaultID, input.onePassword.itemID, identity === 'field' ? 'another_key' : 'private_key', identity === 'section' ? 'extraDetails' : null);
    const rebound = await compilePlan(input);
    assert.notEqual(rebound.configDigest, first.configDigest);
    assert.notEqual(rebound.digest, first.digest);
    await assert.rejects(createReviewRequest(input, first.digest, 'onepassword.item-reference.bind'), { code: 'plan-changed' });
  }
});

test('actual review form preserves explicit references and refuses missing field selection', async () => {
  const source = await readFile(new URL('../review.mjs', import.meta.url), 'utf8');
  const body = source.slice(source.indexOf('async function inputFromForm() {'), source.indexOf('\nfunction download('));
  const set = (object, path, value) => { const parts = path.split('.'), key = parts.pop(); parts.reduce((value, part) => value[part], object)[key] = value; };
  const input = await fixture();
  const document = { querySelectorAll: () => [{ dataset: { path: 'runtime.runtime.opRef' }, value: input.runtime.runtime.opRef }] };
  const read = new Function('publicInput', 'document', 'set', 'publicKeyFingerprint', 'validatePublicInput', body + '; return inputFromForm();');
  assert.equal((await read(input, document, set, publicKeyFingerprint, validatePublicInput)).runtime.runtime.opRef, input.runtime.runtime.opRef);
  document.querySelectorAll = () => [{ dataset: { path: 'runtime.runtime.opRef' }, value: '' }];
  await assert.rejects(read(input, document, set, publicKeyFingerprint, validatePublicInput), { code: 'invalid-public-input' });
});
