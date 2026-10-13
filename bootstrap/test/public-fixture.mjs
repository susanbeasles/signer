import { exampleInput } from '../example.mjs';
import { publicKeyFingerprint } from '../plan.mjs';

export async function completePublicFixture() {
  const input = exampleInput();
  input.source.repositoryID = '123456'; input.source.commit = 'c'.repeat(40); input.source.artifactSha256 = 'd'.repeat(64);
  input.onePassword = { accountDomain: 'synthetic.1password.com', vaultName: 'Reviewed fixture vault', itemName: 'gh-signing-key', vaultID: 'a'.repeat(26), itemID: 'b'.repeat(26), serviceAccountID: 'c'.repeat(26) };
  // RFC 8032 public test vector. No private key or generated credential.
  input.github.publicKey = 'ssh-ed25519 ' + Buffer.from('0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex').toString('base64');
  const fingerprint = await publicKeyFingerprint(input.github.publicKey);
  for (const service of input.runtime.services) { service.git.sha256 = 'e'.repeat(64); service.signer.keyID = fingerprint; }
  Object.assign(input.runtime.runtime, { publicKey: input.github.publicKey, keyID: fingerprint, opRef: `op://${input.onePassword.vaultID}/${input.onePassword.itemID}/private_key?ssh-format=openssh`, opOrigins: ['https://synthetic.1password.com'] });
  for (const tool of Object.values(input.runtime.runtime.toolchain)) tool.sha256 = 'f'.repeat(64);
  input.runtime.platform.imageDigest = 'sha256:' + '1'.repeat(64);
  return input;
}
