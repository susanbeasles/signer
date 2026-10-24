import { parseSSHKeyReference } from '../src/service/op-reference.mjs';
export const INPUT_SCHEMA = 'signing-control-bootstrap-input/v1';
const ACCOUNT_ID = '1a799c6e699d2ef7e87398692ce3ad7b';
const OWNER_ORIGIN = 'https://control.vespoli.me';
const REPOSITORY = 'susanbeasles/signer';
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[a-z2-7]{26}$/;
const encoder = new TextEncoder();

function fail(code = 'invalid-public-input') {
  const error = new Error({ 'invalid-public-input': 'Public configuration is invalid. Check the documented schema; input values are not echoed.', 'plan-changed': 'The public input changed. Compile and review the new plan.', 'unknown-operation': 'Select one operation from the compiled plan.' }[code]);
  error.code = code;
  throw error;
}
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const actual = Object.keys(value).sort();
  if (actual.length !== keys.length || actual.some((key, i) => key !== [...keys].sort()[i])) fail();
}
function nullable(value, check) { if (value !== null && !check(value)) fail(); }
function matches(value, regex) { return typeof value === 'string' && regex.test(value); }
function numericID(value) { return matches(value, /^[1-9][0-9]{0,19}$/); }
function safetyCheck(value, depth = 0) {
  if (depth > 12) fail();
  if (typeof value === 'string') {
    if (value.length > 8192 || /-----BEGIN|\b(?:ops_|opsa_|gh[pousr]_|github_pat_)/i.test(value) || /[\u0000-\u001f\u007f]/.test(value)) fail();
  } else if (value && typeof value === 'object') {
    if (Object.keys(value).length > 64) fail();
    for (const [key, child] of Object.entries(value)) {
      if (['__proto__', 'constructor', 'prototype'].includes(key)) fail();
      safetyCheck(child, depth + 1);
    }
  } else if (typeof value === 'number' && !Number.isSafeInteger(value)) fail();
  else if (value !== null && !['boolean', 'number'].includes(typeof value)) fail();
}

export function parsePublicInput(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > 65536) fail();
  let value;
  try { value = JSON.parse(text); } catch { fail(); }
  safetyCheck(value);
  return value;
}
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export function artifactText(value) { return JSON.stringify(JSON.parse(canonicalJson(value)), null, 2) + '\n'; }
export async function sha256(value) {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('');
}
function base64(bytes) { return btoa(String.fromCharCode(...bytes)); }
export async function publicKeyFingerprint(key) {
  if (!matches(key, /^ssh-ed25519 [A-Za-z0-9+/]{68}$/)) fail();
  let bytes;
  try { bytes = Uint8Array.from(atob(key.slice(12)), c => c.charCodeAt(0)); } catch { fail(); }
  if (bytes.length !== 51 || base64(bytes) !== key.slice(12)) fail();
  const view = new DataView(bytes.buffer);
  if (view.getUint32(0) !== 11 || new TextDecoder().decode(bytes.slice(4, 15)) !== 'ssh-ed25519' || view.getUint32(15) !== 32) fail();
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return `SHA256:${base64(digest).replace(/=+$/, '')}`;
}

export async function validatePublicInput(input) {
  safetyCheck(input);
  if (encoder.encode(canonicalJson(input)).length > 65536) fail();
  exact(input, ['schema', 'accountID', 'ownerOrigin', 'source', 'onePassword', 'github', 'runtime']);
  if (input.schema !== INPUT_SCHEMA || input.accountID !== ACCOUNT_ID || input.ownerOrigin !== OWNER_ORIGIN) fail();
  const source = input.source;
  exact(source, ['repository', 'repositoryID', 'commit', 'artifactSha256']);
  if (source.repository !== REPOSITORY) fail();
  nullable(source.repositoryID, numericID);
  nullable(source.commit, x => matches(x, /^[a-f0-9]{40}$/));
  nullable(source.artifactSha256, x => matches(x, HEX));
  const op = input.onePassword;
  exact(op, ['accountDomain', 'vaultName', 'vaultID', 'itemName', 'itemID', 'serviceAccountID']);
  nullable(op.accountDomain, x => matches(x, /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.1password\.(?:com|ca|eu)$/));
  nullable(op.vaultName, x => typeof x === 'string' && x.length >= 1 && x.length <= 120 && x.trim() === x);
  if (!matches(op.itemName, /^[a-z0-9]+(?:-[a-z0-9]+){2,}$/) || op.itemName.length > 120) fail();
  for (const id of ['vaultID', 'itemID', 'serviceAccountID']) nullable(op[id], x => matches(x, ID));
  const github = input.github;
  exact(github, ['login', 'accountID', 'title', 'publicKey']);
  if (github.login !== 'susanbeasles' || github.accountID !== '215839550' || github.title !== 'signer') fail();
  const fingerprint = github.publicKey === null ? null : await publicKeyFingerprint(github.publicKey);
  const runtime = input.runtime;
  exact(runtime, ['services', 'runtime', 'platform']);
  exact(runtime.platform, ['provider', 'imageDigest']);
  if (runtime.platform.provider !== 'cloudflare-containers') fail();
  nullable(runtime.platform.imageDigest, x => matches(x, /^sha256:[a-f0-9]{64}$/));
  if (!Array.isArray(runtime.services) || runtime.services.length < 1 || runtime.services.length > 32) fail();
  const repositoryIDs = new Set(), repositories = new Set();
  for (const service of runtime.services) {
    exact(service, ['schema', 'repositoryID', 'repository', 'git', 'signer']);
    if (service.schema !== 'signing-control-service/v1' || !matches(service.repository, /^susanbeasles\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}$/) || !Number.isSafeInteger(service.repositoryID) || service.repositoryID < 1 || repositoryIDs.has(service.repositoryID) || repositories.has(service.repository.toLowerCase())) fail();
    repositoryIDs.add(service.repositoryID); repositories.add(service.repository.toLowerCase());
    exact(service.git, ['program', 'sha256', 'directory', 'authenticated', 'maxObjects', 'maxBytes']);
    if (service.git.program !== '/usr/bin/git' || service.git.directory !== '/run/signing-control/git' || typeof service.git.authenticated !== 'boolean' || !Number.isSafeInteger(service.git.maxObjects) || service.git.maxObjects < 1 || service.git.maxObjects > 100000 || !Number.isSafeInteger(service.git.maxBytes) || service.git.maxBytes < 1 || service.git.maxBytes > 8388608) fail();
    nullable(service.git.sha256, x => matches(x, HEX));
    exact(service.signer, ['keyID']);
    if (service.signer.keyID !== fingerprint) fail();
  }
  const signer = runtime.runtime;
  exact(signer, ['schema', 'opRef', 'publicKey', 'keyID', 'opOrigins', 'toolchain']);
  if (signer.schema !== 'signing-control-op-agent/v1' || signer.publicKey !== github.publicKey || signer.keyID !== fingerprint) fail();
  if (signer.opRef === null) { if (op.vaultID !== null || op.itemID !== null) fail(); }
  else {
    let reference; try { reference = parseSSHKeyReference(signer.opRef); } catch { fail(); }
    if (reference.vaultID !== op.vaultID || reference.itemID !== op.itemID) fail();
  }
  if (!Array.isArray(signer.opOrigins) || signer.opOrigins.length > 8 || new Set(signer.opOrigins).size !== signer.opOrigins.length) fail();
  for (const origin of signer.opOrigins) {
    if (!matches(origin, /^https:\/\/(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/) || ['https://signing-control.internal', 'https://github.com'].includes(origin)) fail();
  }
  const paths = { op: '/usr/local/bin/op', sshAgent: '/usr/bin/ssh-agent', sshAdd: '/usr/bin/ssh-add', sshKeygen: '/usr/bin/ssh-keygen' };
  exact(signer.toolchain, Object.keys(paths));
  for (const [name, path] of Object.entries(paths)) {
    exact(signer.toolchain[name], ['path', 'sha256']);
    if (signer.toolchain[name].path !== path) fail();
    nullable(signer.toolchain[name].sha256, x => matches(x, HEX));
  }
  return structuredClone(input);
}

function missingPins(input) {
  const pins = {
    'source.repositoryID': input.source.repositoryID, 'source.commit': input.source.commit, 'source.artifactSha256': input.source.artifactSha256,
    'onePassword.accountDomain': input.onePassword.accountDomain, 'onePassword.vaultName': input.onePassword.vaultName, 'onePassword.vaultID': input.onePassword.vaultID, 'onePassword.itemID': input.onePassword.itemID, 'onePassword.serviceAccountID': input.onePassword.serviceAccountID, 'runtime.runtime.opRef': input.runtime.runtime.opRef,
    'github.publicKey': input.github.publicKey, 'runtime.platform.imageDigest': input.runtime.platform.imageDigest,
  };
  for (const [index, service] of input.runtime.services.entries()) pins[`runtime.services.${index}.git.sha256`] = service.git.sha256;
  for (const [tool, value] of Object.entries(input.runtime.runtime.toolchain)) pins[`runtime.runtime.toolchain.${tool}.sha256`] = value.sha256;
  return [...Object.entries(pins).filter(([, value]) => value === null).map(([path]) => `missing:${path}`), ...(input.runtime.runtime.opOrigins.length ? [] : ['missing:runtime.runtime.opOrigins'])];
}

export async function compilePlan(raw) {
  const input = await validatePublicInput(raw);
  const inputDigest = await sha256(canonicalJson(input));
  const { services, runtime, platform } = input.runtime;
  const configDigest = await sha256(canonicalJson({ services, runtime, platform }));
  const repositoryConfigDigests = Object.fromEntries(await Promise.all(services.map(async service => [String(service.repositoryID), await sha256(canonicalJson({ service, runtime, platform }))])));
  const image = platform.imageDigest === null ? null : `registry.cloudflare.com/${ACCOUNT_ID}/signer@${platform.imageDigest}`;
  const wrangler = {
    name: 'signer', main: 'cloudflare/worker.mjs', account_id: ACCOUNT_ID,
    compatibility_date: '2026-10-08', compatibility_flags: ['nodejs_compat'], workers_dev: false, preview_urls: false, routes: [], observability: { enabled: false },
    durable_objects: { bindings: [{ name: 'SIGNING_CONTROL_STATE', class_name: 'SigningControlRepository' }] },
    migrations: [{ tag: 'signing-control-v1', new_sqlite_classes: ['SigningControlRepository'] }],
    secrets_store_secrets: [],
    vars: { ENABLED: 'false', SIGNING_CONTROL_CONFIG_JSON: canonicalJson(input.runtime) },
    ...(image ? { containers: [{ class_name: 'SigningControlRepository', image, max_instances: 1, instance_type: 'standard-1', scheduling_policy: 'default', observability: { enabled: false } }] } : {}),
  };
  const artifacts = { wrangler, publicRuntimeConfig: input.runtime, imageRuntimeConfig: { services, runtime } };
  const artifactDigests = Object.fromEntries(await Promise.all(Object.entries(artifacts).map(async ([name, value]) => [name, await sha256(artifactText(value))])));
  const op = input.onePassword;
  const actions = [
    ['cloudflare.worker.install', 'Private Worker', { accountID: ACCOUNT_ID, worker: 'signer', source: input.source, ingress: 'private-service-bindings-only', artifactDigests }, ['source-provenance', 'exact-source-artifact-readback', 'existing-depot-deployment-authorization']],
    ['cloudflare.durable-objects.migrate', 'Durable Object state', { accountID: ACCOUNT_ID, worker: 'signer', binding: 'SIGNING_CONTROL_STATE', className: 'SigningControlRepository', migrations: wrangler.migrations }, ['existing-migration-history-readback', 'worker-and-container-operation-authorizations']],
    ['cloudflare.container.configure', 'Dedicated container', { accountID: ACCOUNT_ID, worker: 'signer', className: 'SigningControlRepository', image, maxInstances: 1 }, ['image-provenance-and-digest-readback', 'runtime-isolation-verification', 'source-policy-private-binding', 'depot-producer-OIDC-admission']],
    ['onepassword.vault-reference.bind', 'Dedicated 1Password vault', { accountDomain: op.accountDomain, vaultName: op.vaultName, vaultID: op.vaultID }, ['exact-vault-metadata-readback', 'dedicated-vault-scope-verification']],
    ['onepassword.item-reference.bind', 'Signing item reference', { accountDomain: op.accountDomain, vaultID: op.vaultID, itemName: op.itemName, itemID: op.itemID, opRef: runtime.opRef, publicKeyFingerprint: runtime.keyID }, ['exact-item-and-field-ID-metadata-readback', 'public-key-provenance-verification']],
    ['onepassword.service-account-reference.bind', 'Service account reference', { accountDomain: op.accountDomain, serviceAccountID: op.serviceAccountID, vaultIDs: op.vaultID ? [op.vaultID] : [], permissions: ['read_items'], destinationBinding: 'SIGNER_SERVICE_ACCOUNT_TOKEN', custody: 'cloudflare-secrets-store-service-account-token-only' }, ['dedicated-account-and-exact-vault-permission-readback', 'separate-owner-authorized-secure-token-provisioning']],
    ['github.ssh-signing-key.register', 'Public SSH signing key', { expectedLogin: input.github.login, expectedAccountID: input.github.accountID, method: 'POST', url: 'https://api.github.com/user/ssh_signing_keys', body: { title: input.github.title, key: input.github.publicKey }, fingerprint: runtime.keyID }, ['authenticated-user-numeric-identity-readback', 'existing-signing-key-deduplication', 'explicit-public-key-registration-authorization']],
  ];
  const operations = await Promise.all(actions.map(async ([id, title, payload, prerequisites]) => {
    const operation = { id, title, payload, prerequisites, execution: 'unavailable', authorizationRequirement: 'fresh-operation-specific-owner-authorization', inputDigest, configDigest };
    return { ...operation, digest: await sha256(canonicalJson(operation)) };
  }));
  const plan = {
    schema: 'signing-control-bootstrap-plan/v1', mode: 'dry-run', execution: 'unavailable', scope: 'separate-signer-extension',
    ownerOrigin: OWNER_ORIGIN, inputDigest, configDigest, repositoryConfigDigests, artifactDigests, artifacts, operations,
    blockers: [...missingPins(input), 'required:operation-specific-owner-authorization', 'required:live-resource-and-isolation-readback', 'required:depot-producer-OIDC-admission', 'unconfigured-private-binding:SOURCE_POLICY'],
    promotionPrerequisites: ['required:accepted-durable-promotion-history-custody', ...['OWNER_HARDWARE', 'SOURCE_CI', 'SOURCE_SCANS', 'SOURCE_REVIEW', 'SOURCE_INVENTORY', 'SOURCE_PUBLISHER', ...(services.some(service => service.git.authenticated) ? ['SOURCE_READ_CREDENTIAL'] : [])].map(name => `unconfigured-private-binding:${name}`)],
  };
  return { ...plan, digest: await sha256(canonicalJson(plan)) };
}

export async function createReviewRequest(input, expectedDigest, operationID) {
  const plan = await compilePlan(input);
  if (plan.digest !== expectedDigest) fail('plan-changed');
  const operation = plan.operations.find(item => item.id === operationID);
  if (!operation) fail('unknown-operation');
  return { schema: 'signing-control-bootstrap-review/v1', kind: 'unauthenticated-review-request', planDigest: plan.digest, inputDigest: plan.inputDigest, configDigest: plan.configDigest, operationID, operationDigest: operation.digest, operation, blockers: plan.blockers, promotionPrerequisites: plan.promotionPrerequisites };
}

