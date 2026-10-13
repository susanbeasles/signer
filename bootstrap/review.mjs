import { artifactText, compilePlan, createReviewRequest, parsePublicInput, publicKeyFingerprint, validatePublicInput } from './plan.mjs';
import { exampleInput } from './example.mjs';

const fields = [
  ['Signer source', [
    ['source.repositoryID', 'Private source repository ID', 20], ['source.commit', 'Reviewed source commit · 40 hex', 40], ['source.artifactSha256', 'Source artifact SHA-256 · 64 hex', 64],
  ]],
  ['Configured target repositories', [
    ['runtime.services', 'Exact repository service allowlist · JSON, maximum 32', 32768],
  ]],
  ['Dedicated 1Password references', [
    ['onePassword.accountDomain', 'Account domain · team.1password.com', 90], ['onePassword.vaultName', 'Vault display name · metadata only', 120], ['onePassword.vaultID', 'Approved vault ID', 26], ['onePassword.itemName', 'Item display name · vendor-scope-credentialType', 120], ['onePassword.itemID', 'Signing item ID', 26], ['onePassword.serviceAccountID', 'Dedicated service account ID', 26],
    ['runtime.runtime.opRef', 'Explicit op://vaultID/itemID/[sectionID/]fieldID?ssh-format=openssh', 220],
    ['runtime.runtime.opOrigins', 'Independently reviewed 1Password HTTPS origins · comma-separated', 2100],
  ]],
  ['Public signing identity', [['github.publicKey', 'Ed25519 public key · ssh-ed25519 BASE64', 80]]],
  ['Reviewed image and executable hashes', [
    ['runtime.platform.imageDigest', 'Container image digest · sha256:…', 71],
    ['runtime.runtime.toolchain.op.sha256', '1Password CLI executable SHA-256', 64], ['runtime.runtime.toolchain.sshAgent.sha256', 'ssh-agent executable SHA-256', 64],
    ['runtime.runtime.toolchain.sshAdd.sha256', 'ssh-add executable SHA-256', 64], ['runtime.runtime.toolchain.sshKeygen.sha256', 'ssh-keygen executable SHA-256', 64],
  ]],
];
const $ = id => document.getElementById(id);
const get = (object, path) => path.split('.').reduce((value, part) => value[part], object);
const set = (object, path, value) => { const parts = path.split('.'); const last = parts.pop(); parts.reduce((current, part) => current[part], object)[last] = value; };
let publicInput = exampleInput();
let currentPlan = null;
let selectedReview = null;
let revision = 0;
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
function invalidate() {
  revision += 1;
  currentPlan = null;
  selectedReview = null;
  $('summary').hidden = true;
  $('operation-detail').hidden = true;
  $('operations').replaceChildren();
  $('review-note').textContent = 'Inputs changed. Compile again before reviewing or downloading.';
}
function showFields() {
  $('public-fields').replaceChildren();
  for (const [title, group] of fields) {
    const fieldset = document.createElement('fieldset');
    const legend = document.createElement('legend'); legend.textContent = title; fieldset.append(legend);
    for (const [path, label, maxLength] of group) {
      const node = document.createElement(path === 'runtime.services' ? 'textarea' : 'input'); if (path !== 'runtime.services') node.type = 'text'; else node.rows = 14; node.id = path; node.dataset.path = path; node.maxLength = maxLength;
      const value = get(publicInput, path); node.value = path === 'runtime.services' ? JSON.stringify(value, null, 2) : Array.isArray(value) ? value.join(', ') : value ?? ''; node.placeholder = 'Unresolved'; node.spellcheck = false;
      const caption = document.createElement('label'); caption.htmlFor = path; caption.textContent = label;
      fieldset.append(caption, node);
    }
    $('public-fields').append(fieldset);
  }
}
async function inputFromForm() {
  const input = structuredClone(publicInput);
  for (const node of document.querySelectorAll('[data-path]')) {
    let value = node.value === '' ? null : node.value;
    if (node.dataset.path.endsWith('.opOrigins')) value = node.value === '' ? [] : node.value.split(',').map(part => part.trim());
    if (node.dataset.path === 'runtime.services') value = parsePublicInput(node.value);
    set(input, node.dataset.path, value);
  }
  input.runtime.runtime.publicKey = input.github.publicKey;
  const keyID = input.github.publicKey === null ? null : await publicKeyFingerprint(input.github.publicKey);
  input.runtime.runtime.keyID = keyID;
  if (!Array.isArray(input.runtime.services)) throw new Error('invalid');
  for (const service of input.runtime.services) service.signer.keyID = keyID;
  return validatePublicInput(input);
}
function download(name, object) {
  const url = URL.createObjectURL(new Blob([artifactText(object)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function selectOperation(id) {
  const at = revision;
  try {
    const review = await createReviewRequest(publicInput, currentPlan.digest, id);
    if (at !== revision) return;
    selectedReview = review;
    $('operation-title').textContent = review.operation.title;
    $('operation-json').textContent = JSON.stringify(review, null, 2);
    $('operation-detail').hidden = false;
    $('operation-detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch { if (at === revision) status('The plan changed. Compile and review again.', true); }
}
function showPlan(plan) {
  $('summary').hidden = false;
  $('plan-digest').textContent = plan.digest;
  $('config-digest').textContent = plan.configDigest;
  $('review-note').textContent = 'Seven separate operation intents. Provider actions remain unavailable.';
  $('blockers').replaceChildren(...plan.blockers.map(text => { const item = document.createElement('li'); item.textContent = text; return item; }));
  $('promotion-prerequisites').replaceChildren(...plan.promotionPrerequisites.map(text => { const item = document.createElement('li'); item.textContent = text; return item; }));
  $('operations').replaceChildren(...plan.operations.map((operation, index) => {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'operation'; button.dataset.operation = operation.id;
    const number = document.createElement('span'); number.className = 'number'; number.textContent = String(index + 1).padStart(2, '0');
    const name = document.createElement('span'); name.className = 'operation-name'; name.textContent = operation.title;
    const detail = document.createElement('small'); detail.textContent = 'Inspect exact operation · authorization required'; name.append(detail);
    const arrow = document.createElement('span'); arrow.className = 'arrow'; arrow.textContent = '→';
    button.append(number, name, arrow); button.addEventListener('click', () => selectOperation(operation.id)); return button;
  }));
}
$('public-form').addEventListener('input', () => { invalidate(); status('Inputs changed; previous review requests are no longer current.'); });
$('public-form').addEventListener('submit', async event => {
  event.preventDefault(); invalidate(); const at = revision;
  try {
    const input = await inputFromForm();
    const plan = await compilePlan(input);
    if (at !== revision) return;
    publicInput = input; currentPlan = plan; showPlan(plan); status('Plan compiled locally. Apply remains disabled; this is not approval.');
  } catch { if (at === revision) status('Invalid public input. Use exact IDs and hashes; no tokens or private keys. Input values are never included in errors.', true); }
});
$('reset').addEventListener('click', () => { invalidate(); publicInput = exampleInput(); showFields(); status('Inputs reset. No data was saved.'); });
$('import').addEventListener('change', async event => {
  invalidate(); const at = revision;
  try {
    const file = event.target.files[0];
    if (!file || file.size > 65536) throw new Error('invalid');
    const input = await validatePublicInput(parsePublicInput(await file.text()));
    if (at !== revision) return;
    publicInput = input; showFields(); status('Public configuration imported. Compile to review.');
  } catch { if (at === revision) status('Import rejected. Expected a bounded public configuration JSON file; no input was echoed or saved.', true); }
  finally { event.target.value = ''; }
});
$('download-plan').addEventListener('click', () => { if (currentPlan) download('bootstrap-plan.json', currentPlan); });
$('download-config').addEventListener('click', () => { if (currentPlan) download('public-runtime-config.json', currentPlan.artifacts.publicRuntimeConfig); });
$('download-review').addEventListener('click', () => { if (selectedReview && currentPlan && selectedReview.planDigest === currentPlan.digest) download(`${selectedReview.operationID}.review.json`, selectedReview); });
showFields();
