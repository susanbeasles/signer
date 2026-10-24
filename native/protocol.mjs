export const OWNER = 'susanbeasles';
export const OWNER_ID = '215839550';
export const ORIGIN = 'https://signer.anthonyvespoli.workers.dev';
export const MAX_COMMIT = 262144;
export const encode = value => new TextEncoder().encode(value);
export const b64url = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
export const un64 = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
export const random = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
export const digest = async value => b64url(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? encode(value) : value));
export function fail(code = 'denied', status = 403) { throw Object.assign(new Error(code), {status}); }
export function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== [...keys].sort().join()) fail('invalid-request', 400);
}
export function repository(value, allowed) {
  if (typeof value !== 'string' || !/^susanbeasles\/[A-Za-z0-9_.-]{1,100}$/.test(value) || !allowed.includes(value)) fail('repository-denied');
  return value;
}
export async function bounded(stream, limit) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader(); const chunks = []; let size = 0;
  try {
    for (;;) { const {value, done} = await reader.read(); if (done) break; size += value.byteLength; if (size > limit) fail('input-too-large', 413); chunks.push(value); }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  const output = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}
export async function jsonBody(request, limit = MAX_COMMIT * 2) {
  if (Number(request.headers.get('content-length') || 0) > limit) fail('input-too-large', 413);
  try { return JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(await bounded(request.body, limit))); }
  catch (error) { if (error.status) throw error; fail('invalid-json', 400); }
}
export function commitBytes(commit) {
  if (typeof commit !== 'string' || commit.includes('\0') || commit.includes('\r')) fail('invalid-commit', 400);
  const data = encode(commit); if (data.length > MAX_COMMIT) fail('input-too-large', 413);
  const split = commit.indexOf('\n\n'); if (split < 0) fail('invalid-commit', 400);
  const headers = commit.slice(0, split).split('\n');
  if (!/^tree (?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(headers[0])) fail('invalid-commit', 400);
  let i = 1; while (/^parent (?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(headers[i] || '')) i++;
  const identity = /^[^<>\n]+ <[^<>\s]+@[^<>\s]+> [0-9]{1,12} [+-][0-9]{4}$/;
  if (headers.length !== i + 2 || !headers[i].startsWith('author ') || !identity.test(headers[i].slice(7)) || !headers[i+1].startsWith('committer ') || !identity.test(headers[i+1].slice(10))) fail('invalid-commit', 400);
  return data;
}
export function output(value, status = 200, headers = {}) {
  return Response.json(value, {status, headers:{'cache-control':'no-store', 'x-content-type-options':'nosniff', 'referrer-policy':'no-referrer', ...headers}});
}
