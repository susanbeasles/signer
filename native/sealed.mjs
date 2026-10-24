import {encode, b64url, un64, fail} from './protocol.mjs';
// The wrapping key is supplied by a native secret_key binding; it is never serialized here.
export async function seal(key, name, value) {
  if (!key || key.type !== 'secret' || key.extractable !== false || key.algorithm.name !== 'AES-GCM') fail('custody-unavailable', 503);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:encode('signer:v1:'+name)}, key, encode(JSON.stringify(value)));
  return {version:1, iv:b64url(iv), ciphertext:b64url(ciphertext)};
}
export async function open(key, name, envelope) {
  if (!envelope || envelope.version !== 1 || !key || key.extractable !== false) fail('custody-unavailable', 503);
  const raw = await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(envelope.iv),additionalData:encode('signer:v1:'+name)}, key, un64(envelope.ciphertext));
  return JSON.parse(new TextDecoder().decode(raw));
}
