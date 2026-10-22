// Read only through native Cloudflare Secrets Store binding during an authorized job.
// No Worker-secret fallback, persistence or runtime cross-job cache.
export async function readSignerServiceToken(env) {
 try {
  const binding=env?.SIGNER_SERVICE_ACCOUNT_TOKEN;
  if(typeof binding?.get!=='function')throw Error();
  const value=await binding.get();
  if(typeof value!=='string'||! /^[\x21-\x7e]{1,8192}$/.test(value))throw Error();
  return value;
 } catch {throw Error('signer-service-token-unavailable'); }
}
