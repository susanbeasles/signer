import {OWNER_ID, ORIGIN, encode, un64, bounded, fail, repository} from './protocol.mjs';
const ISSUER = 'https://token.actions.githubusercontent.com';
export async function verifyJWT(token, issuer, audience, jwksURL, {fetcher = fetch, now = Math.floor(Date.now()/1000), maxAge = 600} = {}) {
  if (typeof token !== 'string' || token.length > 12288 || token.length < 90) fail('unauthorized', 401);
  const parts = token.split('.'); if (parts.length !== 3 || parts.some(x => !/^[A-Za-z0-9_-]+$/.test(x))) fail('unauthorized', 401);
  let header, claims;
  try { header = JSON.parse(new TextDecoder().decode(un64(parts[0]))); claims = JSON.parse(new TextDecoder().decode(un64(parts[1]))); } catch { fail('unauthorized', 401); }
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length > 256 || header.crit !== undefined || claims.iss !== issuer || !(claims.aud === audience || (Array.isArray(claims.aud) && claims.aud.includes(audience))) || !audience || !Number.isInteger(claims.exp) || claims.exp <= now || claims.exp > now+maxAge || !Number.isInteger(claims.iat) || claims.iat > now+30 || claims.iat < now-maxAge || claims.exp <= claims.iat || (claims.nbf !== undefined && (!Number.isInteger(claims.nbf) || claims.nbf > now+30))) fail('unauthorized', 401);
  const response = await fetcher(jwksURL, {redirect:'error', signal:AbortSignal.timeout(10000)});
  if (!response.ok) fail('identity-unavailable', 503);
  const jwks = JSON.parse(new TextDecoder().decode(await bounded(response.body, 65536)));
  const keys = jwks.keys?.filter(key => key.kid === header.kid && key.kty === 'RSA' && (!key.alg || key.alg === 'RS256') && (!key.use || key.use === 'sig'));
  if (!keys || keys.length !== 1) fail('unauthorized', 401);
  const key = await crypto.subtle.importKey('jwk', keys[0], {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, un64(parts[2]), encode(parts[0]+'.'+parts[1]))) fail('unauthorized', 401);
  return claims;
}
export async function ownerAccess(token, audience, options = {}) {
  const claims = await verifyJWT(token, 'https://vespoli.cloudflareaccess.com', audience, 'https://vespoli.cloudflareaccess.com/cdn-cgi/access/certs', {...options,maxAge:3600});
  if (claims.email?.toLowerCase() !== 'anthonyvespoli@gmail.com' || typeof claims.sub !== 'string') fail('unauthorized', 401);
  return {subject:claims.sub};
}
export async function workload(token, allowed, options = {}) {
  const claims = await verifyJWT(token, ISSUER, ORIGIN, ISSUER+'/.well-known/jwks', options);
  if (typeof claims.sub!=='string'||claims.sub.length<1||claims.sub.length>512||!/^\d+$/.test(String(claims.repository_id))||claims.repository_owner_id !== OWNER_ID || !allowed.actors.includes(String(claims.actor_id)) || !['push','workflow_dispatch'].includes(claims.event_name) || !/^refs\/heads\/[A-Za-z0-9_./-]+$/.test(claims.ref || '') || claims.ref.includes('..') || typeof claims.jti !== 'string' || claims.jti.length < 1 || claims.jti.length > 256 || !allowed.workflows.includes(claims.job_workflow_ref || claims.workflow_ref)) fail('unauthorized', 401);
  return {subject:claims.sub, repository:repository(claims.repository, allowed.repositories), repositoryID:String(claims.repository_id), replayID:claims.jti, expires:claims.exp*1000};
}
