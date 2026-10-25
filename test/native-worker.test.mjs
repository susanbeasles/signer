import test from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {ORIGIN} from '../native/protocol.mjs';
import {b64url,encode} from '../native/protocol.mjs';
test('real Workerd serves setup after verifying an owner Access assertion',{timeout:30000},async()=>{
  const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
  const jwk=await crypto.subtle.exportKey('jwk',pair.publicKey),now=Math.floor(Date.now()/1000),audience='synthetic-owner-audience';
  const parts=[{alg:'RS256',kid:'owner-test'},{iss:'https://vespoli.cloudflareaccess.com',aud:[audience],iat:now,exp:now+1800,email:'anthonyvespoli@gmail.com',sub:'synthetic-owner'}].map(v=>b64url(encode(JSON.stringify(v))));
  const token=parts.join('.')+'.'+b64url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,encode(parts.join('.'))));
  const built=await build({entryPoints:[new URL('../native/worker.mjs',import.meta.url).pathname],bundle:true,write:false,format:'esm',platform:'neutral',external:['cloudflare:workers']});
  const runtime=new Miniflare(convertV4MiniflareOptions({cf:false,modules:true,script:built.outputFiles[0].text,compatibilityDate:'2026-10-13',bindings:{ACCESS_AUD:audience},durableObjects:{SIGNER:{className:'Signer',useSQLite:true}},outboundService:request=>{
    assert.equal(request.url,'https://vespoli.cloudflareaccess.com/cdn-cgi/access/certs');
    return Response.json({keys:[{...jwk,kid:'owner-test'}]});
  }}));
  try{
    const response=await runtime.dispatchFetch(ORIGIN+'/setup',{headers:{'cf-access-jwt-assertion':token}});
    const body=await response.text();assert.equal(response.status,200,body);assert.match(body,/GitHub App registration required/);
  }finally{await runtime.dispose();}
});
test('real Workerd rejects unauthenticated signing, owner actions, forged callback state and foreign hosts',{timeout:30000},async()=>{
  const built=await build({entryPoints:[new URL('../native/worker.mjs',import.meta.url).pathname],bundle:true,write:false,format:'esm',platform:'neutral',external:['cloudflare:workers']});
  const runtime=new Miniflare(convertV4MiniflareOptions({cf:false,modules:true,script:built.outputFiles[0].text,compatibilityDate:'2026-10-13',durableObjects:{SIGNER:{className:'Signer',useSQLite:true}},outboundService:()=>{throw Error('Unauthorized traffic must not reach providers');}}));
  try{
    const post=path=>runtime.dispatchFetch(ORIGIN+path,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    for(const path of ['/v1/sign','/v1/grants','/v1/key','/v1/session'])assert.equal((await post(path)).status,401);
    assert.equal((await runtime.dispatchFetch(ORIGIN+'/setup')).status,401);
    assert.equal((await post('/owner/approve')).status,401);
    assert.equal((await runtime.dispatchFetch(ORIGIN+'/github/manifest?code=synthetic-code&state='+'a'.repeat(43))).status,403);
    assert.equal((await runtime.dispatchFetch('https://foreign.example/health')).status,404);
    const health=await runtime.dispatchFetch(ORIGIN+'/health');assert.equal(health.status,200);assert.equal((await health.json()).ready,false);
    const bootstrap=await runtime.dispatchFetch(ORIGIN+'/v1/bootstrap',{method:'POST',body:JSON.stringify({repository:'susanbeasles/signer'})});assert.equal(bootstrap.status,200);
    const pending=await bootstrap.json();assert.match(pending.id,/^[A-Za-z0-9_-]{43}$/);
    const redeem=await runtime.dispatchFetch(ORIGIN+'/v1/redeem',{method:'POST',body:JSON.stringify({id:pending.id,secret:pending.secret})});assert.equal(redeem.status,409);assert.equal((await redeem.json()).error,'owner-approval-pending');
  }finally{await runtime.dispose();}
});
