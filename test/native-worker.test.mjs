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

test('real Workerd GitHub client uses native fetch without a receiver error',{timeout:30000},async()=>{
  const built=await build({stdin:{contents:"import {GitHub} from './native/github.mjs';\nexport default {async fetch(){try{return Response.json(await new GitHub({},null).request('/user'));}catch(e){return Response.json({name:e.name,message:e.message},{status:503});}}};",resolveDir:process.cwd()},bundle:true,write:false,format:'esm',platform:'neutral'});
  const runtime=new Miniflare(convertV4MiniflareOptions({cf:false,modules:true,script:built.outputFiles[0].text,compatibilityDate:'2026-10-13',outboundService:request=>{
    assert.equal(request.url,'https://api.github.com/user');return Response.json({id:215839550});
  }}));
  try{const response=await runtime.dispatchFetch(ORIGIN+'/');const body=await response.text();assert.equal(response.status,200,body);}
  finally{await runtime.dispose();}
});

test('real Workerd completes encrypted registration, OAuth and signing-key administration',{timeout:30000},async()=>{
 let publicKey=null;
 const built=await build({stdin:{contents:"import {GitHub} from './native/github.mjs';\nexport default {async fetch(){\n const values=new Map([['app-registration-in-flight',{started:1}]]);\n const storage={async get(k){return values.get(k)},async put(k,v){values.set(k,v)},async delete(k){values.delete(k)},async transaction(fn){return fn(this)}};\n const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);\n const github=new GitHub(storage,key);\n try{\n await github.register('synthetic-code');\n const next=await github.oauthStart();\n await github.oauthComplete('synthetic-code',next.state);\n const id=await github.registerKey({publicKey:'synthetic-public',title:'signer:test'});\n await github.removeKey({githubID:id,publicKey:'synthetic-public',title:'signer:test'});\n return Response.json({registered:!!await storage.get('app'),authorized:!!await storage.get('authorization'),sealed:!!await storage.get('sealed:tokens'),id});\n }catch(e){return Response.json({name:e.name,message:e.message},{status:503});}\n}};",resolveDir:process.cwd()},bundle:true,write:false,format:'esm',platform:'neutral'});
 const runtime=new Miniflare(convertV4MiniflareOptions({cf:false,modules:true,script:built.outputFiles[0].text,compatibilityDate:'2026-10-13',outboundService:async request=>{
   const url=new URL(request.url);
   if(url.pathname.startsWith('/app-manifests/'))return Response.json({id:123,client_id:'synthetic-client',client_secret:'synthetic-secret',pem:'synthetic-pem',slug:'synthetic-app',owner:{id:215839550,login:'susanbeasles'},permissions:{git_signing_ssh_public_keys:'write'}});
   if(url.pathname==='/login/oauth/access_token')return Response.json({access_token:'synthetic-access',refresh_token:'synthetic-refresh',expires_in:3600,refresh_token_expires_in:7200});
   if(url.pathname==='/user')return Response.json({id:215839550,login:'susanbeasles'});
   if(url.pathname==='/user/ssh_signing_keys'){
     if(request.method==='POST'){const body=await request.json();publicKey={id:456,...body};return Response.json(publicKey);}
     return Response.json(publicKey?[publicKey]:[]);
   }
   if(url.pathname==='/user/ssh_signing_keys/456' && request.method==='DELETE'){publicKey=null;return new Response(null,{status:204});}
   throw Error('Unexpected provider request');
 }}));
 try{const response=await runtime.dispatchFetch(ORIGIN+'/');const body=await response.text();assert.equal(response.status,200,body);assert.deepEqual(JSON.parse(body),{registered:true,authorized:true,sealed:true,id:456});assert.equal(publicKey,null);}
 finally{await runtime.dispose();}
});
