import {DurableObject} from 'cloudflare:workers';
import {authorize} from './auth.mjs';
import {sshPublicKey,sshPublicBlob,signCommit,base64} from './ssh.mjs';
const MAX=262144;
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
const sha=async b=>hex(await crypto.subtle.digest('SHA-256',b));
const deny=(status=404)=>new Response('Not found',{status,headers:{'cache-control':'no-store'}});
const response=(obj,status=200)=>Response.json(obj,{status,headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
const bytes=x=>new TextEncoder().encode(x);
function unsignedGitCommit(body) {
 if(typeof body!=='string'||body.length<80||body.length>MAX||body.includes('\0')||body.includes('\r'))throw Error('invalid-commit');
 const i=body.indexOf('\n\n');if(i<0)throw Error('invalid-commit');
 const lines=body.slice(0,i).split('\n');
 if(!/^tree [a-f0-9]{40}$/.test(lines[0]))throw Error('invalid-commit');
 let index=1;
 while(index<lines.length&&/^parent [a-f0-9]{40}$/.test(lines[index]))index++;
 if(lines.length!==index+2||!/^author .+ <[^<>\n]+> [0-9]{1,12} [+-][0-9]{4}$/.test(lines[index])||!/^committer .+ <[^<>\n]+> [0-9]{1,12} [+-][0-9]{4}$/.test(lines[index+1]))throw Error('invalid-commit');
 const buffer=bytes(body);if(buffer.length>MAX)throw Error('commit-too-large');return buffer;
}
export class SigningVault extends DurableObject {
 constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;this.ready=ctx.blockConcurrencyWhile(async()=>{
   const saved=await ctx.storage.get('ed25519:v1');
   if(saved){if(saved.privateKey?.type!=='private'||saved.privateKey?.extractable!==false||saved.privateKey?.algorithm?.name!=='Ed25519'||!Array.isArray(saved.publicKey)||saved.publicKey.length!==32)throw Error('invalid-signer-state');return;}
   const pair=await crypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
   if(pair.privateKey.extractable!==false)throw Error('nonextractability-denied');
   const raw=[...new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey))];
   // The opaque private CryptoKey is never exported, converted to bytes, or written to a file.
   await ctx.storage.put('ed25519:v1',{privateKey:pair.privateKey,publicKey:raw});
   const check=await ctx.storage.get('ed25519:v1');
   if(check?.privateKey?.extractable!==false||check.publicKey.join()!==raw.join())throw Error('key-persistence-denied');
 });}
 async publicKey(){await this.ready;const stored=await this.ctx.storage.get('ed25519:v1');if(!stored?.privateKey||stored.privateKey.extractable!==false)throw Error('signer-unavailable');const raw=new Uint8Array(stored.publicKey);const result={algorithm:'ssh-ed25519',publicKey:sshPublicKey(raw),fingerprint:'SHA256:'+base64(new Uint8Array(await crypto.subtle.digest('SHA-256',sshPublicBlob(raw)))).replace(/=+$/,'')};if(this.env.PUBLIC_KEYS)await this.env.PUBLIC_KEYS.put('ed25519.v1',JSON.stringify(result));return result;}
 async sign(input,token){await this.ready;
   if(!input||Object.keys(input).sort().join()!=='commit,id,repository'||typeof input.id!=='string'||!/^[a-f0-9]{32,64}$/.test(input.id))throw Error('invalid-request');
   const allowedActors=JSON.parse(this.env.AUTHORIZED_GITHUB_ACTORS||'[]');
   const identity=await authorize(token,input.repository,{accessAud:this.env.ACCESS_AUD,ownerEmail:this.env.OWNER_EMAIL,allowedActors});
   const data=unsignedGitCommit(input.commit);
   const digest=await sha(data),key='sign:'+input.id;
   // Reservation is durable and transactional before any non-idempotent use of the key.
   await this.ctx.storage.transaction(async tx=>{
     if(await tx.get(key))throw Error('request-replayed');
     await tx.put(key,{state:'reserved',digest,repository:identity.repository,principal:identity.subject});
   });
   const stored=await this.ctx.storage.get('ed25519:v1');if(!stored||stored.privateKey.extractable!==false)throw Error('signer-unavailable');
   const signature=await signCommit(stored.privateKey,new Uint8Array(stored.publicKey),data);
   const receipt={id:input.id,digest,repository:identity.repository,principal:identity.subject,issuedAt:Date.now(),publicKey:sshPublicKey(new Uint8Array(stored.publicKey))};
   await this.ctx.storage.put(key,{state:'completed',receipt,signature});
   return {signature,receipt};
 }
 async fetch(){return deny();}
}
export default {
 async fetch(request,env){
  const url=new URL(request.url);if(url.search||url.hostname!=='signing-control.anthonyvespoli.workers.dev')return deny();
  if(request.method==='GET'&&url.pathname==='/auth')return response({authenticated:true});
  if(request.method==='GET'&&url.pathname==='/v1/public-key'){
   try{return response(await env.SIGNER_VAULT.getByName('primary').publicKey());}catch{return deny(503)}
  }
  if(request.method==='POST'&&url.pathname==='/v1/sign'){
   const bearer=request.headers.get('authorization')||'';
   if(!/^Bearer [A-Za-z0-9._-]{90,12288}$/.test(bearer))return deny(401);
   if(Number(request.headers.get('content-length')||0)>MAX)return deny(413);
   let input;try{const value=await request.text();if(value.length>MAX)return deny(413);input=JSON.parse(value)}catch{return deny(400)}
   try{return response(await env.SIGNER_VAULT.getByName('primary').sign(input,bearer.slice(7)));}catch(e){const m=e?.message||'';return deny(m==='request-replayed'?409:m==='invalid-request'||m==='invalid-commit'?400:m==='unauthorized'?401:503);}
  }
  return deny();
 },
 scheduled(event,env,ctx){ctx.waitUntil(env.SIGNER_VAULT.getByName('primary').publicKey().catch(e=>env.PUBLIC_KEYS.put('signer-init-diagnostic',JSON.stringify({name:String(e?.name||'Error').slice(0,90),message:String(e?.message||'unknown').slice(0,220)}))));}
};
