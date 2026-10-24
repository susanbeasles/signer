import assert from 'node:assert/strict';
import test from 'node:test';
import {existsSync} from 'node:fs';
import {readFile} from 'node:fs/promises';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
const modulePath=new URL('../runtime/op-git-signer.mjs',import.meta.url);
const runtime=existsSync(modulePath)?await import(modulePath):{};
const hash=value=>createHash('sha256').update(value).digest('hex');
function fixtureKey(){
 const pair=generateKeyPairSync('ed25519'),pub=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32),seed=pair.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32);
 const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32BE(n);return b;},str=value=>{const b=Buffer.from(value);return Buffer.concat([u32(b.length),b]);};
 const publicBlob=Buffer.concat([str('ssh-ed25519'),str(pub)]),payload=Buffer.concat([u32(12345),u32(12345),str('ssh-ed25519'),str(pub),str(Buffer.concat([seed,pub])),str('synthetic-test-only')]);
 const pad=8-payload.length%8,privateBlob=Buffer.concat([payload,Buffer.from(Array.from({length:pad},(_,i)=>i+1))]);
 const wire=Buffer.concat([Buffer.from('openssh-key-v1\0'),str('none'),str('none'),str(''),u32(1),str(publicBlob),str(privateBlob)]);
 const signature=message=>{const signed=Buffer.concat([Buffer.from('SSHSIG'),str('git'),str(''),str('sha512'),str(createHash('sha512').update(message).digest())]);const signatureBlob=Buffer.concat([str('ssh-ed25519'),str(sign(null,signed,pair.privateKey))]);const blob=Buffer.concat([Buffer.from('SSHSIG'),u32(1),str(publicBlob),str('git'),str(''),str('sha512'),str(signatureBlob)]);return '-----BEGIN SSH SIGNATURE-----\n'+blob.toString('base64').match(/.{1,70}/g).join('\n')+'\n-----END SSH SIGNATURE-----\n';};
 return {signature,publicKey:'ssh-ed25519 '+publicBlob.toString('base64'),keyID:'SHA256:'+createHash('sha256').update(publicBlob).digest('base64').replace(/=+$/,''),privateKey:Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----\n'+wire.toString('base64').match(/.{1,70}/g).join('\n')+'\n-----END OPENSSH PRIVATE KEY-----\n')};
}
async function fixture(){
 const key=fixtureKey(),paths={op:'/usr/local/bin/op',sshAgent:'/usr/bin/ssh-agent',sshAdd:'/usr/bin/ssh-add',sshKeygen:'/usr/bin/ssh-keygen'},toolchain={};
 for(const [name,path]of Object.entries(paths))toolchain[name]={path,sha256:name==='op'?'0'.repeat(64):hash(await readFile(path))};
 const config={schema:'signing-control-op-agent/v1',opRef:'op://'+'a'.repeat(26)+'/'+'b'.repeat(26)+'/private_key?ssh-format=openssh',publicKey:key.publicKey,keyID:key.keyID,toolchain,opOrigins:['https://account.example.test']};
 const payload='tree '+'1'.repeat(40)+'\nparent '+'2'.repeat(40)+'\nauthor Fixture <fixture@example.test> 1000 +0000\ncommitter Fixture <fixture@example.test> 1000 +0000\n\nSynthetic fixture\n';
 return {key,config,payload};
}
test('op signer production loader exists and exposes the existing core adapter',()=>assert.equal(typeof runtime.createOpGitSigner,'function'));
test('configuration rejects mutable refs, private keys, foreign paths and public-key mismatch',async()=>{
 const f=await fixture();assert.equal(runtime.validateSignerConfig(f.config).keyID,f.key.keyID);
 for(const change of [c=>c.opRef='op://vault/item/private_key?ssh-format=openssh',c=>c.opRef+='&other=1',c=>c.keyID='SHA256:'+'A'.repeat(43),c=>c.publicKey=f.key.privateKey.toString(),c=>c.toolchain.op.path='/tmp/op',c=>c.toolchain.sshKeygen.sha256='bad']){const c=structuredClone(f.config);change(c);assert.throws(()=>runtime.validateSignerConfig(c));}
});
test('fixture-only key moves via stdin into new agent and real ssh-keygen verifies the exact Git payload',async()=>{
 const f=await fixture(),calls=[],authorizations=[];
 const signer=await runtime.createOpGitSigner({config:f.config,serviceToken:'SYNTHETIC-OP-TOKEN',deadline:Math.floor(Date.now()/1000)+60,authorize:async input=>{authorizations.push(input);return {authorized:true,keyID:f.key.keyID,objectDigest:hash(input.payload),expiresAt:Math.floor(Date.now()/1000)+30};},effects:{preflight:async()=>{},pin:async tool=>tool.path==='/usr/local/bin/op'?tool.path:runtime.pinExecutable(tool),run:async(program,args,options)=>{calls.push({program,args,env:{...options.env},input:program.endsWith('/ssh-add')?Buffer.from(options.input??''):null});if(program==='/usr/local/bin/op')return Buffer.from(f.key.privateKey);return runtime.runBounded(program,args,options);}}});
 try{
  let signature;try{signature=await signer.signGit({type:'commit',payload:f.payload,authorization:{kind:'synthetic'}});}catch(error){assert.fail(error.message+'; subprocess stages: '+calls.map(c=>c.program+' '+c.args.slice(0,2).join(' ')).join(', '));}
  assert.match(signature,/^-----BEGIN SSH SIGNATURE-----/);assert.equal(await signer.verifyGit({payload:f.payload,signature}),true);assert.equal(await signer.verifyGit({payload:f.payload+'changed',signature}),false);
  assert.equal(authorizations.length,1);const op=calls.find(c=>c.program==='/usr/local/bin/op');assert.deepEqual(op.args,['read',f.config.opRef,'--no-newline']);assert.equal(op.env.OP_SERVICE_ACCOUNT_TOKEN,'SYNTHETIC-OP-TOKEN');assert.equal(op.env.SSL_CERT_FILE,'/etc/cloudflare/certs/cloudflare-containers-ca.crt');
  const add=calls.find(c=>c.program.endsWith('/ssh-add')&&c.args.includes('-'));assert.ok(add.input.equals(f.key.privateKey));assert.deepEqual(add.args,['-t','30','-']);
  for(const c of calls.filter(c=>c.program!=='/usr/local/bin/op'))assert.ok(!Object.hasOwn(c.env,'OP_SERVICE_ACCOUNT_TOKEN'));
  const sign=calls.find(c=>c.program.endsWith('/ssh-keygen')&&c.args.includes('sign'));assert.deepEqual(sign.args.slice(0,6),['-Y','sign','-U','-n','git','-f']);assert.ok(!JSON.stringify(calls.map(c=>c.args)).includes('PRIVATE KEY'));
  assert.equal(existsSync(sign.env.SSH_AUTH_SOCK),false);
 }finally{await signer.close();f.key.privateKey.fill(0);for(const c of calls)c.input?.fill(0);}
});
test('denied authorization and absent service token perform no key read or child spawn',async()=>{
 const f=await fixture();let calls=0;
 for(const token of [null,'SYNTHETIC']){
  const signer=await runtime.createOpGitSigner({config:f.config,serviceToken:token,deadline:Math.floor(Date.now()/1000)+60,authorize:async()=>({authorized:false}),effects:{preflight:async()=>{},pin:async t=>t.path,run:async()=>{calls++;throw Error('must not run');},startAgent:async()=>{calls++;throw Error('must not start');}}});
  try{await assert.rejects(signer.signGit({type:'commit',payload:f.payload,authorization:{}}));}finally{await signer.close();}
 }
 assert.equal(calls,0);
});
test('expiry after op read prevents key import/signature, and cleans the agent workspace',async()=>{
 const f=await fixture();let now=1000,workspace;const calls=[];
 const signer=await runtime.createOpGitSigner({config:f.config,serviceToken:'SYNTHETIC',deadline:1100,clock:()=>now,authorize:async input=>({authorized:true,keyID:f.key.keyID,objectDigest:hash(input.payload),expiresAt:1050}),effects:{preflight:async()=>{},pin:async t=>t.path,run:async(program,args,options)=>{calls.push(program);workspace=options.env.HOME;now=1060;return Buffer.from(f.key.privateKey);},startAgent:async()=>({close:async()=>{}})}});
 try{await assert.rejects(signer.signGit({type:'commit',payload:f.payload,authorization:{}}));assert.deepEqual(calls,['/usr/local/bin/op']);assert.equal(existsSync(workspace),false);}finally{await signer.close();f.key.privateKey.fill(0);}
});
test('read-only signature verification never obtains a key or needs an op token',async()=>{
 const f=await fixture();let calls=0;const signer=await runtime.createOpGitSigner({config:f.config,serviceToken:null,deadline:Math.floor(Date.now()/1000)+60,authorize:async()=>{throw Error('not a signing action');},effects:{preflight:async()=>{},pin:async t=>t.path,run:async()=>{calls++;throw Error('must not read');}}});
 try{assert.equal(await signer.verifyGit({payload:f.payload,signature:'invalid'}),false);assert.equal(calls,0);}finally{await signer.close();}
});
test('bounded children suppress error output and terminate timeout/overflow',async()=>{
 for(const [code,timeout,limit]of [["process.stderr.write('SYNTHETIC-PRIVATE');process.exit(1)",1000,1024],["setTimeout(()=>{},30000)",30,1024],["process.stdout.write('SYNTHETIC'.repeat(1000))",1000,32]])await assert.rejects(runtime.runBounded(process.execPath,['-e',code],{env:{PATH:'/usr/bin:/bin'},timeoutMs:timeout,limit}),/^Error: Signer subprocess unavailable$/);
});
test('op origins require explicit exact source-owned HTTPS hostnames',async()=>{
 const f=await fixture();
 for(const origins of [undefined,[],['https://127.0.0.1'],['https://signing-control.internal'],['https://github.com'],['https://account.example.test/'],['https://account.example.test:443'],['https://a.example.test','https://a.example.test']]){assert.throws(()=>runtime.validateSignerConfig({...f.config,opOrigins:origins}));}
 assert.equal(runtime.validateSignerConfig(f.config).opOrigins[0],'https://account.example.test');
});
test('expired final verification cannot return an authorized signature',async()=>{
 const f=await fixture();let now=1000;const signed=f.key.signature(f.payload);
 const signer=await runtime.createOpGitSigner({config:f.config,serviceToken:'SYNTHETIC',deadline:1100,clock:()=>now,authorize:async input=>({authorized:true,keyID:f.key.keyID,objectDigest:hash(input.payload),expiresAt:1050}),effects:{preflight:async()=>{},pin:async t=>t.path,startAgent:async()=>({close:async()=>{}}),run:async(program,args)=>{
  if(program.endsWith('/op'))return Buffer.from(f.key.privateKey);
  if(args.includes('-L'))return Buffer.from(f.config.publicKey+'\n');
  if(args.includes('sign'))return Buffer.from(signed);
  if(args.includes('check-novalidate'))now=1060;
  return Buffer.alloc(0);
 }}});
 try{await assert.rejects(signer.signGit({type:'commit',payload:f.payload,authorization:{}}));}finally{await signer.close();f.key.privateKey.fill(0);}
});
test('close waits for outstanding verification cleanup',async()=>{
 const f=await fixture();let started,release;const entered=new Promise(r=>{started=r;}),pending=new Promise(r=>{release=r;});let directory;
 const signer=await runtime.createOpGitSigner({config:f.config,deadline:Math.floor(Date.now()/1000)+60,authorize:async()=>{},effects:{preflight:async()=>{},pin:async t=>t.path,run:async(program,args,options)=>{directory=options.env.HOME;started();await pending;return Buffer.alloc(0);}}});
 const verification=signer.verifyGit({payload:f.payload,signature:f.key.signature(f.payload)});await entered;
 let done=false;const closing=signer.close().then(()=>{done=true;});await new Promise(r=>setTimeout(r,10));assert.equal(done,false);
 release();await verification;await closing;assert.equal(existsSync(directory),false);f.key.privateKey.fill(0);
});
test('signing snapshots exact authorized payload before asynchronous key loading',async()=>{
 const f=await fixture(),input={type:'commit',payload:f.payload,authorization:{}};let signedPayload;
 const signer=await runtime.createOpGitSigner({config:f.config,serviceToken:'SYNTHETIC',deadline:1100,clock:()=>1000,authorize:async value=>({authorized:true,keyID:f.key.keyID,objectDigest:hash(value.payload),expiresAt:1050}),effects:{preflight:async()=>{},pin:async t=>t.path,startAgent:async()=>({close:async()=>{}}),run:async(program,args,options)=>{
  if(program.endsWith('/op')){input.payload='MUTATED AFTER AUTHORIZATION';return Buffer.from(f.key.privateKey);}
  if(args.includes('-L'))return Buffer.from(f.config.publicKey+'\n');
  if(args.includes('sign')){signedPayload=options.input.toString();return Buffer.from(f.key.signature(signedPayload));}
  return Buffer.alloc(0);
 }}});
 try{await signer.signGit(input);assert.equal(signedPayload,f.payload);}finally{await signer.close();f.key.privateKey.fill(0);}
});

