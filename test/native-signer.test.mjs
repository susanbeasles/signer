import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {SignerService} from '../native/service.mjs';
import {GitHub,manifest} from '../native/github.mjs';
import {b64url,commitBytes,digest,encode,ORIGIN} from '../native/protocol.mjs';
import {seal,open} from '../native/sealed.mjs';
import {workload} from '../native/identity.mjs';
import {verifyCommit} from '../native/ssh.mjs';
import {remoteSign} from '../native/client.mjs';
const run=promisify(execFile),repo='susanbeasles/signer';
const commit='tree '+'a'.repeat(40)+'\nauthor Susan B <215839550+susanbeasles@users.noreply.github.com> 1792832400 +0000\ncommitter Susan B <215839550+susanbeasles@users.noreply.github.com> 1792832400 +0000\n\nTest commit\n';
class Storage {
  constructor(){this.values=new Map();this.queue=Promise.resolve();}
  async get(key){return structuredClone(this.values.get(key));}
  async put(key,value){this.values.set(key,structuredClone(value));}
  async delete(key){return this.values.delete(key);}
  async list({prefix='',limit=1000}={}){return new Map([...this.values].filter(([k])=>k.startsWith(prefix)).slice(0,limit));}
  async transaction(fn){const operation=this.queue.then(()=>fn(this));this.queue=operation.catch(()=>{});return operation;}
}
function fixture(){
  const storage=new Storage(),keys=new Map();let time=1792832400000,nextID=1;
  const github={async registerKey(record){const id=nextID++;keys.set(id,{...record,id,key:record.publicKey});return id;},async keys(){return [...keys.values()];},async removeKey(record){const key=keys.get(record.githubID);assert.equal(key.title,record.title);assert.equal(key.key,record.publicKey);keys.delete(record.githubID);}};
  const service=new SignerService(storage,null,{github,now:()=>time});
  return {storage,keys,github,service,now:()=>time,advance:ms=>{time+=ms;}};
}
async function session(f){const p=await f.service.bootstrap({repository:repo},'test-client');await f.service.approve({id:p.id},{subject:'owner'});return f.service.redeem({id:p.id,secret:p.secret});}
async function fetcher(f,url,options){const request=JSON.parse(options.body),token=options.headers.authorization.slice(7);try{
  const path=new URL(url).pathname;const value=path==='/v1/grants'?await f.service.grant(request,token):path==='/v1/sign'?await f.service.sign(request,token):await f.service.key(token);return Response.json(value);
}catch(error){return Response.json({error:error.message},{status:error.status||503});}}
test('commit framing rejects embedded signatures, injected headers, invalid identities and bounded data',()=>{
  assert.equal(commitBytes(commit).length,Buffer.byteLength(commit));
  for(const value of [commit.replace('tree ','gpgsig bad\ntree '),commit.replace('author ','encoding utf8\nauthor '),commit.replace(' +0000',' bad'),commit+'\0',commit.replace(/\n/g,'\r\n'),'x'.repeat(262145)])assert.throws(()=>commitBytes(value));
});
test('manifest requests only SSH signing-key administration with canonical callbacks',()=>{
  const value=manifest();assert.deepEqual(value.default_permissions,{git_signing_ssh_public_keys:'write'});assert.match(value.name,/^signer-[a-f0-9]{12}$/);assert.notEqual(value.name,manifest().name);assert.equal(value.redirect_url,ORIGIN+'/github/manifest');assert.equal(value.public,false);
});
test('credential envelopes authenticate their purpose and cannot be decrypted after tampering',async()=>{
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  const envelope=await seal(key,'app',{test:'synthetic'});assert.equal(JSON.stringify(envelope).includes('synthetic'),false);assert.deepEqual(await open(key,'app',envelope),{test:'synthetic'});await assert.rejects(open(key,'tokens',envelope));
  const exported=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);await assert.rejects(seal(exported,'app',{}));
});
test('owner-approved bootstrap is expiring, one-use, and repository restricted',async()=>{
  const f=fixture(),p=await f.service.bootstrap({repository:repo},'test');
  await assert.rejects(f.service.redeem({id:p.id,secret:p.secret}),/pending/);
  await assert.rejects(f.service.bootstrap({repository:'susanbeasles/other'},'test'),/repository/);
  await f.service.approve({id:p.id},{subject:'owner'});await f.service.redeem({id:p.id,secret:p.secret});await assert.rejects(f.service.redeem({id:p.id,secret:p.secret}),/consumed/);
  const p2=await f.service.bootstrap({repository:repo},'test');f.advance(600001);await assert.rejects(f.service.approve({id:p2.id},{subject:'owner'}),/pending/);
});
test('exact signing, replay races, cross-repository requests, tampering, expiry and revocation',async()=>{
  const f=fixture(),s=await session(f),grant=await f.service.grant({repository:repo,commit},s.session);
  await assert.rejects(f.service.sign({repository:'susanbeasles/other',commit,grant:grant.grant},s.session),/repository/);
  await assert.rejects(f.service.sign({repository:repo,commit:commit+'changed',grant:grant.grant},s.session),/grant/);
  const results=await Promise.allSettled([1,2].map(()=>f.service.sign({repository:repo,commit,grant:grant.grant},s.session)));
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  const signed=results.find(r=>r.status==='fulfilled').value;assert(await verifyCommit(signed.publicKey,signed.signature,encode(commit)));assert.equal(await verifyCommit(signed.publicKey,signed.signature,encode(commit+'changed')),false);
  const grant2=await f.service.grant({repository:repo,commit},s.session);f.advance(60001);await assert.rejects(f.service.sign({repository:repo,commit,grant:grant2.grant},s.session),/grant/);
  const key=await f.service.key(s.session);await f.service.revoke({sessionID:key.sessionID});await assert.rejects(f.service.grant({repository:repo,commit},s.session),/unauthorized/);
  await assert.rejects(f.service.key('x'.repeat(43)),/unauthorized/);
});
test('private keys are non-extractable, never durable, replaced on restart and cleaned safely',async()=>{
  const f=fixture(),s=await session(f),first=await f.service.key(s.session),identity=await f.service.identity(await f.service.session(s.session));
  assert.equal(identity.privateKey.extractable,false);await assert.rejects(crypto.subtle.exportKey('pkcs8',identity.privateKey));
  assert.equal([...f.storage.values.values()].some(v=>v?.privateKey!==undefined),false);
  const secondService=new SignerService(f.storage,null,{github:f.github,now:f.now});const second=await secondService.key(s.session);assert.notEqual(second.publicKey,first.publicKey);
  f.keys.set(900,{id:900,title:'unrelated',key:'unrelated'});
  f.advance(25*60*60*1000);await secondService.cleanup();assert.deepEqual([...f.keys.keys()],[900]);
});
test('bootstrap and signing limits are enforced durably across runtime restarts',async()=>{
  const f=fixture();for(let i=0;i<5;i++)await f.service.bootstrap({repository:repo},'one-ip');
  const next=new SignerService(f.storage,null,{github:f.github,now:f.now});await assert.rejects(next.bootstrap({repository:repo},'one-ip'),/rate-limited/);
});
test('GitHub refresh is serialized and an uncertain exchange is not replayed after restart',async()=>{
  const storage=new Storage(),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);let calls=0;
  const github=new GitHub(storage,key,async()=>{calls++;return Response.json({access_token:'synthetic-next',refresh_token:'synthetic-refresh-next',expires_in:3600,refresh_token_expires_in:7200});});
  await storage.put('app',{clientID:'synthetic-client'});await github.save('app',{clientSecret:'synthetic-secret'});await github.save('tokens',{access:'synthetic-expired',refresh:'synthetic-refresh',expires:0,refreshExpires:Date.now()+3600000});
  const tokens=await Promise.all([github.token(),github.token()]);assert.deepEqual(tokens,['synthetic-next','synthetic-next']);assert.equal(calls,1);
  await github.save('tokens',{access:'expired',refresh:'consumed',expires:0,refreshExpires:Date.now()+3600000});await storage.put('refresh-in-flight',{});
  await assert.rejects(new GitHub(storage,key,async()=>{throw Error('must not call');}).token(),/reauthorization/);assert.equal(calls,1);
});
test('key registration reconciles interrupted creation and refuses unrelated deletion',async()=>{
  const storage=new Storage(),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),requests=[];
  const github=new GitHub(storage,key,async(url,opts)=>{requests.push({url,method:opts.method});return Response.json([{id:12,key:'public',title:'signer:owned'}]);});
  await github.save('tokens',{access:'synthetic',expires:Date.now()+3600000});
  assert.equal(await github.registerKey({publicKey:'public',title:'signer:owned'}),12);assert.equal(requests.length,1);
  await assert.rejects(github.removeKey({githubID:12,publicKey:'different',title:'signer:owned'}),/ownership/);assert.equal(requests.some(r=>r.method==='DELETE'),false);
});
test('OAuth state is one-use and the privileged owner identity is checked before token custody',async()=>{
  const storage=new Storage(),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  const github=new GitHub(storage,key,async url=>Response.json(url.includes('/user')?{id:999,login:'other'}:{access_token:'synthetic',refresh_token:'synthetic',expires_in:3600,refresh_token_expires_in:7200}));
  await storage.put('app',{clientID:'synthetic'});await github.save('app',{clientSecret:'synthetic'});
  const start=await github.oauthStart();assert.equal(new URL(start.url).searchParams.get('code_challenge_method'),'S256');await assert.rejects(github.oauthComplete('synthetic-code',start.state),/owner-denied/);assert.equal(await github.secret('tokens'),null);await assert.rejects(github.oauthComplete('synthetic-code',start.state),/state-denied/);
});
test('signed workload JWTs validate exact issuer, audience, repository, workflow, actor, expiry and replay',async()=>{
  const f=fixture(),pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']),jwk=await crypto.subtle.exportKey('jwk',pair.publicKey),now=Math.floor(Date.now()/1000);
  const policy={repositories:[repo],repositoryIDs:{[repo]:'1416201242'},actors:['215839550'],workflows:[repo+'/.github/workflows/agent.yml@refs/heads/main']};
  const claims={iss:'https://token.actions.githubusercontent.com',aud:ORIGIN,iat:now,exp:now+300,repository:repo,repository_id:'1416201242',repository_owner_id:'215839550',actor_id:'215839550',event_name:'workflow_dispatch',ref:'refs/heads/main',sub:'test-run',jti:'one-run',workflow_ref:policy.workflows[0]};
  const token=async change=>{const parts=[b64url(encode(JSON.stringify({alg:'RS256',kid:'test'}))),b64url(encode(JSON.stringify({...claims,...change})))];return parts.join('.')+'.'+b64url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,encode(parts.join('.'))));};
  const options={now,fetcher:async()=>Response.json({keys:[{...jwk,kid:'test'}]})};
  const identity=await workload(await token({}),policy,options);assert.equal(identity.repository,repo);
  for(const change of [{aud:'wrong'},{iss:'https://evil.invalid'},{exp:now-1},{actor_id:'1'},{repository:'susanbeasles/other'},{event_name:'pull_request'},{workflow_ref:'evil'},{ref:'refs/heads/../bad'}])await assert.rejects(workload(await token(change),policy,options));
  await f.service.workloadSession(identity);await assert.rejects(f.service.workloadSession(identity),/replayed/);
});
test('remote adapter verifies the signed response and does not retry uncertain signing requests',async()=>{
  const f=fixture(),s=await session(f),fetch=fetcher.bind(null,f);
  assert.match(await remoteSign(commit,{session:s.session,repository:repo,fetcher:fetch}),/BEGIN SSH SIGNATURE/);
  let calls=0;await assert.rejects(remoteSign(commit,{session:s.session,repository:repo,fetcher:async(url,opts)=>{calls++;if(url.endsWith('/v1/sign'))throw Error('uncertain response');return fetch(url,opts);}}),/uncertain/);assert.equal(calls,2);
});
test('actual git commit -S invokes the SSH adapter and OpenSSH verifies its signature',async()=>{
  const f=fixture(),s=await session(f),directory=await mkdtemp(join(tmpdir(),'signer-git-test-'));
  const server=createServer(async(req,res)=>{try{const chunks=[];for await(const c of req)chunks.push(c);const response=await fetcher(f,ORIGIN+req.url,{body:Buffer.concat(chunks).toString(),headers:{authorization:req.headers.authorization}});res.writeHead(response.status,{'content-type':'application/json'});res.end(await response.text());}catch{res.writeHead(503);res.end('{}');}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const port=server.address().port,client=resolve('native/client.mjs');
    const wrapper=join(directory,'adapter.mjs');
    await writeFile(wrapper,`#!/usr/bin/env node\nimport {main} from ${JSON.stringify('file://'+client)};\nconst originalFetch=fetch;globalThis.fetch=(url,options)=>originalFetch('http://127.0.0.1:${port}'+new URL(url).pathname,options);\ntry{process.stdout.write(await main(process.argv.slice(2)));}catch(error){process.stderr.write(error.message+' '+JSON.stringify(process.argv.slice(2)));process.exitCode=1;}\n`,{mode:0o700});
    const git=async(...args)=>(await run('git',args,{cwd:directory,env:{...process.env,GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',SIGNER_SESSION:s.session,SIGNER_REPOSITORY:repo,GIT_AUTHOR_NAME:'Susan B',GIT_AUTHOR_EMAIL:'215839550+susanbeasles@users.noreply.github.com',GIT_COMMITTER_NAME:'Susan B',GIT_COMMITTER_EMAIL:'215839550+susanbeasles@users.noreply.github.com'}})).stdout;
    await git('init','-q');
    const key=await f.service.key(s.session);await writeFile(join(directory,'allowed'),`215839550+susanbeasles@users.noreply.github.com ${key.publicKey}\n`);
    await git('-c','gpg.format=ssh','-c','user.signingkey=key::'+key.publicKey,'-c','gpg.ssh.program='+wrapper,'commit','--allow-empty','-S','-m','Remote signing integration');
    const verified=await git('-c','gpg.format=ssh','-c','gpg.ssh.allowedSignersFile='+join(directory,'allowed'),'verify-commit','HEAD');
    assert.equal(verified,'');assert.match(await git('cat-file','commit','HEAD'),/gpgsig -----BEGIN SSH SIGNATURE-----/);
  }finally{await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});}
});

test('GitHub provider redirects are rejected without following or forwarding credentials',async()=>{
  let calls=0;
  const github=new GitHub(new Storage(),null,async(url,options)=>{
    calls++;assert.equal(options.redirect,'manual');
    return new Response(null,{status:302,headers:{location:'https://foreign.invalid/'}});
  });
  await assert.rejects(github.request('/user',{token:'synthetic'}),/provider-request-failed/);
  assert.equal(calls,1);
});
