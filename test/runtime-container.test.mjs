import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {canonical} from '../src/vendor/repoctl/ledger.mjs';
const moduleURL=new URL('../runtime/container-server.mjs',import.meta.url);
const runtime=existsSync(moduleURL)?await import(moduleURL):{};
const sha=value=>createHash('sha256').update(value).digest('hex');
function fixture(){
 const blob=Buffer.concat([Buffer.from('0000000b7373682d6564323535313900000020','hex'),Buffer.alloc(32,1)]);
 const keyID='SHA256:'+createHash('sha256').update(blob).digest('base64').replace(/=+$/,'');
 const toolchain=Object.fromEntries(Object.entries({op:'/usr/local/bin/op',sshAgent:'/usr/bin/ssh-agent',sshAdd:'/usr/bin/ssh-add',sshKeygen:'/usr/bin/ssh-keygen'}).map(([k,path])=>[k,{path,sha256:'a'.repeat(64)}]));
 const config={service:{schema:'signing-control-service/v1',repositoryID:7,repository:'fixture/source',git:{program:'/usr/bin/git',sha256:'b'.repeat(64),directory:'/run/signing-control/git',maxObjects:100,maxBytes:10000,authenticated:false},signer:{keyID}},runtime:{schema:'signing-control-op-agent/v1',opRef:'op://'+'a'.repeat(26)+'/'+'b'.repeat(26)+'/private_key?ssh-format=openssh',publicKey:'ssh-ed25519 '+blob.toString('base64'),keyID,opOrigins:['https://account.example.test'],toolchain},platform:{provider:'cloudflare-containers',imageDigest:'sha256:'+'c'.repeat(64)}};
 const job={version:1,id:'11111111-1111-4111-8111-111111111111',action:'lookupCandidate',input:{repositoryID:7,sequence:1},configDigest:sha(canonical(config)),deadline:1100};
 return {config,immutableConfig:{services:[config.service],runtime:config.runtime},job,callbackToken:'C'.repeat(43),serviceAccountToken:null};
}
// Synthetic handoff tests inject host qualification; production-preflight tests below exercise its denial rules.
const fixtureHandler=options=>runtime.createContainerHandler({preflight:async()=>{},...options});
const request=body=>new Request('http://container/v1/execute',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
test('one-shot handoff serves readiness, binds immutable config and never repeats execution',async()=>{
 assert.equal(typeof runtime.createContainerHandler,'function');const f=fixture(),calls=[];
 const handler=fixtureHandler({immutableConfig:f.immutableConfig,clock:()=>1000,launch:async x=>{calls.push(x);},onTerminal:()=>{}});
 assert.equal((await handler(new Request('http://container/ready'))).status,204);
 const {immutableConfig,...body}=f;assert.equal((await handler(request(body))).status,202);await new Promise(r=>setImmediate(r));assert.equal(calls.length,1);
 assert.deepEqual(calls[0],body);assert.equal((await handler(request(body))).status,409);assert.equal(calls.length,1);
});
test('malformed, expired, changed configuration and secret-bearing read handoffs fail closed',async()=>{
 for(const change of [f=>f.config.runtime.opRef=f.config.runtime.opRef.replace('a','c'),f=>f.job.deadline=1000,f=>f.job.action='sign',f=>f.serviceAccountToken='SYNTHETIC',f=>f.callbackToken='bad',f=>f.config.service.signer.keyID='SHA256:'+'A'.repeat(43),f=>f.job.configDigest='d'.repeat(64)]){
  const f=fixture(),immutableConfig=structuredClone(f.immutableConfig);delete f.immutableConfig;change(f);let calls=0;const handler=fixtureHandler({immutableConfig,clock:()=>1000,launch:async()=>{calls++;},onTerminal:()=>{}});
  assert.equal((await handler(request(f))).status,400);assert.equal(calls,0);assert.equal((await handler(request(f))).status,409);
 }
});
test('supervisor launch keeps private values in FD3/4 and permits only a bounded nonsecret receipt',async()=>{
 const f=fixture();delete f.immutableConfig;f.job.action='prepare';f.serviceAccountToken='SYNTHETIC-OP-TOKEN';
 let spawns=0;const source=`let body='';for await(const c of process.stdin)body+=c;const {readPrivateFD}=await import(${JSON.stringify(new URL('../runtime/private-fd.mjs',import.meta.url).href)});const token=await readPrivateFD(3),callback=await readPrivateFD(4);if(token!=='SYNTHETIC-OP-TOKEN'||callback!=='${'C'.repeat(43)}'||body.includes(token)||Object.values(process.env).includes(token))process.exit(2);process.stdout.write(JSON.stringify({jobId:JSON.parse(body).job.id,state:'completed'}));`;
 const receipt=await runtime.launchSupervisor(f,{preflight:async()=>{},clock:()=>1000,spawnImpl:(program,args,options)=>{spawns++;assert.ok(!JSON.stringify({args,env:options.env}).includes('SYNTHETIC-OP-TOKEN'));return spawn(program,['--input-type=module','-e',source],options);}});
 assert.deepEqual(receipt,{jobId:f.job.id,state:'completed'});assert.equal(spawns,1);assert.equal(f.serviceAccountToken,null);assert.equal(f.callbackToken,null);
 const bad=fixture();delete bad.immutableConfig;await assert.rejects(runtime.launchSupervisor(bad,{preflight:async()=>{},clock:()=>1000,spawnImpl:(program,args,options)=>spawn(program,['-e',"process.stdout.write('x'.repeat(9000));setInterval(()=>{},1000)"],options)}),/unavailable/);
});
test('supervisor completes once, redacts failures, and never retries ambiguous completion',async()=>{
 const url=new URL('../runtime/supervisor.mjs',import.meta.url);assert.equal(existsSync(url),true);const {runSupervisor}=await import(url);
 for(const mode of ['ok','execute-error','secret-result','lost-completion']){
  const f=fixture(),calls=[];const {immutableConfig,...body}=f;
  const result=await runSupervisor({body,immutableConfig,clock:()=>1000,execute:async input=>{assert.equal(input.serviceAccountToken,null);if(mode==='execute-error')throw Error('SYNTHETIC-PRIVATE');return mode==='secret-result'?{privateKey:'SYNTHETIC-PRIVATE'}:{repositoryID:7,verified:true};},transportFactory:()=>({call:async(path,input)=>{calls.push({path,input});if(mode==='lost-completion')throw Error('lost response');return {recorded:true};}})});
  assert.equal(calls.length,1);assert.equal(calls[0].path,'/v1/jobs/complete');assert.equal(calls[0].input.state,mode==='execute-error'||mode==='secret-result'?'uncertain':'completed');assert.equal(result.state,mode==='ok'?'completed':'uncertain');assert.ok(!JSON.stringify(result).includes('PRIVATE'));
 }
});
test('concurrent slow requests reserve the lifetime before parsing the private body',async()=>{
 const f=fixture();const handler=fixtureHandler({immutableConfig:f.immutableConfig,clock:()=>1000,launch:async()=>{},onTerminal:()=>{}});delete f.immutableConfig;
 let complete;const stream=new ReadableStream({start(c){complete=()=>{c.enqueue(new TextEncoder().encode(JSON.stringify(f)));c.close();};}});
 const first=handler(new Request('http://container/v1/execute',{method:'POST',body:stream,duplex:'half'}));
 assert.equal((await handler(request(f))).status,409);complete();assert.equal((await first).status,202);
});
test('promotion verification accepts only its receipt digest without an op token',async()=>{
 const f=fixture();f.job.action='verifyPromotion';f.job.input={receiptDigest:'d'.repeat(64)};let launches=0;const handler=fixtureHandler({immutableConfig:f.immutableConfig,clock:()=>1000,launch:async()=>{launches++;},onTerminal:()=>{}});delete f.immutableConfig;
 assert.equal((await handler(request(f))).status,202);await new Promise(r=>setImmediate(r));assert.equal(launches,1);
});
test('valid JSON prefix without EOF times out, cancels without awaiting an untrusted promise, and never launches',async()=>{
 const f=fixture();let launches=0;const handler=fixtureHandler({immutableConfig:f.immutableConfig,clock:()=>1000,bodyTimeoutMs:20,launch:async()=>{launches++;},onTerminal:()=>{}});delete f.immutableConfig;
 const body=new ReadableStream({start(c){c.enqueue(new TextEncoder().encode(JSON.stringify(f)));},cancel(){return new Promise(()=>{});}});
 const result=await handler(new Request('http://container/v1/execute',{method:'POST',body,duplex:'half'}));assert.equal(result.status,400);assert.equal(launches,0);
});
test('private FD reader consumes inherited socket pipes directly and rejects oversized values',async()=>{
 const path=new URL('../runtime/private-fd.mjs',import.meta.url).href;
 for(const [value,ok]of [['SYNTHETIC',true],['x'.repeat(200),false]]){
  const source=`import {readPrivateFD} from ${JSON.stringify(path)};try{const v=await readPrivateFD(3,{maxBytes:100,timeoutMs:1000});process.stdout.write(v==='SYNTHETIC'?'ok':'bad');}catch{process.stdout.write('denied');}`;
  const child=spawn(process.execPath,['--input-type=module','-e',source],{env:{PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe','pipe']});let output='';child.stdout.on('data',v=>output+=v);child.stderr.resume();child.stdio[3].end(JSON.stringify(value));await new Promise(r=>child.on('close',r));assert.equal(output,ok?'ok':'denied');
 }
});
test('readiness and private body parsing require current memory-safety preflight',async()=>{
 const f=fixture();let checks=0,launches=0,bytesRead=0;
 const handler=fixtureHandler({immutableConfig:f.immutableConfig,clock:()=>1000,preflight:async()=>{checks++;throw Error('unqualified memory');},launch:async()=>{launches++;},onTerminal:()=>{}});
 assert.equal((await handler(new Request('http://container/ready'))).status,503);
 const body=new ReadableStream({pull(){bytesRead++;}});assert.equal((await handler(new Request('http://container/v1/execute',{method:'POST',body,duplex:'half'}))).status,400);assert.equal(checks,2);assert.equal(launches,0);assert.ok(bytesRead<=1);
 const next=fixture();let fresh=0;const second=fixtureHandler({immutableConfig:next.immutableConfig,clock:()=>1000,preflight:async()=>{if(++fresh===2)throw Error('host state changed');},launch:async()=>{launches++;},onTerminal:()=>{}});delete next.immutableConfig;
 assert.equal((await second(request(next))).status,400);assert.equal(fresh,2);assert.equal(launches,0);
});
test('production memory preflight denies non-tmpfs, swap and core dumps without changing host settings',async()=>{
 const {assertPrivateMemory}=await import('../runtime/op-git-signer.mjs');assert.equal(typeof assertPrivateMemory,'function');
 for(const mode of ['tmpfs','swap','core'])await assert.rejects(assertPrivateMemory({statfsImpl:async()=>({type:mode==='tmpfs'?123:0x01021994}),readFileImpl:async path=>path==='/proc/swaps'?(mode==='swap'?'Filename Type Size Used Priority\n/swap file 10 0 -1\n':'Filename Type Size Used Priority\n'):(mode==='core'?'Max core file size unlimited unlimited bytes\n':'Max core file size 0 0 bytes\n')}));
 await assertPrivateMemory({statfsImpl:async()=>({type:0x01021994}),readFileImpl:async path=>path==='/proc/swaps'?'Filename Type Size Used Priority\n':'Max core file size 0 0 bytes\n'});
});
test('handoff action and configuration contract composes with the actual fixed source service',async()=>{
 const {ACTIONS,validateJobConfiguration}=await import('../src/service/run.mjs');const {validateHandoff,signingActions}=await import('../runtime/handoff.mjs');
 const identity='Fixture <fixture@example.test> 1000 +0000',sha='a'.repeat(40),digest='d'.repeat(64);
 const candidate={repositoryID:7,commitSHA:sha,shadowRef:'refs/heads/promotion/1/shadow'},sequence={repositoryID:7,sequence:1},receipt={receiptDigest:digest};
 const inputs={prepare:{repositoryID:7,sourcePR:{repositoryID:7,number:1,headSHA:sha},author:identity,committer:identity,message:'Fixture\n',artifactIntentDigest:digest,expiresAt:1100},retireShadow:sequence,publishShadow:sequence,approvalIntent:{...sequence,expiresAt:1100},approve:{...sequence,ownerApproval:{payload:'synthetic'}},publish:sequence,lookupCandidate:candidate,lookupReviewPolicy:candidate,lookupReceipt:receipt,verifyPromotion:receipt,prepareFeature:{repositoryID:7,baseSHA:sha,treeSHA:'b'.repeat(40),featureRef:'refs/heads/feature/fixture',message:'Fixture\n',author:identity,committer:identity,nonce:digest,expiresAt:1100},lookupFeature:{repositoryID:7,nonce:digest}};
 for(const action of ACTIONS){const f=fixture();f.job.action=action;f.job.input=structuredClone(inputs[action]);f.serviceAccountToken=signingActions.includes(action)?'SYNTHETIC':null;const {immutableConfig,...body}=f;assert.doesNotThrow(()=>validateJobConfiguration(body.job,body.config,1000),action);assert.doesNotThrow(()=>validateHandoff(body,immutableConfig,1000),action);}
});
test('image recipe requires a reviewed digest base, Node/setpriv pins and exact public runtime projection',async()=>{
 const url=new URL('../runtime/check-image.mjs',import.meta.url);assert.equal(existsSync(url),true);const {validateImageInputs}=await import(url);const f=fixture();
 const inputs={baseImage:'registry.example.test/reviewed/signer@sha256:'+'e'.repeat(64),nodeSHA256:'f'.repeat(64),setprivSHA256:'1'.repeat(64),config:f.immutableConfig};assert.doesNotThrow(()=>validateImageInputs(inputs));
 for(const change of [v=>v.baseImage='node:latest',v=>v.nodeSHA256='',v=>v.setprivSHA256=null,v=>v.config=f.config,v=>v.config.runtime.privateKey='secret']){const value=structuredClone(inputs);change(value);assert.throws(()=>validateImageInputs(value));}
});
test('PID1 boundary requires dedicated UID/GID, no capabilities and NoNewPrivs',async()=>{
 const {assertRuntimeIdentity}=await import('../runtime/container-server.mjs');assert.equal(typeof assertRuntimeIdentity,'function');const status='Uid:\t10001\t10001\t10001\t10001\nGid:\t10001\t10001\t10001\t10001\nGroups:\t\n'+['Inh','Prm','Eff','Bnd','Amb'].map(name=>'Cap'+name+':\t0000000000000000\n').join('')+'NoNewPrivs:\t1\n';
 await assertRuntimeIdentity({pid:1,readStatus:async()=>status});for(const altered of [status.replace('NoNewPrivs:\t1','NoNewPrivs:\t0'),status.replace('CapEff:\t0000000000000000','CapEff:\t0000000000000001'),status.replaceAll('10001','0')])await assert.rejects(assertRuntimeIdentity({pid:1,readStatus:async()=>altered}));await assert.rejects(assertRuntimeIdentity({pid:2,readStatus:async()=>status}));
});

test('one immutable image accepts seven exact approved repository profiles without changing per-job digest binding',async()=>{
 const {validateHandoff,validateImageConfiguration}=await import('../runtime/handoff.mjs');assert.equal(typeof validateImageConfiguration,'function');
 const f=fixture();f.immutableConfig.services=Array.from({length:7},(_,i)=>({...structuredClone(f.config.service),repositoryID:i+10,repository:`fixture/source-${i}`}));
 assert.deepEqual(validateImageConfiguration(f.immutableConfig),f.immutableConfig);
 for(const service of f.immutableConfig.services){const config={...f.config,service},job={...f.job,input:{repositoryID:service.repositoryID,sequence:1},configDigest:sha(canonical(config))};assert.doesNotThrow(()=>validateHandoff({job,config,serviceAccountToken:null,callbackToken:f.callbackToken},f.immutableConfig,1000));}
 const service={...f.immutableConfig.services[0],git:{...f.config.service.git,maxBytes:9000}},config={...f.config,service},job={...f.job,input:{repositoryID:service.repositoryID,sequence:1},configDigest:sha(canonical(config))};
 assert.throws(()=>validateHandoff({job,config,serviceAccountToken:null,callbackToken:f.callbackToken},f.immutableConfig,1000));
});
test('image allowlist rejects empty, duplicate, oversized or unpinned repository configurations',async()=>{
 const {validateImageConfiguration}=await import('../runtime/handoff.mjs');assert.equal(typeof validateImageConfiguration,'function');
 for(const mode of ['empty','id','name','large','key','extra','legacy']){const f=fixture(),image=structuredClone(f.immutableConfig);if(mode==='empty')image.services=[];if(mode==='id')image.services.push({...image.services[0],repository:'fixture/other'});if(mode==='name')image.services.push({...image.services[0],repositoryID:8});if(mode==='large')image.services=Array.from({length:33},(_,i)=>({...image.services[0],repositoryID:i+1,repository:`fixture/source-${i}`}));if(mode==='key')image.services[0].signer.keyID='SHA256:'+'A'.repeat(43);if(mode==='extra')image.services[0].remote='https://caller.test';if(mode==='legacy'){image.service=image.services[0];delete image.services;}assert.throws(()=>validateImageConfiguration(image),mode);}
});

