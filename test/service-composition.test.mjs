import test from 'node:test';
import assert from 'node:assert/strict';
import {createSigningController,configDigest} from '../cloudflare/controller.mjs';
import {createRemoteStorage} from '../src/service/adapters.mjs';
import {createSigningAuthorization} from '../src/service/authorization.mjs';
import {canonical} from '../src/vendor/repoctl/ledger.mjs';
import {fixture} from './service-fixture.mjs';

test('actual reviewed core and sign grant use controller durable CAS for commit and separately approved tags',async()=>{
 let controller,submitted,props;const data=new Map(),db={get:async k=>structuredClone(data.get(k)),put:async(k,v)=>data.set(k,structuredClone(v)),setAlarm:async()=>{},deleteAlarm:async()=>{},transaction:async fn=>fn(db)};
 const transport={call:(path,input)=>controller.callback(path,input,'Bearer '+submitted.callbackToken,props)};
 const storage=createRemoteStorage(transport),f=await fixture(storage);
 const config={service:{schema:'signing-control-service/v1',repositoryID:7,repository:'owner/project',git:{program:'/usr/bin/git',sha256:'a'.repeat(64),directory:'/run/signing-control/git',maxObjects:100,maxBytes:100000,authenticated:false},signer:{keyID:f.signer.keyID}},runtime:{schema:'signing-control-op-agent/v1',keyID:f.signer.keyID,opOrigins:['https://fixture.1password.com']},platform:{provider:'cloudflare-containers',imageDigest:'sha256:'+'b'.repeat(64)}};
 const container={running:false,async interceptOutboundHttps(_host,binding){props=binding.props;},start(){this.running=true;},async setInactivityTimeout(){},async inspect(){return this.running?{image:config.platform.imageDigest}:null;},async destroy(){this.running=false;},monitor(){return new Promise(()=>{});},getTcpPort(){return {fetch:async(url,options)=>{if(url.endsWith('/ready'))return new Response(null,{status:204});submitted=JSON.parse(options.body);return new Response(null,{status:202});}};}};
 const capabilities={policy:{...f.policy,authorizeFeatureCommit:async()=>({})},hardware:{verify:async()=>({})},ci:f.ci,review:f.review,scans:f.scans,inventory:{classify:async()=>({})},publisher:{...f.publisher,findPullRequest:async()=>null,createPullRequest:async()=>({}),deleteRef:async()=>{},closePullRequest:async()=>{}}};
 controller=createSigningController({storage:db,container,containerId:'fixture',config,capabilities,serviceToken:async()=> 'SYNTHETIC-ONLY',interceptor:p=>({props:p}),clock:()=>1000,sleep:async()=>{},waitUntil:()=>{}});
 const authorize=createSigningAuthorization({storage,policy:f.policy,git:f.git,signerKeyID:f.signer.keyID,approvalVerifier:f.approvalVerifier,ci:f.ci,review:f.review,scans:f.scans,clock:()=>1000}),sign=f.signer.signGit;
 const armor=payload=>'-----BEGIN SSH SIGNATURE-----\n'+Buffer.from('SYNTHETIC-NONCRYPTOGRAPHIC:'+payload).toString('base64')+'\n-----END SSH SIGNATURE-----\n';
 f.signer.signGit=async input=>{const grant=await authorize(input);assert.equal(grant.authorized,true);await sign(input);return armor(input.payload);};f.signer.verifyGit=async({payload,signature})=>signature===armor(payload);
 const execute=async(action,input)=>controller.execute({version:1,id:crypto.randomUUID(),action,input,configDigest:configDigest(config),deadline:1200});
 await execute('prepare',f.input);const candidate=await f.core.prepare(f.input);assert.equal(f.signatures.length,1);assert.ok(await storage.get('source-signing-effect:7:1:commit'));
 await transport.call('/v1/jobs/complete',{state:'completed',result:{sequence:1}});await controller.alarm();
 const approval={repositoryID:7,sequence:1,ownerApproval:{protocol:'synthetic-fixture',keyID:'f'.repeat(64),encoding:'synthetic-fixture',payload:canonical(candidate.approvalPayload),signature:'synthetic-fixture'}};
 await execute('approve',approval);assert.equal((await f.core.approve(approval)).state,'tagged');assert.equal(f.signatures.length,3);assert.ok(await storage.get('source-signing-effect:7:1:source'));assert.ok(await storage.get('source-signing-effect:7:1:main'));
 await assert.rejects(authorize(f.signatures[0]));assert.equal(f.signatures.length,3);
});
