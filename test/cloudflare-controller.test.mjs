import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
const url=new URL('../cloudflare/controller.mjs',import.meta.url);
async function implementation(){assert.ok(existsSync(url),'durable signing controller exists');return import(url.href);}
class Store{
 data=new Map();tail=Promise.resolve();alarm=null;
 async get(key){return structuredClone(this.data.get(key));}
 async put(key,value){this.data.set(key,structuredClone(value));}
 async setAlarm(value){this.alarm=value;}
 async deleteAlarm(){this.alarm=null;}
 async transaction(fn){const next=this.tail.then(()=>fn(this));this.tail=next.catch(()=>{});return next;}
}
async function fixture(){
 const api=await implementation();let now=1000,tokenReads=0,starts=0,submissions=0,destroys=0,submitted;const monitors=[];
 const config={service:{schema:'signing-control-service/v1',repositoryID:7,repository:'fixture/source',git:{program:'/usr/bin/git',sha256:'a'.repeat(64),directory:'/run/signing-control/git',maxObjects:100,maxBytes:100000,authenticated:false},signer:{keyID:'SHA256:'+'A'.repeat(43)}},runtime:{schema:'signing-control-op-agent/v1',keyID:'SHA256:'+'A'.repeat(43),opOrigins:['https://fixture.1password.com']},platform:{provider:'cloudflare-containers',imageDigest:'sha256:'+'b'.repeat(64)}};
 const store=new Store(),intercepts=[];
 const container={running:false,interceptOutboundHttps:async(host,binding)=>intercepts.push({host,binding}),start(options){assert.equal(options.enableInternet,false);starts++;this.running=true;},async setInactivityTimeout(){},async inspect(){return this.running?{image:config.platform.imageDigest}:null;},async destroy(){destroys++;this.running=false;},monitor(){return new Promise(resolve=>monitors.push(resolve));},getTcpPort(port){assert.equal(port,8080);return {fetch:async(url,options={})=>{if(url==='http://container/ready')return new Response(null,{status:204});assert.equal(url,'http://container/v1/execute');submissions++;submitted=JSON.parse(options.body);return new Response(null,{status:202});}};}};
 const capabilities={policy:{current:async()=>({authority:'workflow_depot',repositoryID:7,repository:'fixture/source',signerKeyID:config.service.signer.keyID}),authorizeCandidate:async()=>({}),authorizeFeatureCommit:async()=>({})},hardware:{verify:async()=>({})},ci:{verify:async()=>({})},scans:{verify:async()=>({})},review:{verify:async()=>({})},inventory:{classify:async()=>({})},publisher:Object.fromEntries(['putObject','readRef','createRef','findPullRequest','createPullRequest','deleteRef','closePullRequest'].map(name=>[name,async()=>({})]))};
 const opts={storage:store,container,containerId:'synthetic-container',config,capabilities,serviceToken:async()=>{tokenReads++;return 'SYNTHETIC-SERVICE-ONLY';},interceptor:props=>({props}),clock:()=>now,sleep:async()=>{},waitUntil:()=>{}};
 const controller=api.createSigningController(opts);
 const job={version:1,id:crypto.randomUUID(),action:'prepare',input:{repositoryID:7},configDigest:api.configDigest(config),deadline:1100};
 const props=()=>intercepts.at(-1).binding.props;
 const call=(path,input)=>controller.callback(path,input,'Bearer '+submitted.callbackToken,props());
 return {api,config,opts,controller,job,store,container,capabilities,intercepts,monitors,call,props,get submitted(){return submitted;},counts:()=>({tokenReads,starts,submissions,destroys}),advance:value=>now=value};
}

test('disabled Cloudflare source has no public routes or installed authority/credential placeholders',()=>{
 const path=new URL('../cloudflare/wrangler.jsonc',import.meta.url);assert.ok(existsSync(path),'disabled controller config exists');const config=JSON.parse(readFileSync(path,'utf8'));
 assert.equal(config.name,'signer');assert.equal(config.workers_dev,false);assert.equal(config.preview_urls,false);assert.deepEqual(config.routes,[]);
 assert.deepEqual(config.vars,{ENABLED:'false',SIGNING_CONTROL_CONFIG_JSON:'{}'});assert.equal(config.services,undefined);
 assert.deepEqual(config.durable_objects.bindings,[{name:'SIGNING_CONTROL_STATE',class_name:'SigningControlRepository'}]);assert.equal(config.containers[0].class_name,'SigningControlRepository');
});
test('one durable reservation launches one exact pinned image with private token handoff and fixed intercepts',async()=>{
 const f=await fixture(),status=await f.controller.execute(f.job);assert.equal(status.state,'running');assert.equal(f.counts().starts,1);assert.equal(f.counts().submissions,1);
 assert.deepEqual(f.intercepts.map(i=>i.host).sort(),['fixture.1password.com','github.com','signing-control.internal']);
 assert.deepEqual(f.submitted.job,f.job);assert.deepEqual(f.submitted.config,f.config);assert.equal(f.submitted.serviceAccountToken,'SYNTHETIC-SERVICE-ONLY');
 const persisted=JSON.stringify([...f.store.data]);assert.ok(!persisted.includes('SYNTHETIC-SERVICE-ONLY'));assert.ok(!persisted.includes(f.submitted.callbackToken));
 assert.equal((await f.controller.execute(f.job)).state,'running');assert.equal(f.counts().starts,1);await assert.rejects(f.controller.execute({...f.job,input:{repositoryID:7,other:true}}));
 await assert.rejects(f.controller.execute({...f.job,id:crypto.randomUUID()}));
});
test('missing capability, configuration drift, foreign repository or expired job deny before token/container effects',async()=>{
 for(const mode of ['capability','image','repository','digest','expiry']){
  const f=await fixture();let job=f.job;if(mode==='capability')delete f.capabilities.hardware.verify;if(mode==='image')f.config.platform.imageDigest='unqualified';if(mode==='repository')job={...job,input:{repositoryID:8}};if(mode==='digest')job={...job,configDigest:'c'.repeat(64)};if(mode==='expiry')f.advance(job.deadline);
  await assert.rejects(f.controller.execute(job));assert.deepEqual(f.counts(),{tokenReads:0,starts:0,submissions:0,destroys:0});
 }
});
test('metadata state uses atomic revision CAS, repository confinement and immutable receipt/effect tombstones',async()=>{
 const f=await fixture();await f.controller.execute(f.job);assert.deepEqual(await f.call('/v1/state/snapshot',{}),{revision:0,entries:[]});
 const write={expectedRevision:0,writes:[{key:'source-sequence:7',value:1},{key:'source-signing:7:1',value:{repositoryID:7,sequence:1,state:'reserved'}}]};
 assert.deepEqual(await f.call('/v1/state/transaction',write),{revision:1});await assert.rejects(f.call('/v1/state/transaction',write));
 const snapshot=await f.call('/v1/state/snapshot',{});assert.equal(snapshot.entries.length,2);
 await assert.rejects(f.call('/v1/state/transaction',{expectedRevision:1,writes:[{key:'source-signing:8:1',value:{repositoryID:8}}]}));
 const receipt={key:'source-signing-effect:7:1:commit',value:{repositoryID:7,sequence:1,kind:'candidate-policy',objectDigest:'d'.repeat(64),expiresAt:1100}};
 assert.deepEqual(await f.call('/v1/state/transaction',{expectedRevision:1,writes:[receipt]}),{revision:2});
 await assert.rejects(f.call('/v1/state/transaction',{expectedRevision:2,writes:[{...receipt,value:{repositoryID:7,sequence:2}}]}));
 await assert.rejects(f.call('/v1/state/transaction',{expectedRevision:2,writes:[{key:'source-signing:7:1',value:{privateKey:'forbidden'}}]}));
});
test('job-bound callbacks refuse wrong token, container, identity, source archive routes and unknown capabilities',async()=>{
 const f=await fixture();await f.controller.execute(f.job);
 await assert.rejects(f.controller.callback('/v1/state/snapshot',{},'Bearer '+'A'.repeat(43),f.props()));
 await assert.rejects(f.controller.callback('/v1/state/snapshot',{},'Bearer '+f.submitted.callbackToken,{...f.props(),containerId:'other'}));
 for(const path of ['/v1/capability/history/retain','/v1/capability/history/read','/v1/capability/source/fetch','/v1/capability/policy/unknown'])await assert.rejects(f.call(path,{input:{}}));
});
test('completion persists bounded nonsecret result, closes callbacks and destroys before releasing the repository',async()=>{
 const f=await fixture();await f.controller.execute(f.job);await f.call('/v1/jobs/complete',{state:'completed',result:{sequence:1}});
 await assert.rejects(f.call('/v1/state/snapshot',{}));await f.controller.alarm();
 const status=await f.controller.status(f.job.id);assert.equal(status.state,'completed');assert.deepEqual(status.result,{sequence:1});assert.equal(f.counts().destroys,1);
 await f.controller.execute({...f.job,id:crypto.randomUUID(),action:'lookupCandidate',input:{repositoryID:7,commitSHA:'a'.repeat(40),shadowRef:'refs/heads/promotion/1/shadow'}});
 assert.equal(f.counts().starts,2);assert.equal(f.counts().tokenReads,1);assert.equal(f.submitted.serviceAccountToken,null);
});
test('deadline/restart preserves uncertainty, destroys independently and never relaunches an admitted job',async()=>{
 const f=await fixture();await f.controller.execute(f.job);f.advance(f.job.deadline);const resumed=f.api.createSigningController(f.opts);await resumed.resume();await resumed.alarm();
 assert.equal((await resumed.status(f.job.id)).state,'uncertain');assert.equal(f.counts().starts,1);assert.equal(f.counts().destroys,1);
 await assert.rejects(resumed.execute({...f.job,id:crypto.randomUUID(),deadline:1200}));
});
test('expiry during token retrieval cannot hand off credentials or retry the action',async()=>{
 const f=await fixture();const controller=f.api.createSigningController({...f.opts,serviceToken:async()=>{f.advance(f.job.deadline);return 'SYNTHETIC-EXPIRED';}});
 const result=await controller.execute(f.job);assert.equal(result.state,'uncertain');assert.equal(f.counts().submissions,0);await controller.alarm();assert.equal(f.counts().destroys,1);
});
test('actual image mismatch denies token retrieval and successful result claims after expiry are rejected',async()=>{
 const f=await fixture();f.container.inspect=async()=>f.container.running?{image:'sha256:'+'c'.repeat(64)}:null;
 assert.equal((await f.controller.execute(f.job)).state,'uncertain');assert.equal(f.counts().tokenReads,0);assert.equal(f.counts().submissions,0);
 const g=await fixture();await g.controller.execute(g.job);g.advance(g.job.deadline);await assert.rejects(g.call('/v1/jobs/complete',{state:'completed',result:{}}));
});
test('late old monitor and concurrent cleanup never destroy the next container or clear its deadline',async()=>{
 const f=await fixture();await f.controller.execute(f.job);await f.call('/v1/jobs/complete',{state:'completed',result:{sequence:1}});
 await Promise.all([f.controller.alarm(),f.controller.alarm()]);assert.equal(f.counts().destroys,1);
 const next={...f.job,id:crypto.randomUUID(),deadline:1150};await f.controller.execute(next);f.monitors[0]();await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.counts().destroys,1);assert.equal(f.container.running,true);assert.equal(f.store.alarm,1150000);assert.equal((await f.controller.status(next.id)).state,'running');
});
test('private receipt and promotion verification preserve their exact digest-only input contract and need no op token',async()=>{
 for(const action of ['lookupReceipt','verifyPromotion']){const f=await fixture();await f.controller.execute({...f.job,action,input:{receiptDigest:'a'.repeat(64)}});assert.equal(f.counts().tokenReads,0);}
});
test('read-only actions cannot write durable state or invoke publisher mutations',async()=>{
 const f=await fixture();await f.controller.execute({...f.job,action:'lookupCandidate',input:{repositoryID:7,commitSHA:'a'.repeat(40),shadowRef:'refs/heads/promotion/1/shadow'}});
 await assert.rejects(f.call('/v1/state/transaction',{expectedRevision:0,writes:[{key:'source-sequence:7',value:1}]}));
 for(const method of ['putObject','createRef','createPullRequest'])await assert.rejects(f.call('/v1/capability/publisher/'+method,{input:{}}));
});
test('metadata writes deny archive fields and unrelated generation, and source credentials bind exact configured repository',async()=>{
 const f=await fixture();await f.controller.execute(f.job);
 await assert.rejects(f.call('/v1/state/transaction',{expectedRevision:0,writes:[{key:'source-signing:7:1',value:{repositoryID:7,sequence:1,state:'reserved',archive:'encoded-source'}}]}));
 await assert.rejects(f.call('/v1/capability/policy/current',{input:{repositoryID:8}}));
 await assert.rejects(f.call('/v1/capability/source/credential',{input:{repositoryID:8,repository:'other/source'}}));
});
test('GitHub egress admits only this repository normal Git read endpoints and denies redirect authority expansion',async()=>{
 const f=await fixture(),seen=[];const controller=f.api.createSigningController({...f.opts,fetcher:async request=>{seen.push(request);return new Response('git');}});await controller.execute(f.job);
 for(const [path,method]of [['/fixture/source.git/info/refs?service=git-upload-pack','GET'],['/fixture/source.git/git-upload-pack','POST']])assert.equal((await controller.outbound(new Request('https://github.com'+path,{method}),f.props())).status,200);
 for(const [path,method]of [['/other/source.git/git-upload-pack','POST'],['/fixture/source.git/git-receive-pack','POST'],['/fixture/source/issues','POST'],['/fixture/source.git/info/refs?service=git-receive-pack','GET']])await assert.rejects(controller.outbound(new Request('https://github.com'+path,{method}),f.props()));
 assert.equal(seen.length,2);assert.ok(seen.every(r=>r.redirect==='manual'));
});
test('private publication authority consumes only the exact retained generation grant once',async()=>{
 const f=await fixture(),sequence=3,commit='d'.repeat(40),ref='refs/heads/promotion/3/shadow',policy=await f.capabilities.policy.current({repositoryID:7});
 const effect={repository:'fixture/source',repositoryID:7,operation:'create-ref',ref,objectSHA:commit},requestDigest=f.api.configDigest(effect);
 await f.store.put('core:state',{revision:1,entries:[{key:'source-signing:7:3',value:{repositoryID:7,sequence,state:'awaiting-owner',config:policy,shadowRef:ref,finalSignedCommitSHA:commit}},{key:'source-shadow:7:3:ref',value:{commitSHA:commit,requestDigest:'e'.repeat(64)}},{key:'source-effect-grant:7:3:ref',value:{requestDigest,expiresAt:1050}}]});
 await f.controller.execute({...f.job,action:'publishShadow',input:{repositoryID:7,sequence}});
 await assert.rejects(f.controller.verifyPublication({...effect,objectSHA:'e'.repeat(40)}));
 const results=await Promise.allSettled([f.controller.verifyPublication(effect),f.controller.verifyPublication(effect)]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.deepEqual(results.find(r=>r.status==='fulfilled').value,{verified:true,requestDigest,expiresAt:1050});
 assert.ok(await f.store.get('source-effect-consumed:7:3:ref'));
});
test('publisher metadata callback rejects blob/tree and unretained signed metadata',async()=>{
 const f=await fixture(),policy=await f.capabilities.policy.current({repositoryID:7});await f.store.put('core:state',{revision:1,entries:[{key:'source-signing:7:1',value:{repositoryID:7,sequence:1,state:'awaiting-owner',config:policy,shadowRef:'refs/heads/promotion/1/shadow',finalSignedCommitSHA:'a'.repeat(40),signedCommit:'not-a-valid-retained-commit'}}]});await f.controller.execute({...f.job,action:'publishShadow',input:{repositoryID:7,sequence:1}});
 for(const type of ['blob','tree','commit','tag'])await assert.rejects(f.call('/v1/capability/publisher/putObject',{input:{type,payload:'source bytes'}}));
});
test('failed read releases the repository only after confirmed destruction; mutations retain uncertainty',async()=>{
 const f=await fixture(),read={...f.job,action:'lookupFeature',input:{repositoryID:7,nonce:'c'.repeat(64)}};await f.controller.execute(read);await f.call('/v1/jobs/complete',{state:'uncertain'});assert.equal(await f.store.get('control:active'),read.id);await f.controller.alarm();assert.equal((await f.controller.status(read.id)).state,'uncertain');assert.equal(await f.store.get('control:active'),null);await f.controller.execute({...f.job,id:crypto.randomUUID()});assert.equal(f.counts().starts,2);
});
test('actual source core prepare and two-tag approval persist through confined callback storage',async()=>{
 const {createSourceSigning,sha256}=await import('../src/vendor/repoctl/source-signing/core.mjs');const {mandatoryScanCategories}=await import('../src/vendor/repoctl/source-signing/scans.mjs');const {createRemoteStorage}=await import('../src/service/adapters.mjs');
 const f=await fixture(),canonical=f.api.canonical,hash=c=>c.repeat(64),sha=c=>c.repeat(40),policy={authority:'workflow_depot',repositoryID:7,repository:'fixture/source',sourceRef:'refs/heads/feature/source',targetRef:'refs/heads/main',signerKeyID:f.config.service.signer.keyID,policyDigest:hash('b')};
 policy.reviewPolicy={styleGuideDigest:hash('4'),styleGuideRevision:sha('5'),styleGuidePath:'docs/style.md',reviewerAppID:10,reviewerInstallationID:11,reviewerActorID:12,privilegedAppIDs:[20],privilegedActorIDs:[21],allowBotApproval:true,requiresHumanReview:false};
 policy.scanPolicy={supportedLanguages:['javascript'],supportedFrameworks:['node'],requiredCategories:[...mandatoryScanCategories],sonarqubeStandardRulesetDigest:hash('3'),requiredTools:mandatoryScanCategories.map(category=>({id:category==='quality'?'sonarqube':`synthetic-${category}`,category,version:'1',rulesetDigest:hash('3'),databaseMaxAgeSeconds:100})),exemptions:[]};
 f.capabilities.policy.current=async()=>policy;f.capabilities.policy.authorizeCandidate=async input=>({eligible:true,requestDigest:sha256(canonical(input)),policyDigest:policy.policyDigest,signerKeyID:policy.signerKeyID,expiresAt:1100});
 const inventory={digest:hash('2'),complete:true,paths:['index.mjs','package.json'],languages:['javascript'],frameworks:['node'],manifests:['package.json']};
 const snapshot={sourceSHA:sha('c'),sourceBaseSHA:sha('a'),mainSHA:sha('a'),treeSHA:sha('d'),historyDigest:hash('e'),retentionReference:'local-immutable-fixture',verified:true,inventory};
 const signature='-----BEGIN SSH SIGNATURE-----\nU1lOVEhFVElD\n-----END SSH SIGNATURE-----\n',signed=[];
 const signer={keyID:policy.signerKeyID,signGit:async input=>{signed.push(input.type);return signature;},verifyGit:async value=>value.signature===signature};
 const ci={verify:async input=>({verified:true,requestDigest:sha256(canonical(input))})},review={verify:async input=>({verified:true,receipt:{schema:'repoctl-source-review/v1',...Object.fromEntries(['repositoryID','sourcePRNumber','sourceSHA','baseSHA','commitSHA','treeSHA','policyDigest'].map(k=>[k,input[k]])),...Object.fromEntries(['styleGuideDigest','styleGuideRevision','styleGuidePath','reviewerAppID','reviewerInstallationID','reviewerActorID'].map(k=>[k,policy.reviewPolicy[k]])),methods:['deterministic-style','security-tests','evidence-review'],verdict:'approved',findings:[],humanReviewVerified:false,expiresAt:1100}})},scans={verify:async input=>({verified:true,receipt:{schema:'repoctl-source-scans/v1',repositoryID:7,commitSHA:input.commitSHA,treeSHA:input.treeSHA,policyDigest:input.policyDigest,inventoryDigest:inventory.digest,tools:policy.scanPolicy.requiredTools.map(({databaseMaxAgeSeconds,...tool})=>({...tool,status:'passed',commitSHA:input.commitSHA,inventoryDigest:inventory.digest,coveredPaths:inventory.paths,databaseUpdatedAt:995,completedAt:1000,evidenceDigest:hash('1')}))}})};
 const storage=createRemoteStorage({call:f.call});const core=createSourceSigning({storage,policy:f.capabilities.policy,git:{snapshot:async()=>snapshot,main:async()=>snapshot.mainSHA,source:async()=>snapshot.sourceSHA},signer,approvalVerifier:{verify:async()=>({ownerKeyID:hash('f'),hardwareVerified:true,proofDigest:hash('9'),validUntil:1100})},ci,review,scans,publisher:{putObject:async()=>{},readRef:async()=>null,createRef:async()=>{}},clock:()=>1000});
 const input={repositoryID:7,sourcePR:{number:9,repositoryID:7,headSHA:sha('c')},author:'Owner <owner@example.test> 1000 +0000',committer:'Signer <signer@example.test> 1000 +0000',message:'Synthetic source candidate\n',artifactIntentDigest:hash('8'),expiresAt:1100};
 await f.controller.execute({...f.job,input});const candidate=await core.prepare(input);await f.call('/v1/jobs/complete',{state:'completed',result:candidate});await f.controller.alarm();
 const approval={repositoryID:7,sequence:candidate.sequence,ownerApproval:{protocol:'fixture',keyID:hash('f'),encoding:'p1363',payload:canonical(candidate.approvalPayload),signature:'synthetic'}};await f.controller.execute({...f.job,id:crypto.randomUUID(),action:'approve',input:approval});assert.equal((await core.approve(approval)).state,'tagged');assert.deepEqual(signed,['commit','tag','tag']);
 const retained=await storage.get('source-signing:7:1');assert.deepEqual(Object.keys(retained.tags).sort(),['main','source']);
});
test('state metadata rejects object-valued request fields and nested authority booleans',async()=>{
 const f=await fixture();await f.controller.execute(f.job);
 for(const value of [{repositoryID:7,sequence:1,state:'reserved',author:{unexpected:'opaque'}},{repositoryID:7,sequence:1,state:'reserved',candidateAuthorization:{eligible:{opaque:'bytes'},requestDigest:'a'.repeat(64),policyDigest:'b'.repeat(64),signerKeyID:f.config.service.signer.keyID,expiresAt:1100}}])await assert.rejects(f.call('/v1/state/transaction',{expectedRevision:0,writes:[{key:'source-sequence:7',value:1},{key:'source-signing:7:1',value}]}));
});
async function featureFixture(){
 const f=await fixture(),input={repositoryID:7,baseSHA:'a'.repeat(40),treeSHA:'b'.repeat(40),featureRef:'refs/heads/fix/approved',message:'Approved producer intent\n',author:'Producer <producer@example.test> 1000 +0000',committer:'Producer <producer@example.test> 1000 +0000',nonce:'c'.repeat(64),expiresAt:1100};let authorizations=0,consumes=0,checks=0;
 for(const name of Object.keys(f.capabilities))if(name!=='policy')delete f.capabilities[name];delete f.capabilities.policy.authorizeCandidate;
 const grant=request=>({authorized:true,requestDigest:f.api.configDigest(request),policyDigest:'d'.repeat(64),signerKeyID:f.config.service.signer.keyID,producerID:'fixture-producer',producerEvidenceDigest:'e'.repeat(64),grantID:'f'.repeat(64),expiresAt:1090});
 f.capabilities.policy.current=async()=>({authority:'workflow_depot',repositoryID:7,repository:'fixture/source',signerKeyID:f.config.service.signer.keyID,policyDigest:'d'.repeat(64)});
 f.capabilities.policy.authorizeFeatureCommit=async request=>{authorizations++;return grant(request);};f.capabilities.policy.consumeFeatureCommit=async({request})=>{consumes++;return grant(request);};f.capabilities.policy.checkFeatureCommit=async({request})=>{checks++;return grant(request);};
 return {...f,job:{...f.job,action:'prepareFeature',input},grant,featureCounts:()=>({authorizations,consumes,checks})};
}
test('feature metadata admission requires depot grant before container/token effects, without promotion or tree dependencies',async()=>{
 const f=await featureFixture();const status=await f.controller.execute(f.job);assert.equal(status.state,'running');assert.equal(f.counts().starts,1);assert.ok(f.featureCounts().authorizations>=1);
 const retained=await f.store.get('control:job:'+f.job.id);assert.equal(retained.featureGrant.producerID,'fixture-producer');assert.equal(retained.featureGrant.producerEvidenceDigest,'e'.repeat(64));assert.equal(f.store.alarm,1090000);
 const g=await featureFixture();g.capabilities.policy.authorizeFeatureCommit=async()=>({authorized:true});await assert.rejects(g.controller.execute(g.job));assert.equal(g.counts().tokenReads,0);assert.equal(g.counts().starts,0);
});
test('feature metadata rejects arbitrary bytes, main ref and malformed commit fields before depot or token effects',async()=>{
 for(const changes of [{payload:'arbitrary bytes'},{featureRef:'refs/heads/main'},{treeSHA:'x'},{author:'newline\nidentity'},{closureDigest:'a'.repeat(64)}]){const f=await featureFixture();await assert.rejects(f.controller.execute({...f.job,input:{...f.job.input,...changes}}));assert.equal(f.featureCounts().authorizations,0);assert.equal(f.counts().starts,0);}
});
test('actual feature signer consumes exact depot grant through durable controller callbacks before synthetic signature and returns only retained result',async()=>{
 const {createFeatureSigning}=await import('../src/service/feature.mjs'),{createRemoteStorage,createCapabilities}=await import('../src/service/adapters.mjs');const f=await featureFixture();await f.controller.execute(f.job);
 const transport={call:f.call},storage=createRemoteStorage(transport),caps=createCapabilities(transport);let signerCalls=0,core;
 const signature='-----BEGIN SSH SIGNATURE-----\nU1lOVEhFVElD\n-----END SSH SIGNATURE-----\n';const signer={keyID:f.config.service.signer.keyID,signGit:async input=>{const proof=await core.authorize(input);assert.equal(proof.authorized,true);assert.equal(f.featureCounts().consumes,1);signerCalls++;return signature;},verifyGit:async input=>input.signature===signature};
 core=createFeatureSigning({config:f.config.service,storage,policy:caps.policy,signer,clock:()=>1000});
 await assert.rejects(f.call('/v1/capability/policy/consumeFeatureCommit',{input:{request:{},grantID:'f'.repeat(64)}}));assert.equal(f.featureCounts().consumes,0);
 const result=await core.prepare(f.job.input);assert.equal(signerCalls,1);assert.equal(result.receipt.claim,'authenticated-producer-intent');assert.equal(result.receipt.closureDigest,undefined);assert.equal(f.featureCounts().checks,1);
 const row=await storage.get('source-feature:7:'+f.job.input.nonce);assert.equal(row.proof,undefined);assert.equal(row.signingConsumed,true);
 await assert.rejects(f.call('/v1/capability/policy/consumeFeatureCommit',{input:{request:row.request,grantID:row.authorization.grantID}}));assert.equal(f.featureCounts().consumes,1);
 await assert.rejects(f.call('/v1/jobs/complete',{state:'completed',result:{...result,arbitrary:'payload'}}));await f.call('/v1/jobs/complete',{state:'completed',result});await f.controller.alarm();assert.deepEqual((await f.controller.status(f.job.id)).result,result);
});
test('feature grant expiry, drift and missing consume/check never start effects or extend retained admission',async()=>{
 for(const mode of ['expired','foreign-policy','missing-consume','missing-check']){const f=await featureFixture();if(mode==='expired')f.capabilities.policy.authorizeFeatureCommit=async req=>({...f.grant(req),expiresAt:1000});if(mode==='foreign-policy')f.capabilities.policy.authorizeFeatureCommit=async req=>({...f.grant(req),policyDigest:'a'.repeat(64)});if(mode==='missing-consume')delete f.capabilities.policy.consumeFeatureCommit;if(mode==='missing-check')delete f.capabilities.policy.checkFeatureCommit;await assert.rejects(f.controller.execute(f.job));assert.equal(f.counts().starts,0);assert.equal(f.counts().tokenReads,0);}
 const f=await featureFixture();await f.controller.execute(f.job);f.advance(1090);await assert.rejects(f.call('/v1/state/snapshot',{}));await f.controller.alarm();assert.equal((await f.controller.status(f.job.id)).state,'uncertain');assert.equal(f.counts().destroys,1);
});
test('operator installation selects exact allowlisted repository config and never guesses multi-repository receipt scope',async()=>{
 const f=await fixture(),second={...f.config.service,repositoryID:8,repository:'fixture/second'},installation={services:[f.config.service,second],runtime:f.config.runtime,platform:f.config.platform};
 assert.deepEqual(f.api.selectConfiguration(installation,7),f.config);assert.equal(f.api.selectConfiguration(installation,8).service.repository,'fixture/second');assert.deepEqual(f.api.selectConfiguration(f.config),f.config);
 for(const id of [undefined,9,'7',0])assert.throws(()=>f.api.selectConfiguration(installation,id));
 for(const services of [[f.config.service,f.config.service],[f.config.service,{...second,repository:f.config.service.repository}],Array.from({length:33},(_,i)=>({...second,repositoryID:i+1,repository:'fixture/repo'+i}))])assert.throws(()=>f.api.validateInstallation({...installation,services}));
 await assert.rejects(f.controller.execute({...f.job,input:{repositoryID:8}}));assert.equal(f.counts().starts,0);assert.equal(f.counts().tokenReads,0);
});

