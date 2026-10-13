import test from 'node:test';
import assert from 'node:assert/strict';
import {createFeatureSigning} from '../src/service/feature.mjs';
import {canonical} from '../src/vendor/repoctl/ledger.mjs';
import {sha256,gitObjectID} from '../src/vendor/repoctl/source-signing/core.mjs';

function fixture(){let now=1000,signs=0,consumes=0,consumed=false;const rows=new Map(),storage={get:async k=>structuredClone(rows.get(k)),put:async(k,v)=>rows.set(k,structuredClone(v)),transaction:async fn=>fn(storage)};
 const config={repositoryID:7,repository:'fixture/source',signer:{keyID:'SHA256:'+'A'.repeat(43)}};
 const input={repositoryID:7,baseSHA:'a'.repeat(40),treeSHA:'b'.repeat(40),featureRef:'refs/heads/feature/reviewed',message:'Producer change\n',author:'Owner <owner@example.test> 1000 +0000',committer:'Owner <owner@example.test> 1000 +0000',nonce:'c'.repeat(64),expiresAt:1200};
 const grant=req=>({authorized:true,requestDigest:sha256(canonical(req)),policyDigest:'e'.repeat(64),signerKeyID:config.signer.keyID,producerID:'fixture:approved-producer',producerEvidenceDigest:'f'.repeat(64),grantID:'d'.repeat(64),expiresAt:1100});
 const policy={authorizeFeatureCommit:async req=>{assert.equal(consumed,false);return grant(req);},consumeFeatureCommit:async({request,grantID})=>{assert.equal(consumed,false);assert.equal(grantID,'d'.repeat(64));assert.equal([...rows.values()][0].signingConsumed,true);consumed=true;consumes++;return grant(request);},checkFeatureCommit:async({request,grantID})=>{assert.equal(consumed,true);assert.equal(grantID,'d'.repeat(64));return grant(request);}};
 let api;const signer={keyID:config.signer.keyID,signGit:async req=>{await api.authorize(req);signs++;assert.equal(req.type,'commit');return 'SYNTHETIC SIGNATURE\n';},verifyGit:async()=>true};
 api=createFeatureSigning({config,storage,policy,signer,clock:()=>now});return {api,config,input,storage,policy,signer,grant,rows,advance:n=>now=n,counts:()=>({signs,consumes})};
}
test('remote feature signs canonical metadata under consumed producer grant without claiming local tree proof',async()=>{
 const f=fixture(),result=await f.api.prepare(f.input),{receipt,signature}=result;assert.equal(receipt.claim,'authenticated-producer-intent');assert.equal(receipt.producerID,'fixture:approved-producer');assert.equal(receipt.grantID,'d'.repeat(64));assert.equal(receipt.featureRef,f.input.featureRef);assert.equal(receipt.baseSHA,f.input.baseSHA);assert.equal(receipt.treeSHA,f.input.treeSHA);assert.match(receipt.commitSHA,/^[a-f0-9]{40}$/);assert.equal(signature,'SYNTHETIC SIGNATURE\n');assert.equal(receipt.closureDigest,undefined);assert.equal(receipt.complete,undefined);
 const record=[...f.rows.values()][0];assert.equal(record.proof,undefined);assert.equal(record.request.closureDigest,undefined);assert.equal(record.state,'signed');assert.equal(record.request.unsignedCommit,`tree ${f.input.treeSHA}\nparent ${f.input.baseSHA}\nauthor ${f.input.author}\ncommitter ${f.input.committer}\n\n${f.input.message}`);assert.equal(record.request.objectDigest,sha256(record.request.unsignedCommit));
 await assert.rejects(f.api.prepare(f.input),/reserved/);assert.deepEqual(f.counts(),{signs:1,consumes:1});
});
test('no caller payload, protected ref, malformed identity, hidden field, or unbound producer reaches signing',async()=>{
 for(const mode of ['bytes','main','tag','identity','message','unicode','hidden','producer','policy','expiry']){const f=fixture(),input={...f.input};if(mode==='bytes')input.payload='untrusted bytes';if(mode==='main')input.featureRef='refs/heads/main';if(mode==='tag')input.featureRef='refs/tags/v1';if(mode==='identity')input.author+='\nparent '+'f'.repeat(40);if(mode==='message')input.message='a\rb\n';if(mode==='unicode')input.message='bad\ud800\n';if(mode==='hidden')input.complete=true;if(mode==='producer')f.policy.authorizeFeatureCommit=async req=>({...f.grant(req),producerID:''});if(mode==='policy')f.policy.authorizeFeatureCommit=async()=>({authorized:true});if(mode==='expiry')f.advance(1200);await assert.rejects(f.api.prepare(input));assert.deepEqual(f.counts(),{signs:0,consumes:0},mode);}
});
test('expiration during durable reservation and changed policy deny before grant consumption',async()=>{
 const f=fixture(),tx=f.storage.transaction;f.storage.transaction=async fn=>{const result=await tx(fn);f.advance(1200);return result;};await assert.rejects(f.api.prepare(f.input));assert.deepEqual(f.counts(),{signs:0,consumes:0});
 const g=fixture();let calls=0;g.policy.authorizeFeatureCommit=async req=>({...g.grant(req),policyDigest:++calls===1?'e'.repeat(64):'f'.repeat(64)});await assert.rejects(g.api.prepare(g.input));assert.deepEqual(g.counts(),{signs:0,consumes:0});
});
test('revoked, changed or expired consume result cannot reach key use and reservation stays consumed',async()=>{
 for(const mode of ['revoked','changed','expired']){const f=fixture();f.policy.consumeFeatureCommit=async({request})=>{if(mode==='revoked')throw Error('revoked');if(mode==='expired')f.advance(1100);return {...f.grant(request),...(mode==='changed'?{producerID:'other'}:{})};};await assert.rejects(f.api.prepare(f.input));assert.equal(f.counts().signs,0);assert.equal([...f.rows.values()][0].signingConsumed,true);assert.equal([...f.rows.values()][0].state,'uncertain');await assert.rejects(f.api.prepare(f.input),/reserved/);}
});
test('signing ambiguity retains reservation and never automatically retries',async()=>{
 const f=fixture();f.signer.signGit=async req=>{await f.api.authorize(req);throw Error('lost reply');};await assert.rejects(f.api.prepare(f.input));assert.equal([...f.rows.values()][0].state,'uncertain');await assert.rejects(f.api.prepare(f.input),/reserved/);assert.equal(f.counts().consumes,1);
});
test('feat and fix lookup exports only exact completed signed metadata for independent local assembly verification',async()=>{
 for(const prefix of ['feat','fix','feature']){const f=fixture();f.input.featureRef=`refs/heads/${prefix}/reviewed`;const {receipt}=await f.api.prepare(f.input),exported=await f.api.lookup({repositoryID:7,nonce:f.input.nonce});assert.deepEqual(exported.receipt,receipt);assert.equal(gitObjectID('commit',exported.signedCommit),receipt.commitSHA);assert.deepEqual(Object.keys(exported).sort(),['receipt','signedCommit']);await assert.rejects(f.api.lookup({repositoryID:8,nonce:f.input.nonce}));}
});
test('late signature verification cannot report success after consumed grant expiry',async()=>{const f=fixture();f.signer.verifyGit=async()=>{f.advance(1100);return true;};await assert.rejects(f.api.prepare(f.input));assert.equal([...f.rows.values()][0].state,'uncertain');});
test('runtime authorize hook binds exact canonical bytes once and consumes before key use',async()=>{
 const f=fixture();let signedInput,granted;f.signer.signGit=async input=>{signedInput=structuredClone(input);await assert.rejects(f.api.authorize({...input,payload:input.payload+'changed'}));await assert.rejects(f.api.authorize({...input,authorization:{...input.authorization,nonce:'f'.repeat(64)}}));granted=await f.api.authorize(input);assert.equal(granted.authorized,true);await assert.rejects(f.api.authorize(input));return 'SYNTHETIC SIGNATURE\n';};
 await f.api.prepare(f.input);assert.equal(granted.objectDigest,sha256(signedInput.payload));await assert.rejects(f.api.authorize(signedInput));
});
test('fresh policy responses cannot extend the original reserved lifetime',async()=>{
 const f=fixture();let requests=0;f.policy.authorizeFeatureCommit=async input=>({...f.grant(input),expiresAt:++requests===1?1100:1200});f.signer.signGit=async input=>{f.advance(1101);await f.api.authorize(input);throw Error('must not reach key use');};await assert.rejects(f.api.prepare(f.input));assert.notEqual([...f.rows.values()][0].signingConsumed,true);
});
test('caller mutation during asynchronous admission cannot change canonical intent',async()=>{
 const f=fixture(),original=f.policy.authorizeFeatureCommit;f.policy.authorizeFeatureCommit=async request=>{f.input.treeSHA='f'.repeat(40);f.input.message='Changed later\n';return original(request);};const {receipt}=await f.api.prepare(f.input);assert.equal(receipt.treeSHA,'b'.repeat(40));assert.equal([...f.rows.values()][0].request.message,'Producer change\n');
});

test('post-signature revoked producer or altered consumed grant cannot report success',async()=>{for(const mode of ['revoked','changed']){const f=fixture();f.policy.checkFeatureCommit=async({request})=>{if(mode==='revoked')throw Error('revoked');return {...f.grant(request),producerEvidenceDigest:'a'.repeat(64)};};await assert.rejects(f.api.prepare(f.input));assert.equal([...f.rows.values()][0].state,'uncertain');}});
