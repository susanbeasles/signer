import test from 'node:test';
import assert from 'node:assert/strict';
import {createSigningAuthorization,candidateRequest} from '../src/service/authorization.mjs';
import {canonical} from '../src/vendor/repoctl/ledger.mjs';
import {sha256} from '../src/vendor/repoctl/source-signing/core.mjs';
function fixture(){let now=1000;const rows=new Map(),storage={get:async k=>structuredClone(rows.get(k)),put:async(k,v)=>rows.set(k,structuredClone(v)),transaction:async fn=>fn(storage)};
 const record={repositoryID:7,sequence:1,state:'signing',expiresAt:1200,config:{authority:'workflow_depot',repositoryID:7,repository:'fixture/source',sourceRef:'refs/heads/feature/source',targetRef:'refs/heads/main',signerKeyID:'SHA256:'+'A'.repeat(43),policyDigest:'a'.repeat(64)},snapshot:{sourceSHA:'b'.repeat(40),sourceBaseSHA:'c'.repeat(40),mainSHA:'d'.repeat(40),treeSHA:'e'.repeat(40),historyDigest:'f'.repeat(64)},sourcePR:{number:1,repositoryID:7,headSHA:'b'.repeat(40)},unsignedCommit:'tree '+'e'.repeat(40)+'\nparent '+'d'.repeat(40)+'\nauthor A <a@example.test> 1000 +0000\ncommitter A <a@example.test> 1000 +0000\n\nFixture\n',artifactIntentDigest:'b'.repeat(64),shadowRef:'refs/heads/promotion/1/shadow'};
 record.unsignedCommitDigest=sha256(record.unsignedCommit);record.candidateAuthorization={eligible:true,requestDigest:sha256(canonical(candidateRequest(record))),policyDigest:record.config.policyDigest,signerKeyID:record.config.signerKeyID,expiresAt:1100};rows.set('source-signing:7:1',record);
 const policy={current:async()=>record.config,authorizeCandidate:async()=>record.candidateAuthorization},git={main:async()=>record.snapshot.mainSHA,source:async()=>record.snapshot.sourceSHA};
 const authorize=createSigningAuthorization({storage,policy,git,signerKeyID:record.config.signerKeyID,approvalVerifier:{},ci:{},scans:{},review:{},clock:()=>now});
 const input={type:'commit',payload:record.unsignedCommit,authorization:{kind:'candidate-policy',...record.candidateAuthorization,repositoryID:7,sequence:1}};return {authorize,input,record,storage,policy,git,rows,advance:n=>now=n};
}
test('installed signer authorization consumes one exact retained candidate effect',async()=>{const f=fixture(),proof=await f.authorize(f.input);assert.equal(proof.objectDigest,sha256(f.input.payload));assert.equal(proof.authorized,true);assert.equal(f.rows.has('source-signing-effect:7:1:commit'),true);await assert.rejects(f.authorize(f.input),/consumed/);});
test('tampered payload, policy drift, source drift and expiry cannot grant a signing effect',async()=>{
 for(const mode of ['payload','policy','source','expiry']){const f=fixture(),input=structuredClone(f.input);if(mode==='payload')input.payload+='attacker';if(mode==='policy')f.policy.current=async()=>({...f.record.config,policyDigest:'e'.repeat(64)});if(mode==='source')f.git.source=async()=> 'e'.repeat(40);if(mode==='expiry')f.advance(1200);await assert.rejects(f.authorize(input));assert.equal(f.rows.has('source-signing-effect:7:1:commit'),false);}
});
test('expiration after durable authorization consumes reservation but never returns signing permission',async()=>{const f=fixture(),transaction=f.storage.transaction;f.storage.transaction=async fn=>{const result=await transaction(fn);f.advance(1200);return result;};await assert.rejects(f.authorize(f.input));assert.equal(f.rows.has('source-signing-effect:7:1:commit'),true);});
