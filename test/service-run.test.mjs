import test from 'node:test';
import assert from 'node:assert/strict';
import {runTrustedJob,validateJobConfiguration} from '../src/service/run.mjs';
import {sha256} from '../src/vendor/repoctl/source-signing/core.mjs';
import {canonical} from '../src/vendor/repoctl/ledger.mjs';
function fixture(){
 const blob=Buffer.concat([Buffer.from('0000000b7373682d6564323535313900000020','hex'),Buffer.alloc(32)]),keyID='SHA256:'+Buffer.from(sha256(blob),'hex').toString('base64').replace(/=+$/,'');
 const toolchain=Object.fromEntries(Object.entries({op:'/usr/local/bin/op',sshAgent:'/usr/bin/ssh-agent',sshAdd:'/usr/bin/ssh-add',sshKeygen:'/usr/bin/ssh-keygen'}).map(([key,path])=>[key,{path,sha256:'a'.repeat(64)}]));
 const config={service:{schema:'signing-control-service/v1',repositoryID:7,repository:'fixture/source',git:{program:'/usr/bin/git',sha256:'a'.repeat(64),directory:'/run/signing-control/git',maxObjects:100,maxBytes:100000,authenticated:false},signer:{keyID}},runtime:{schema:'signing-control-op-agent/v1',opRef:'op://'+'a'.repeat(26)+'/'+'b'.repeat(26)+'/private_key?ssh-format=openssh',publicKey:'ssh-ed25519 '+blob.toString('base64'),keyID,toolchain,opOrigins:['https://fixture.1password.com']},platform:{provider:'cloudflare-containers',imageDigest:'sha256:'+'b'.repeat(64)}};
 const job={version:1,id:crypto.randomUUID(),action:'prepare',input:{repositoryID:7,sourcePR:{number:1,repositoryID:7,headSHA:'a'.repeat(40)},author:'Fixture <fixture@example.test> 1000 +0000',committer:'Fixture <fixture@example.test> 1000 +0000',message:'Fixture\n',artifactIntentDigest:'b'.repeat(64),expiresAt:Math.floor(Date.now()/1000)+60},configDigest:sha256(canonical(config)),deadline:Math.floor(Date.now()/1000)+60};return {config,job};
}
test('production composition rejects generic signing, caller modules and config drift before private transport',async()=>{
 for(const mode of ['generic','module','config','expiry','foreign']){const {job,config}=fixture();if(mode==='generic')job.action='sign';if(mode==='module')job.input={repositoryID:7,module:'/tmp/fake.mjs'};if(mode==='config')config.service.repository='other/source';if(mode==='expiry')job.deadline=1;if(mode==='foreign')job.input.repositoryID=8;let calls=0;
  await assert.rejects(runTrustedJob({job,config,serviceAccountToken:null,transport:{call:async()=>{calls++;}}}));assert.equal(calls,0);
 }
});
test('configured booleans cannot replace installed independent source policy',async()=>{const {job,config}=fixture();let calls=0;await assert.rejects(runTrustedJob({job,config,serviceAccountToken:null,transport:{call:async()=>{calls++;return {eligible:true,hardwareVerified:true};}}}));assert.equal(calls,1);});
test('Cloudflare feature composition reaches depot admission without fetching source or accessing a local tree',async()=>{
 const {job,config}=fixture(),now=Math.floor(Date.now()/1000);job.action='prepareFeature';job.input={repositoryID:7,baseSHA:'a'.repeat(40),treeSHA:'b'.repeat(40),featureRef:'refs/heads/feature/fixture',message:'Fixture\n',author:'Fixture <fixture@example.test> 1000 +0000',committer:'Fixture <fixture@example.test> 1000 +0000',nonce:'c'.repeat(64),expiresAt:now+60};
 const calls=[];await assert.rejects(runTrustedJob({job,config,serviceAccountToken:null,transport:{call:async(path,input)=>{calls.push({path,input});if(path==='/v1/state/snapshot')return {revision:0,entries:[]};throw Error('Synthetic depot denies unadmitted producer');}}}),/Synthetic depot denies/);
 assert.deepEqual(calls.map(x=>x.path),['/v1/state/snapshot','/v1/capability/policy/authorizeFeatureCommit']);assert.equal(calls[1].input.input.closureDigest,undefined);assert.equal(calls[1].input.input.treeSHA,job.input.treeSHA);assert.equal(calls[1].input.input.objectDigest,sha256(calls[1].input.input.unsignedCommit));
});
test('feature canonical field validation denies before any private callback',async()=>{
 const {job,config}=fixture();job.action='prepareFeature';job.input={repositoryID:7,baseSHA:'a'.repeat(40),treeSHA:'b'.repeat(40),featureRef:'refs/heads/main',message:'Fixture\n',author:'Fixture <fixture@example.test> 1000 +0000',committer:'Fixture <fixture@example.test> 1000 +0000',nonce:'c'.repeat(64),expiresAt:Math.floor(Date.now()/1000)+60};let calls=0;await assert.rejects(runTrustedJob({job,config,serviceAccountToken:null,transport:{call:async()=>{calls++;return {revision:0,entries:[]};}}}));assert.equal(calls,0);
});
