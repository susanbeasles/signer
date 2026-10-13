import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {sha256} from '../src/vendor/repoctl/source-signing/core.mjs';
import {createLocalTreeProof,createDurableArchive,validateGitConfig} from '../src/service/source.mjs';

test('fixed Git configuration forbids arbitrary program, path, remote and oversized closures',()=>{
 const config={program:'/usr/bin/git',sha256:'a'.repeat(64),directory:'/run/signing-control/git',maxObjects:100,maxBytes:8388608,authenticated:false};assert.deepEqual(validateGitConfig(config),config);
 for(const patch of [{program:'/tmp/git'},{directory:'/workspace/app'},{maxBytes:8388609},{remote:'https://evil.test'}])assert.throws(()=>validateGitConfig({...config,...patch}));
});
test('actual local Git tree proof verifies full normal object closure and denies missing objects',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'signing-tree-fixture-'));
 const git=(args,input)=>execFileSync('/usr/bin/git',['-c','core.hooksPath=/dev/null',...args],{cwd:directory,input,env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_AUTHOR_NAME:'Fixture',GIT_AUTHOR_EMAIL:'fixture@example.test',GIT_COMMITTER_NAME:'Fixture',GIT_COMMITTER_EMAIL:'fixture@example.test'},encoding:'utf8'}).trim();
 try{git(['init','--bare','--quiet']);const blob=git(['hash-object','-w','--stdin'],'ordinary fixture source\n'),treeSHA=git(['mktree'],`100644 blob ${blob}\tindex.js\n`),baseSHA=git(['commit-tree',treeSHA], 'Fixture base\n');
  const tree=createLocalTreeProof({directory,program:'/usr/bin/git',programSHA256:sha256(await readFile('/usr/bin/git')),maxBytes:100000,maxObjects:100,requireCustody:false});
  const proof=await tree.verify({repositoryID:7,repository:'fixture/source',baseSHA,treeSHA});assert.equal(proof.complete,true);assert.match(proof.closureDigest,/^[a-f0-9]{64}$/);
  await assert.rejects(tree.verify({repositoryID:7,repository:'fixture/source',baseSHA,treeSHA:'a'.repeat(40)}));
  const child=git(['commit-tree',treeSHA,'-p',baseSHA],'Fixture child\n');await writeFile(join(directory,'info/grafts'),child+'\n');await rm(join(directory,'objects',baseSHA.slice(0,2),baseSHA.slice(2)));
  await assert.rejects(tree.verify({repositoryID:7,repository:'fixture/source',baseSHA:child,treeSHA}),/graft|alternate/i);
 }finally{await rm(directory,{recursive:true,force:true});}
});
test('missing durable history custody fails closed; tmpfs cannot be labeled retained history',async()=>{
 await assert.rejects(createDurableArchive({directory:'/var/lib/signing-control/nonexistent-fixture'}));
 const directory=await mkdtemp('/dev/shm/signing-history-test-');try{await assert.rejects(createDurableArchive({directory}),/durable/);}finally{await rm(directory,{recursive:true,force:true});}
});
