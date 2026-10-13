import test from 'node:test';
import assert from 'node:assert/strict';
import {runGitProcess} from '../src/service/git-process.mjs';
test('fixed Git process wrapper bounds output and kills its subprocess group on timeout',async()=>{
 assert.equal((await runGitProcess(process.execPath,['-e','process.stdout.write("fixture")'],{env:{PATH:'/usr/bin:/bin'},timeoutMs:1000,limit:100})).toString(),'fixture');
 await assert.rejects(runGitProcess(process.execPath,['-e','process.stdout.write("x".repeat(1000))'],{env:{PATH:'/usr/bin:/bin'},timeoutMs:1000,limit:100}));
 const start=Date.now();await assert.rejects(runGitProcess(process.execPath,['-e','require("node:child_process").spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"inherit"});setInterval(()=>{},1000)'],{env:{PATH:'/usr/bin:/bin'},timeoutMs:100,limit:100}));assert.ok(Date.now()-start<3000);
});
