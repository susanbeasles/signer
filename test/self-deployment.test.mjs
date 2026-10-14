import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const api=await import('../deployment/deploy.mjs').catch(()=>({}));
test('main source requests the pinned central deployment receiver without provider/signing secrets',async()=>{
 const workflow=await readFile(new URL('../.github/workflows/deploy.yml',import.meta.url),'utf8');
 assert.match(workflow,/branches: \[main\]/);assert.match(workflow,/workflow_depot\/\.github\/workflows\/request-deployment\.yml@[a-f0-9]{40}/);assert.match(workflow,/RELEASE_DISPATCH_TOKEN/);assert.doesNotMatch(workflow,/CLOUDFLARE_API_TOKEN|OP_SERVICE_ACCOUNT_TOKEN|npm run deploy/);
});
test('self deployment validates public runtime before any provider writes',()=>{
 assert.equal(typeof api.validateDeployment,'function');assert.throws(()=>api.validateDeployment({}),/configuration/);
});
import {mkdtemp,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {completePublicFixture} from '../bootstrap/test/public-fixture.mjs';
async function fixture(){
 const publicInput=await completePublicFixture();const input={schema:'signing-control-deployment/v1',accountID:publicInput.accountID,baseImage:'registry.example/base@sha256:'+'a'.repeat(64),nodeSHA256:'b'.repeat(64),setprivSHA256:'c'.repeat(64),imageConfig:{services:publicInput.runtime.services,runtime:publicInput.runtime.runtime},bindings:[{binding:'SOURCE_POLICY',service:'fixture-policy',entrypoint:'SourceFeaturePolicy'}]};
 const root=await mkdtemp(join(tmpdir(),'signer-deploy-test-'));const env={PATH:process.env.PATH,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',GITHUB_REPOSITORY:'susanbeasles/delivery_control',SOURCE_REPOSITORY:'susanbeasles/signing_control',SOURCE_REPOSITORY_ID:'1416201242',SOURCE_SHA:'d'.repeat(40),GITHUB_TOKEN:'synthetic-github',CLOUDFLARE_API_TOKEN:'synthetic-cloudflare',SIGNING_DEPLOYMENT_JSON:JSON.stringify(input)};
 const image='registry.cloudflare.com/'+input.accountID+'/signing-control@sha256:'+'e'.repeat(64);const calls=[];let deployed,existing=true,mainReads=0,stale=false;
 const readJSON=async url=>{
  if(url.startsWith('https://api.github.com/')){mainReads++;return {object:{sha:stale&&mainReads>1?'f'.repeat(40):env.SOURCE_SHA}};}
  if(url.includes('/fixture-policy/'))return {success:true,result:{bindings:[]}};
  if(deployed)return {success:true,result:{bindings:[{name:'OP_SERVICE_ACCOUNT_TOKEN',type:'secret_text'},...Object.entries(deployed.vars).map(([name,text])=>({name,type:'plain_text',text})),...deployed.services.map(b=>({name:b.binding,type:'service',service:b.service,entrypoint:b.entrypoint}))]}};
  return existing?{success:true,result:{bindings:[{name:'OP_SERVICE_ACCOUNT_TOKEN',type:'secret_text'}]}}:null;
 };
 const run=async(program,args,options)=>{
  calls.push({program,args,env:options.env});assert(!Object.hasOwn(options.env,'OP_SERVICE_ACCOUNT_TOKEN'));assert(!args.some(v=>v.includes('synthetic-')));
  if(program==='docker'){assert(!options.env.CLOUDFLARE_API_TOKEN);if(args[0]==='image')return JSON.stringify([image]);}
  if(args[1]==='deploy'){
   deployed=JSON.parse(await readFile(args[args.indexOf('--config')+1],'utf8'));
   if(env.OP_SERVICE_ACCOUNT_TOKEN)assert.deepEqual(JSON.parse(await readFile(args[args.indexOf('--secrets-file')+1],'utf8')),{OP_SERVICE_ACCOUNT_TOKEN:env.OP_SERVICE_ACCOUNT_TOKEN});
  }
  return '';
 };
 return {input,env,root,image,calls,readJSON,run,setExisting(){existing=true;},setMissing(){existing=false;},setStale(){stale=true;},cleanup:()=>rm(root,{recursive:true,force:true})};
}
test('central executor uses the exact signer source and immutable image',async()=>{
 const f=await fixture();try{const result=await api.deploy(f);assert.equal(result.image,f.image);assert.equal(f.calls.length,4);assert(f.calls[0].args.includes('SIGNING_BASE_IMAGE='+f.input.baseImage));assert.equal(f.calls[1].args[1],'containers');assert.equal(f.calls[3].args[1],'deploy');assert.deepEqual(await readdir(f.root),[]);}finally{await f.cleanup();}
});
test('existing Cloudflare signing secret is retained without copying it into the runner',async()=>{
 const f=await fixture();delete f.env.OP_SERVICE_ACCOUNT_TOKEN;f.setExisting();try{await api.deploy(f);assert(!f.calls.at(-1).args.includes('--secrets-file'));}finally{await f.cleanup();}
});
test('missing runtime secret and wrong source branch fail before any build or provider mutation',async()=>{
 const f=await fixture();f.setMissing();try{await assert.rejects(api.deploy(f),/Missing retained Worker OP_SERVICE_ACCOUNT_TOKEN/);assert.equal(f.calls.length,0);f.env.GITHUB_REF='refs/heads/feature/no';await assert.rejects(api.deploy(f),/central delivery_control/);assert.equal(f.calls.length,0);}finally{await f.cleanup();}
});
test('main advancing during image publication prevents Worker deployment and cleans generated files',async()=>{
 const f=await fixture();f.setStale();try{await assert.rejects(api.deploy(f),/superseded deployment/);assert(!f.calls.some(c=>c.args[1]==='deploy'));assert.deepEqual(await readdir(f.root),[]);}finally{await f.cleanup();}
});
test('ambiguous deployment failure is not retried and generated configuration is removed',async()=>{
 const f=await fixture();const run=f.run;f.run=async(...args)=>{await run(...args);if(args[1][1]==='deploy')throw Error('uncertain upload');return args[1][0]==='image'?JSON.stringify([f.image]):'';};try{await assert.rejects(api.deploy(f),/uncertain upload/);assert.equal(f.calls.filter(c=>c.args[1]==='deploy').length,1);assert.deepEqual(await readdir(f.root),[]);}finally{await f.cleanup();}
});
test('configuration cannot enable public routes, redirect private bindings, or accept mutable images',async()=>{
 const f=await fixture();try{const config=api.deploymentConfig(f.input,f.image);assert.equal(config.vars.ENABLED,'true');assert.equal(config.workers_dev,false);assert.deepEqual(config.routes,[]);assert.equal(config.containers[0].image,f.image);assert.equal(JSON.parse(config.vars.SIGNING_CONTROL_CONFIG_JSON).platform.imageDigest,f.image.split('@')[1]);assert.throws(()=>api.deploymentConfig(f.input,f.image.split('@')[0]+':latest'));assert.throws(()=>api.validateDeployment({...f.input,bindings:[]}));assert.throws(()=>api.validateDeployment({...f.input,baseImage:'registry.example/base:latest'}));assert.throws(()=>api.publishedImage([f.image,f.image]));}finally{await f.cleanup();}
});

test('standalone main and runner-provided signing token cannot bypass central custody',async()=>{const f=await fixture();try{f.env.OP_SERVICE_ACCOUNT_TOKEN='synthetic-op';await assert.rejects(api.deploy(f),/runner uploads are forbidden/);assert.equal(f.calls.length,0);delete f.env.OP_SERVICE_ACCOUNT_TOKEN;f.env.GITHUB_REPOSITORY='susanbeasles/signing_control';f.env.GITHUB_EVENT_NAME='push';await assert.rejects(api.deploy(f),/central delivery_control/);assert.equal(f.calls.length,0);}finally{await f.cleanup();}});
