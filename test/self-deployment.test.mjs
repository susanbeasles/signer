import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const api=await import('../deployment/deploy.mjs').catch(()=>({}));
test('GitHub validates PR and main commits without receiving signer or deployment credentials',async()=>{
 const workflow=await readFile(new URL('../.github/workflows/deploy.yml',import.meta.url),'utf8');
 assert.match(workflow,/pull_request:/);
 assert.match(workflow,/branches: \[main\]/);
 assert.match(workflow,/run: npm test/);
 assert.match(workflow,/github\.repository == 'susanbeasles\/signer'/);
 assert.match(workflow,/github\.repository_id == '1416201242'/);
 assert.doesNotMatch(workflow,/RELEASE_DISPATCH_TOKEN|workflow_depot\/\.github|CLOUDFLARE_API_TOKEN|SIGNER_SERVICE_ACCOUNT_TOKEN|npm run deploy/);
});
test('self deployment validates public runtime before any provider writes',()=>{
 assert.equal(typeof api.validateDeployment,'function');assert.throws(()=>api.validateDeployment({}),/configuration/);
});
import {mkdtemp,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {completePublicFixture} from '../bootstrap/test/public-fixture.mjs';
async function fixture(){
 const publicInput=await completePublicFixture();const input={schema:'signing-control-deployment/v1',accountID:publicInput.accountID,baseImage:'registry.example/base@sha256:'+'a'.repeat(64),nodeSHA256:'b'.repeat(64),setprivSHA256:'c'.repeat(64),imageConfig:{services:publicInput.runtime.services,runtime:publicInput.runtime.runtime},signerTokenSecret:{store_id:'a'.repeat(32),secret_name:'signer-op-service-account'},bindings:[{binding:'SOURCE_POLICY',service:'fixture-policy',entrypoint:'SourceFeaturePolicy'}]};
 const root=await mkdtemp(join(tmpdir(),'signer-deploy-test-'));const env={PATH:process.env.PATH,WORKERS_CI:'1',CI:'true',WORKERS_CI_BRANCH:'main',WORKERS_CI_COMMIT_SHA:'d'.repeat(40),CLOUDFLARE_API_TOKEN:'synthetic-cloudflare',SIGNING_DEPLOYMENT_JSON:JSON.stringify(input)};
 const image='registry.cloudflare.com/'+input.accountID+'/signer@sha256:'+'e'.repeat(64);const calls=[];let deployed,existing=true,activeSecret=true,secretScope='workers',incorrectBinding=false,mainReads=0,stale=false,unsigned=false;const tokenBinding={name:'SIGNER_SERVICE_ACCOUNT_TOKEN',type:'secrets_store_secret',...input.signerTokenSecret};
 const readJSON=async url=>{
  if(url.includes('/git/ref/heads/main')){mainReads++;return {object:{sha:stale&&mainReads>1?'f'.repeat(40):env.WORKERS_CI_COMMIT_SHA}};}
  if(url.startsWith('https://api.github.com/')&&url.includes('/commits/'))return {sha:env.WORKERS_CI_COMMIT_SHA,commit:{verification:{verified:!unsigned}}};
  if(url.includes('/secrets_store/stores/'))return {success:true,result:activeSecret?[{name:input.signerTokenSecret.secret_name,status:'active',scopes:[secretScope]}]:[]};
  if(url.includes('/fixture-policy/'))return {success:true,result:{bindings:[]}};
  if(deployed)return {success:true,result:{bindings:[tokenBinding,...Object.entries(deployed.vars).map(([name,text])=>({name,type:'plain_text',text})),...deployed.services.map(b=>({name:b.binding,type:'service',service:b.service,entrypoint:b.entrypoint}))]}};
  if(existing==='dormant')return {success:true,result:{bindings:[{name:'ENABLED',type:'plain_text',text:'false'},{name:'SIGNING_CONTROL_CONFIG_JSON',type:'plain_text',text:'{}'}]}};
  return existing?{success:true,result:{bindings:incorrectBinding?[{name:'OP_SERVICE_ACCOUNT_TOKEN',type:'secret_text'}]:[tokenBinding]}}:null;
 };
 const run=async(program,args,options)=>{
  calls.push({program,args,env:options.env});assert(!Object.hasOwn(options.env,'OP_SERVICE_ACCOUNT_TOKEN'));assert(!args.some(v=>v.includes('synthetic-')));
  if(program==='docker'){assert(!options.env.CLOUDFLARE_API_TOKEN);if(args[0]==='image')return JSON.stringify([image]);}
  if(args[1]==='deploy'){
   deployed=JSON.parse(await readFile(args[args.indexOf('--config')+1],'utf8'));
   assert(!args.includes('--secrets-file'));
  }
  return '';
 };
 return {input,env,root,image,calls,readJSON,run,setExisting(){existing=true;},setMissing(){existing=false;},setDormant(){existing='dormant';},setUnsigned(){unsigned=true;},setMissingSecret(){activeSecret=false;},setWrongScope(){secretScope='ai_gateway';},setWrongBinding(){incorrectBinding=true;},setStale(){stale=true;},cleanup:()=>rm(root,{recursive:true,force:true})};
}
test('Cloudflare Builds production job uses immutable image and signed main',async()=>{
 const f=await fixture();try{const result=await api.deploy(f);assert.equal(result.image,f.image);assert.equal(f.calls.length,4);assert(f.calls[0].args.includes('SIGNING_BASE_IMAGE='+f.input.baseImage));assert.equal(f.calls[1].args[1],'containers');assert.equal(f.calls[3].args[1],'deploy');assert.deepEqual(await readdir(f.root),[]);}finally{await f.cleanup();}
});
test('non-production, missing or changed Cloudflare Builds identities are denied before provider use',async()=>{
 const f=await fixture();try{
  for(const change of [{WORKERS_CI:'0'},{CI:'false'},{WORKERS_CI_BRANCH:'int/feature'},{WORKERS_CI_COMMIT_SHA:'bad'}]){
   const original=structuredClone(f.env);
   Object.assign(f.env,change);
   await assert.rejects(api.deploy(f),/production Cloudflare Builds commit/);
   Object.assign(f.env,original);
  }
  assert.equal(f.calls.length,0);
 }finally{await f.cleanup();}
});
test('unsigned main commits are denied before Cloudflare mutation',async()=>{
 const f=await fixture();f.setUnsigned();
 try{await assert.rejects(api.deploy(f),/not verified signed/);assert.equal(f.calls.length,0);}
 finally{await f.cleanup();}
});
test('native Secrets Store binding is retained without copying its value into the runner',async()=>{
 const f=await fixture();delete f.env.OP_SERVICE_ACCOUNT_TOKEN;f.setExisting();try{await api.deploy(f);assert(!f.calls.at(-1).args.includes('--secrets-file'));}finally{await f.cleanup();}
});
test('initial commissioning accepts a previously absent Worker only with an active scoped secret',async()=>{
 const f=await fixture();f.setMissing();try{
   const result=await api.deploy(f);
   assert.equal(result.worker,'signer');
   assert.equal(f.calls.filter(x=>x.args[1]==='deploy').length,1);
   assert.deepEqual(await readdir(f.root),[]);
 }finally{await f.cleanup();}
});
test('missing or wrongly scoped Secrets Store token fails before Docker or Cloudflare writes',async()=>{
 for(const mode of ['setMissingSecret','setWrongScope']){
   const f=await fixture();f.setMissing();f[mode]();
   try{await assert.rejects(api.deploy(f),/Signer Secrets Store token is missing/);assert.equal(f.calls.length,0);}
   finally{await f.cleanup();}
 }
});
test('existing Worker with different signer credential fails closed before any mutation',async()=>{
 const f=await fixture();f.setWrongBinding();
 try{await assert.rejects(api.deploy(f),/mismatched token custody/);assert.equal(f.calls.length,0);}
 finally{await f.cleanup();}
});
test('disabled bootstrap placeholder may be upgraded only with an active scoped token',async()=>{
 const f=await fixture();f.setDormant();
 try{const result=await api.deploy(f);assert.equal(result.worker,'signer');}
 finally{await f.cleanup();}
});
test('main advancing during image publication prevents Worker deployment and cleans generated files',async()=>{
 const f=await fixture();f.setStale();try{await assert.rejects(api.deploy(f),/superseded deployment/);assert(!f.calls.some(c=>c.args[1]==='deploy'));assert.deepEqual(await readdir(f.root),[]);}finally{await f.cleanup();}
});
test('ambiguous deployment failure is not retried and generated configuration is removed',async()=>{
 const f=await fixture();const run=f.run;f.run=async(...args)=>{await run(...args);if(args[1][1]==='deploy')throw Error('uncertain upload');return args[1][0]==='image'?JSON.stringify([f.image]):'';};try{await assert.rejects(api.deploy(f),/uncertain upload/);assert.equal(f.calls.filter(c=>c.args[1]==='deploy').length,1);assert.deepEqual(await readdir(f.root),[]);}finally{await f.cleanup();}
});
test('configuration cannot enable public routes, redirect private bindings, or accept mutable images',async()=>{
 const f=await fixture();try{const config=api.deploymentConfig(f.input,f.image);assert.equal(config.vars.ENABLED,'true');assert.deepEqual(config.secrets_store_secrets,[{binding:'SIGNER_SERVICE_ACCOUNT_TOKEN',...f.input.signerTokenSecret}]);assert.equal(config.workers_dev,false);assert.deepEqual(config.routes,[]);assert.equal(config.containers[0].image,f.image);assert.equal(JSON.parse(config.vars.SIGNING_CONTROL_CONFIG_JSON).platform.imageDigest,f.image.split('@')[1]);assert.throws(()=>api.deploymentConfig(f.input,f.image.split('@')[0]+':latest'));assert.throws(()=>api.validateDeployment({...f.input,bindings:[]}));assert.throws(()=>api.validateDeployment({...f.input,baseImage:'registry.example/base:latest'}));assert.throws(()=>api.publishedImage([f.image,f.image]));}finally{await f.cleanup();}
});

test('a signer runtime credential on the build runner is rejected before provider mutations',async()=>{
 const f=await fixture();
 try{f.env.OP_SERVICE_ACCOUNT_TOKEN='synthetic-op';
  await assert.rejects(api.deploy(f),/build-runtime injection is forbidden/);
  assert.equal(f.calls.length,0);
 }finally{await f.cleanup();}
});

