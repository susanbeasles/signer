import {isIntegrationRef} from '../src/vendor/repoctl/source-signing/integration-ref.mjs';
import {featureRequest,validateFeatureAuthorization} from '../src/service/feature-contract.mjs';
import {validateStateWrite,validateCapability,generationFor,publicationEffect} from './confinement.mjs';
import {createHash,timingSafeEqual} from 'node:crypto';
export const INTERNAL_ORIGIN='https://signing-control.internal';
export const MUTATIONS=['prepareFeature','prepare','retireShadow','publishShadow','approvalIntent','approve','publish'];
export const READS=['lookupFeature','lookupCandidate','lookupReviewPolicy','lookupReceipt','verifyPromotion'];
export const CAPABILITIES={policy:['current','authorizeCandidate','authorizeFeatureCommit','consumeFeatureCommit','checkFeatureCommit'],hardware:['verify'],ci:['verify'],scans:['verify'],review:['verify'],inventory:['classify'],publisher:['putObject','readRef','createRef','findPullRequest','createPullRequest','deleteRef','closePullRequest'],source:['credential']};
const MAX_STATE=2*1024*1024,MAX_RESULT=512*1024,HASH=/^[a-f0-9]{64}$/,UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const check=(ok,code='signing-control-denied')=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join()===keys.slice().sort().join();
export function canonical(value){if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);if(Number.isSafeInteger(value))return String(value);if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';if(value&&Object.getPrototypeOf(value)===Object.prototype)return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';throw Error('invalid-metadata');}
const hash=value=>createHash('sha256').update(value).digest('hex');
export const configDigest=value=>hash(canonical(value));
function bounded(value,max){const body=canonical(value);check(Buffer.byteLength(body)<=max,'metadata-too-large');return structuredClone(value);}
function noSecrets(value){
 if(typeof value==='string'){check(!/-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/.test(value),'private-material-denied');return;}
 if(Array.isArray(value)){for(const item of value)noSecrets(item);return;}
 if(value&&typeof value==='object')for(const [name,item] of Object.entries(value)){check(!/^(privateKey|privateKeyPKCS8|serviceAccountToken|opServiceAccountToken|OP_SERVICE_ACCOUNT_TOKEN|callbackToken)$/i.test(name),'private-material-denied');noSecrets(item);}
}
function httpsOrigin(value){try{const url=new URL(value);return url.protocol==='https:'&&url.origin===value&&!url.username&&!url.password&&!url.port&&/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(url.hostname)&&!/^\d+\.\d+\.\d+\.\d+$/.test(url.hostname);}catch{return false;}}
export function validateConfiguration(config){
 check(exact(config,['service','runtime','platform']),'configuration-unavailable');bounded(config,262144);noSecrets(config);
 check(config.service?.schema==='signing-control-service/v1'&&Number.isSafeInteger(config.service.repositoryID)&&config.service.repositoryID>0&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(config.service.repository),'repository-unconfigured');
 check(exact(config.platform,['provider','imageDigest'])&&config.platform.provider==='cloudflare-containers'&&/^sha256:[a-f0-9]{64}$/.test(config.platform.imageDigest),'image-unconfigured');
 check(config.runtime?.schema==='signing-control-op-agent/v1'&&/^SHA256:[A-Za-z0-9+/]{43}$/.test(config.service.signer?.keyID??'')&&config.runtime.keyID===config.service.signer.keyID,'signer-unconfigured');
 check(Array.isArray(config.runtime.opOrigins)&&config.runtime.opOrigins.length>0&&config.runtime.opOrigins.length<=8&&new Set(config.runtime.opOrigins).size===config.runtime.opOrigins.length&&config.runtime.opOrigins.every(origin=>httpsOrigin(origin)&&origin!==INTERNAL_ORIGIN&&origin!=='https://github.com'),'op-egress-unconfigured');
 return config;
}
export function validateInstallation(value){
 if(exact(value,['service','runtime','platform'])){validateConfiguration(value);return value;}
 check(exact(value,['services','runtime','platform'])&&Array.isArray(value.services)&&value.services.length>0&&value.services.length<=32,'installation-unconfigured');bounded(value,262144);noSecrets(value);
 check(new Set(value.services.map(service=>service.repositoryID)).size===value.services.length&&new Set(value.services.map(service=>service.repository)).size===value.services.length,'duplicate-repository');
 for(const service of value.services)validateConfiguration({service,runtime:value.runtime,platform:value.platform});return value;
}
export function installationConfigurations(value){validateInstallation(value);return (value.services??[value.service]).map(service=>({service,runtime:value.runtime,platform:value.platform}));}
export function selectConfiguration(value,repositoryID){const choices=installationConfigurations(value);if(repositoryID===undefined){check(choices.length===1,'repository-scope-required');return choices[0];}check(Number.isSafeInteger(repositoryID)&&repositoryID>0,'repository-denied');const selected=choices.find(config=>config.service.repositoryID===repositoryID);check(selected,'repository-denied');return selected;}
function stateKey(key,repositoryID,value){
 const r=String(repositoryID),plain=typeof key==='string'&&key.length<=250;
 check(plain&&(new RegExp('^source-retiring:'+r+':[1-9][0-9]*$').test(key)||(key.startsWith('source-active:'+r+':')&&isIntegrationRef(key.slice(('source-active:'+r+':').length)))||(key.startsWith('source-published:'+r+':')&&isIntegrationRef(key.slice(('source-published:'+r+':').length)))||new RegExp('^source-commit:'+r+':[a-f0-9]{40}$').test(key)||key==='source-sequence:'+r||new RegExp('^source-(?:signing|shadow|publication|effect-grant|signing-effect):'+r+':[1-9][0-9]*(?::(?:source|main|commit|ref|pr|close|delete|receipt))?$').test(key)||new RegExp('^source-feature:'+r+':[a-f0-9]{64}$').test(key)||/^source-(?:approval|receipt):[a-f0-9]{64}$/.test(key)),'state-key-denied');
 if(/^source-(?:approval|receipt):/.test(key))check(value?.repositoryID===repositoryID,'state-repository-denied');
 if(value?.repositoryID!==undefined)check(value.repositoryID===repositoryID,'state-repository-denied');
 noSecrets(value);
}
const immutableKey=key=>/^source-(?:approval|receipt|effect-grant|signing-effect|publication):/.test(key)||/^source-shadow:/.test(key);

export function createSigningController({storage,container,containerId,config,capabilities,serviceToken,interceptor,clock=()=>Math.floor(Date.now()/1000),sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),waitUntil=()=>{},fetcher=fetch}){
 const key=id=>'control:job:'+id;
 const expires=r=>Math.min(r.job.deadline,r.featureGrant?.expiresAt??r.job.deadline);
 const live=r=>check(r&&!r.terminal&&!r.cleanup&&expires(r)>clock(),'job-closed');
 const edit=(id,fn)=>storage.transaction(async tx=>{const record=await tx.get(key(id));check(record,'job-not-found');const result=await fn(record,tx);await tx.put(key(id),record);return result;});
 const get=async id=>{check(UUID.test(id??''));const r=await storage.get(key(id));check(r,'job-not-found');return r;};
 function publicStatus(r){const state=r.cleanup==='unconfirmed'?'uncertain':r.terminal==='uncertain'?'uncertain':r.terminal==='completed'?(r.cleanup==='destroyed'?'completed':'finishing'):r.phase==='running'?'running':'launching';return {jobId:r.job.id,repositoryID:config.service.repositoryID,state,...(state==='completed'?{result:structuredClone(r.result)}:{})};}
 const status=async id=>publicStatus(await get(id));
 async function currentPolicy(job){
  if(!job){const active=await storage.get('control:active');if(active)job=(await storage.get(key(active)))?.job;}
  let sourcePRNumber=job?.input?.sourcePR?.number;
  if(job&&!sourcePRNumber){const state=await storage.get('core:state')??{entries:[]};sourcePRNumber=generationFor(job,new Map(state.entries.map(e=>[e.key,e.value])))?.sourcePR?.number;}
  const p=await capabilities.policy.current({repositoryID:config.service.repositoryID,...(sourcePRNumber?{sourcePRNumber}:{})});check(p?.authority==='workflow_depot'&&p.repositoryID===config.service.repositoryID&&p.repository===config.service.repository&&p.signerKeyID===config.service.signer.keyID,'source-policy-unavailable');return p;}
 function dependencies(action){
  if(['prepareFeature','lookupFeature'].includes(action)){const methods=action==='prepareFeature'?['current','authorizeFeatureCommit','consumeFeatureCommit','checkFeatureCommit']:['current'];check(methods.every(method=>typeof capabilities?.policy?.[method]==='function'),'source-feature-policy-unavailable');return;}
  for(const [cap,methods]of Object.entries(CAPABILITIES)){if(cap==='source'&&!config.service.git?.authenticated)continue;const required=cap==='policy'?['current','authorizeCandidate']:methods;check(required.every(method=>typeof capabilities?.[cap]?.[method]==='function'),'source-capability-unavailable');}
 }
 let cleanupTail=Promise.resolve();
 function stop(id){
  const task=cleanupTail.then(async()=>{
   const needed=await storage.transaction(async tx=>{const r=await tx.get(key(id));if(!r||r.cleanup==='destroyed'||await tx.get('control:active')!==id)return false;if(!r.terminal)r.terminal='uncertain';r.cleanup='requested';await tx.put(key(id),r);return true;});
   if(!needed)return;
   try{await container.destroy();check(container.running===false&&await container.inspect()===null,'cleanup-unconfirmed');await edit(id,async(r,tx)=>{check(await tx.get('control:active')===id);r.cleanup='destroyed';await tx.deleteAlarm();if(r.terminal==='completed'||READS.includes(r.job.action))await tx.put('control:active',null);});}
   catch{await edit(id,async(r,tx)=>{r.cleanup='unconfirmed';if(await tx.get('control:active')===id)await tx.setAlarm((clock()+30)*1000);});}
  });cleanupTail=task.catch(()=>{});return task;
 }
 async function alarm(){const stopID=await storage.transaction(async tx=>{const id=await tx.get('control:active');if(!id)return null;const r=await tx.get(key(id));check(r,'job-not-found');if(r.cleanup==='destroyed')return null;if(expires(r)<=clock()||r.terminal||r.cleanup)return id;await tx.setAlarm(expires(r)*1000);return null;});if(stopID)await stop(stopID);}
 async function execute(job){
  validateConfiguration(config);job=bounded(job,131072);noSecrets(job);dependencies(job.action);
  check(exact(job,['version','id','action','input','configDigest','deadline'])&&job.version===1&&UUID.test(job.id)&&[...MUTATIONS,...READS].includes(job.action)&&HASH.test(job.configDigest)&&job.configDigest===configDigest(config)&&Number.isSafeInteger(job.deadline)&&job.deadline>clock()&&job.deadline<=clock()+300,'job-invalid');
  check(['lookupReceipt','verifyPromotion'].includes(job.action)?exact(job.input,['receiptDigest'])&&HASH.test(job.input.receiptDigest):job.input?.repositoryID===config.service.repositoryID,'repository-denied');
  const acceptedPolicy=await currentPolicy(job);check(job.deadline>clock(),'job-expired');
  let feature=null,featureGrant=null;if(job.action==='prepareFeature'){feature=featureRequest(job.input,config.service,clock());featureGrant=bounded(await capabilities.policy.authorizeFeatureCommit(structuredClone(feature)),16384);validateFeatureAuthorization(feature,featureGrant,clock());check(featureGrant.policyDigest===acceptedPolicy.policyDigest,'feature-policy-changed');check(featureGrant.expiresAt>clock()&&job.deadline>clock(),'feature-authority-expired');}
  const identity=hash(canonical({job,containerId})),token=Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');let claimed=false;
  await storage.transaction(async tx=>{claimed=false;const existing=await tx.get(key(job.id));if(existing){check(existing.identity===identity,'immutable-job-conflict');return;}check(!await tx.get('control:active'),'repository-busy-or-uncertain');check(job.deadline>clock(),'job-expired');await tx.put(key(job.id),{job:structuredClone(job),identity,containerId,tokenHash:hash(token),phase:'reserved',terminal:null,cleanup:null,...(feature?{featureRequest:feature,featureGrant}: {})});await tx.put('control:active',job.id);await tx.setAlarm(Math.min(job.deadline,featureGrant?.expiresAt??job.deadline)*1000);claimed=true;});
  if(!claimed)return status(job.id);
  try{
   check(container&&!container.running,'container-already-running');const props={jobId:job.id,repositoryID:config.service.repositoryID,containerId,identity},binding=interceptor(props);
   for(const origin of [INTERNAL_ORIGIN,'https://github.com',...config.runtime.opOrigins])await container.interceptOutboundHttps(new URL(origin).hostname,binding);
   await edit(job.id,r=>{live(r);check(r.phase==='reserved');r.phase='booting';});live(await get(job.id));
   container.start({enableInternet:false});await container.setInactivityTimeout(Math.min(60000,Math.max(1,(job.deadline-clock())*1000)));
   waitUntil(container.monitor().then(()=>stop(job.id),()=>stop(job.id)).catch(()=>{}));
   let ready=false;for(let i=0;i<40&&clock()<job.deadline;i++){try{const response=await container.getTcpPort(8080).fetch('http://container/ready',{signal:AbortSignal.timeout(2000)});await response.body?.cancel();if(response.status===204){ready=true;break;}}catch{}await sleep(250);}
   check(ready,'container-not-ready');live(await get(job.id));const image=(await container.inspect())?.image;check(image===config.platform.imageDigest||image?.endsWith('@'+config.platform.imageDigest),'image-mismatch');
   await currentPolicy();live(await get(job.id));let secret=null;
   if(['prepareFeature','prepare','approve'].includes(job.action)){secret=await serviceToken();check(typeof secret==='string'&&/^[\x21-\x7e]{1,8192}$/.test(secret),'op-token-unavailable');}
   live(await get(job.id));await edit(job.id,r=>{live(r);check(r.phase==='booting');r.phase='submitted';});live(await get(job.id));
   const body=JSON.stringify({job,config,serviceAccountToken:secret,callbackToken:token});secret=null;
   const response=await container.getTcpPort(8080).fetch('http://container/v1/execute',{method:'POST',headers:{'content-type':'application/json'},body,signal:AbortSignal.timeout(Math.min(10000,Math.max(1,(job.deadline-clock())*1000)))});await response.body?.cancel();check(response.status===202,'handoff-uncertain');
   await edit(job.id,r=>{if(!r.terminal&&!r.cleanup){live(r);check(r.phase==='submitted');r.phase='running';}});
  }catch{await edit(job.id,async(r,tx)=>{if(!r.terminal)r.terminal='uncertain';await tx.setAlarm(clock()*1000+1);});}
  return status(job.id);
 }
 async function bound(props,authorization){
  check(exact(props,['jobId','repositoryID','containerId','identity'])&&props.repositoryID===config.service.repositoryID&&props.containerId===containerId,'callback-identity-denied');
  const r=await get(props.jobId);live(r);check(r.identity===props.identity&&r.containerId===containerId&&['submitted','running'].includes(r.phase),'callback-identity-denied');
  check(typeof authorization==='string'&&/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization),'callback-auth-denied');check(timingSafeEqual(Buffer.from(hash(authorization.slice(7)),'hex'),Buffer.from(r.tokenHash,'hex')),'callback-auth-denied');
  check(await storage.get('control:active')===props.jobId,'callback-identity-denied');live(await get(props.jobId));return r;
 }
 async function callback(path,input,authorization,props){
  const r=await bound(props,authorization);bounded(input,MAX_STATE);
  if(path==='/v1/state/snapshot'){check(exact(input,[]));const state=await storage.get('core:state')??{revision:0,entries:[]};live(await get(r.job.id));return bounded(state,MAX_STATE);}
  if(path==='/v1/state/transaction'){
   check(MUTATIONS.includes(r.job.action),'read-only-action');const policy=await currentPolicy();live(await get(r.job.id));
   check(exact(input,['expectedRevision','writes'])&&Number.isSafeInteger(input.expectedRevision)&&input.expectedRevision>=0&&Array.isArray(input.writes)&&input.writes.length>0&&input.writes.length<=32,'state-write-denied');
   return storage.transaction(async tx=>{live(await tx.get(key(r.job.id)));const state=await tx.get('core:state')??{revision:0,entries:[]};check(state.revision===input.expectedRevision,'state-conflict');const entries=new Map(state.entries.map(entry=>[entry.key,entry.value])),seen=new Set();
    for(const entry of input.writes){check(exact(entry,['key','value'])&&!seen.has(entry.key));seen.add(entry.key);stateKey(entry.key,config.service.repositoryID,entry.value);validateStateWrite({entry,job:r.job,entries,policy,canonical,admission:r});const old=entries.get(entry.key);if(immutableKey(entry.key)&&old!==undefined)check(canonical(old)===canonical(entry.value),'immutable-state-conflict');if(entry.key==='source-sequence:'+config.service.repositoryID)check(Number.isSafeInteger(entry.value)&&entry.value===(old??0)+1,'sequence-conflict');entries.set(entry.key,entry.value);}
    const next={revision:state.revision+1,entries:[...entries].sort(([a],[b])=>a.localeCompare(b)).map(([key,value])=>({key,value}))};bounded(next,MAX_STATE);check(next.entries.length<=2048,'state-capacity');live(await tx.get(key(r.job.id)));await tx.put('core:state',next);return {revision:next.revision};});
  }
  if(path==='/v1/jobs/complete'){
   check(exact(input,input.state==='completed'?['state','result']:['state'])&&['completed','uncertain'].includes(input.state),'completion-denied');if(input.state==='completed'){bounded(input.result,MAX_RESULT);noSecrets(input.result);}
   return edit(r.job.id,async(record,tx)=>{live(record);if(input.state==='completed'&&['prepareFeature','lookupFeature'].includes(record.job.action)){const retained=(await tx.get('core:state'))?.entries.find(entry=>entry.key===`source-feature:${config.service.repositoryID}:${record.job.input.nonce}`)?.value;check(retained?.state==='signed'&&retained.signingConsumed===true,'feature-result-unavailable');if(record.job.action==='prepareFeature')check(record.featureEffect==='consumed'&&canonical(input.result)===canonical({receipt:retained.receipt,signature:retained.signature}),'feature-result-denied');else check(canonical(input.result)===canonical({receipt:retained.receipt,signedCommit:retained.signedCommit}),'feature-result-denied');}record.terminal=input.state;if(input.state==='completed')record.result=structuredClone(input.result);await tx.setAlarm(clock()*1000+1);return {recorded:true};});
  }
  const match=/^\/v1\/capability\/([a-z]+)\/([A-Za-z]+)$/.exec(path);
  check(match&&CAPABILITIES[match[1]]?.includes(match[2])&&exact(input,['input']),'capability-denied');const [_,name,method]=match;check(typeof capabilities?.[name]?.[method]==='function','capability-unavailable');
  const state=await storage.get('core:state')??{entries:[]};const entries=new Map(state.entries.map(e=>[e.key,e.value]));const policy=await currentPolicy();live(await get(r.job.id));validateCapability({name,method,input:input.input,job:r.job,config,entries,policy,canonical,admission:r,now:clock()});
  if(name==='policy'&&method==='consumeFeatureCommit')await edit(r.job.id,async(record,tx)=>{live(record);check(!record.featureEffect,'feature-effect-replayed');const state=await tx.get('core:state'),retained=state?.entries.find(entry=>entry.key===`source-feature:${config.service.repositoryID}:${r.job.input.nonce}`)?.value;check(retained?.state==='signing'&&retained.signingConsumed===true&&canonical(retained.request)===canonical(record.featureRequest),'feature-effect-not-reserved');record.featureEffect='reserved';});
  if(name==='policy'&&method==='checkFeatureCommit')check((await get(r.job.id)).featureEffect==='consumed','feature-effect-not-consumed');
  const result=await capabilities[name][method](structuredClone(input.input));live(await get(r.job.id));
  if(name==='policy'&&['authorizeFeatureCommit','consumeFeatureCommit','checkFeatureCommit'].includes(method)){validateFeatureAuthorization(r.featureRequest,result,clock());check(canonical(result)===canonical(r.featureGrant),'feature-grant-changed');if(method==='consumeFeatureCommit')await edit(r.job.id,record=>{live(record);check(record.featureEffect==='reserved');record.featureEffect='consumed';});}
  return bounded(result,MAX_STATE);
 }
 async function outbound(request,props){
  const url=new URL(request.url);check(url.protocol==='https:'&&!url.username&&!url.password&&!url.port&&!url.hash,'egress-denied');
  if(url.origin===INTERNAL_ORIGIN){check(request.method==='POST'&&!url.search,'callback-denied');const input=await readJSON(request,MAX_STATE);return Response.json(await callback(url.pathname,input,request.headers.get('authorization'),props),{headers:{'cache-control':'no-store'}});}
  const r=await get(props.jobId);live(r);check(props.identity===r.identity&&props.containerId===containerId&&props.repositoryID===config.service.repositoryID,'egress-identity-denied');
  check(['https://github.com',...config.runtime.opOrigins].includes(url.origin)&&['GET','HEAD','POST'].includes(request.method),'egress-denied');
  if(url.origin==='https://github.com'){const base='/'+config.service.repository+'.git';check((request.method==='GET'&&url.pathname===base+'/info/refs'&&url.search==='?service=git-upload-pack')||(request.method==='POST'&&url.pathname===base+'/git-upload-pack'&&!url.search),'git-transport-denied');}
  else check(['prepareFeature','prepare','approve'].includes(r.job.action),'op-action-denied');
  return fetcher(new Request(request,{redirect:'manual',signal:AbortSignal.timeout(Math.min(30000,Math.max(1,(r.job.deadline-clock())*1000)))}));
 }
 async function verifyPublication(input){
  bounded(input,32768);noSecrets(input);const id=await storage.get('control:active');check(id,'publication-unavailable');const active=await get(id);live(active);check(['publishShadow','retireShadow','publish'].includes(active.job.action),'publication-action-denied');
  const accepted=await currentPolicy();live(await get(id));
  return storage.transaction(async tx=>{const job=await tx.get(key(id));live(job);check(await tx.get('control:active')===id,'publication-job-changed');const state=await tx.get('core:state')??{entries:[]},entries=new Map(state.entries.map(e=>[e.key,e.value]));const r=generationFor(job.job,entries);check(r&&canonical(r.config)===canonical(accepted),'publication-policy-changed');const part=publicationEffect(input,r,canonical,entries);check((['ref','pr','close','delete'].includes(part)?['publishShadow','retireShadow'].includes(job.job.action):job.job.action==='publish'),'publication-action-denied');
   const suffix=`${r.repositoryID}:${r.sequence}:${part}`,grant=entries.get('source-effect-grant:'+suffix),reservation=entries.get((['ref','pr','close','delete'].includes(part)?'source-shadow:':'source-publication:')+suffix),requestDigest=hash(canonical(input));
   check(grant&&exact(grant,['requestDigest','expiresAt'])&&grant.requestDigest===requestDigest&&Number.isSafeInteger(grant.expiresAt)&&grant.expiresAt>clock()&&grant.expiresAt<=clock()+60,'publication-grant-denied');
   check(reservation&&(['ref','pr','close','delete'].includes(part)?reservation.commitSHA===r.finalSignedCommitSHA:reservation.objectSHA===r.tags[part].objectSHA),'publication-reservation-denied');
   const tombstone='source-effect-consumed:'+suffix;check(!await tx.get(tombstone),'publication-replayed');await tx.put(tombstone,{repositoryID:r.repositoryID,sequence:r.sequence,requestDigest,expiresAt:grant.expiresAt});return {verified:true,requestDigest,expiresAt:Math.min(grant.expiresAt,job.job.deadline)};
  });
 }
 async function resume(){const id=await storage.get('control:active');if(!id){if(container?.running)await container.destroy();return;}const r=await get(id);if(r.cleanup==='destroyed')return;if(expires(r)<=clock()||r.terminal||!container?.running){await stop(id);return;}await storage.setAlarm(expires(r)*1000);waitUntil(container.monitor().then(()=>stop(id),()=>stop(id)).catch(()=>{}));}
 return {execute,status,callback,outbound,alarm,resume,verifyPublication};
}
export async function readJSON(request,max=131072){const reader=request.body?.getReader();check(reader,'body-required');const chunks=[];let size=0;try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;check(size<=max,'body-too-large');chunks.push(value);}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));}finally{void reader.cancel().catch(()=>{});reader.releaseLock();}}
