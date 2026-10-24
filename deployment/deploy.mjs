import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {validateImageInputs} from '../runtime/check-image.mjs';
import {validateInstallation,canonical} from '../cloudflare/controller.mjs';
const exec=promisify(execFile);
const accountID='1a799c6e699d2ef7e87398692ce3ad7b';
const repository='susanbeasles/signer';
const need=(ok,message)=>{if(!ok)throw Error(message);};
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.sort().join();
const bindingNames=['SOURCE_POLICY','OWNER_HARDWARE','SOURCE_CI','SOURCE_SCANS','SOURCE_REVIEW','SOURCE_INVENTORY','SOURCE_PUBLISHER','SOURCE_READ_CREDENTIAL'];
export function validateDeployment(input){
 need(exact(input,['schema','accountID','baseImage','nodeSHA256','setprivSHA256','imageConfig','bindings','signerTokenSecret'])&&input.schema==='signing-control-deployment/v1'&&input.accountID===accountID,'Invalid SIGNING_DEPLOYMENT_JSON configuration');
 need(JSON.stringify(input).length<=262144&&!/-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----|\b(?:ops_|opsa_|github_pat_|ghp_)/.test(JSON.stringify(input)),'Deployment configuration must contain public references only');
 try{validateImageInputs({baseImage:input.baseImage,nodeSHA256:input.nodeSHA256,setprivSHA256:input.setprivSHA256,config:input.imageConfig});}catch{throw Error('Missing or invalid approved image, tool hashes, signing public key or 1Password item reference');}
 need(Array.isArray(input.bindings)&&input.bindings.length<=bindingNames.length&&new Set(input.bindings.map(b=>b.binding)).size===input.bindings.length,'Invalid private service bindings');
 for(const b of input.bindings)need(exact(b,['binding','service','entrypoint'])&&bindingNames.includes(b.binding)&&/^[a-z0-9][a-z0-9_-]{0,62}$/.test(b.service)&&b.service!=='signer'&&/^[A-Za-z][A-Za-z0-9_]{0,99}$/.test(b.entrypoint),'Invalid private service binding');
 need(exact(input.signerTokenSecret,['store_id','secret_name'])&&/^[a-f0-9]{32}$/.test(input.signerTokenSecret.store_id)&&/^[A-Za-z0-9_-]{1,128}$/.test(input.signerTokenSecret.secret_name),'Reviewed signer Secrets Store reference required');
 need(input.bindings.some(b=>b.binding==='SOURCE_POLICY'),'Missing SOURCE_POLICY private service binding');
 return structuredClone(input);
}
export function deploymentConfig(input,image){
 const approved=validateDeployment(input);
 need(new RegExp('^registry\\.cloudflare\\.com/'+accountID+'/signer@sha256:[a-f0-9]{64}$').test(image),'Published signer image digest missing');
 const installation={...approved.imageConfig,platform:{provider:'cloudflare-containers',imageDigest:image.split('@')[1]}};validateInstallation(installation);
 return {name:'signer',account_id:accountID,main:'../cloudflare/worker.mjs',compatibility_date:'2026-10-08',compatibility_flags:['nodejs_compat'],workers_dev:false,preview_urls:false,routes:[],observability:{enabled:false},secrets_store_secrets:[{binding:'SIGNER_SERVICE_ACCOUNT_TOKEN',...approved.signerTokenSecret}],services:approved.bindings,vars:{ENABLED:'true',SIGNING_CONTROL_CONFIG_JSON:canonical(installation)},durable_objects:{bindings:[{name:'SIGNING_CONTROL_STATE',class_name:'SigningControlRepository'}]},migrations:[{tag:'signing-control-v1',new_sqlite_classes:['SigningControlRepository']}],containers:[{class_name:'SigningControlRepository',image,max_instances:1,instance_type:'standard-1',scheduling_policy:'default',observability:{enabled:false}}]};
}
export function publishedImage(values){
 need(Array.isArray(values),'Published signer image digest missing');const prefix=`registry.cloudflare.com/${accountID}/signer@sha256:`;const matches=values.filter(v=>typeof v==='string'&&v.startsWith(prefix)&&/^[a-f0-9]{64}$/.test(v.slice(prefix.length)));
 need(matches.length===1,'Published signer image digest missing or ambiguous');return matches[0];
}
async function requestJSON(url,token,fetcher=fetch){
 const response=await fetcher(url,{redirect:'error',signal:AbortSignal.timeout(20000),headers:{...(token?{Authorization:'Bearer '+token}:{}),Accept:'application/json','X-GitHub-Api-Version':'2022-11-28'}});
 if(response.status===404)return null;
 need(response.ok,`Deployment metadata read failed (HTTP ${response.status})`);
 const reader=response.body.getReader();let size=0;const chunks=[];
 try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;need(size<=1048576,'Deployment metadata response too large');chunks.push(value);}}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
 return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
const runDefault=async(program,args,options)=>{try{return (await exec(program,args,{...options,encoding:'utf8',timeout:600000,maxBuffer:4194304})).stdout;}catch(error){throw Error(`Deployment command ${program==='docker'?'docker':'wrangler'} failed (exit ${Number.isInteger(error.code)?error.code:'unavailable'}); provider output withheld to protect credentials`);}};
export async function deploy({env=process.env,root=process.cwd(),run=runDefault,readJSON=requestJSON}={}){
 need(env.WORKERS_CI==='1'&&env.CI==='true'&&env.WORKERS_CI_BRANCH==='main'&&/^[a-f0-9]{40}$/.test(env.WORKERS_CI_COMMIT_SHA??''),'Signer deployment requires a production Cloudflare Builds commit');
 const sourceSHA=env.WORKERS_CI_COMMIT_SHA;
 need(!env.OP_SERVICE_ACCOUNT_TOKEN&&!env.SIGNER_SERVICE_ACCOUNT_TOKEN,'Signing credentials must remain in Cloudflare Secrets Store; build-runtime injection is forbidden');
 need(env.CLOUDFLARE_API_TOKEN,'Missing central Cloudflare deployment credential');need(env.SIGNING_DEPLOYMENT_JSON,'Missing repository variable SIGNING_DEPLOYMENT_JSON');
 let input;try{input=JSON.parse(env.SIGNING_DEPLOYMENT_JSON);}catch{throw Error('Invalid SIGNING_DEPLOYMENT_JSON configuration');}input=validateDeployment(input);
 const assertCurrentMain=async()=>{
   const head=await readJSON(`https://api.github.com/repos/${repository}/git/ref/heads/main`,null);
   need(head?.object?.sha===sourceSHA,'Main advanced; superseded deployment refused');
   const signed=await readJSON(`https://api.github.com/repos/${repository}/commits/${sourceSHA}`,null);
   need(signed?.sha===sourceSHA&&signed?.commit?.verification?.verified===true,
     'Current main source commit is not verified signed');
 };
 await assertCurrentMain();
 const settingsURL=`https://api.cloudflare.com/client/v4/accounts/${accountID}/workers/scripts/signer/settings`;
 const previous=await readJSON(settingsURL,env.CLOUDFLARE_API_TOKEN);
 const matchesTokenBinding=b=>b.name==='SIGNER_SERVICE_ACCOUNT_TOKEN'&&b.type==='secrets_store_secret'&&b.store_id===input.signerTokenSecret.store_id&&b.secret_name===input.signerTokenSecret.secret_name;
 // An uninstalled Worker must not deadlock initial deployment. Its backing secret
 // must already exist and be active in the explicitly approved Secrets Store.
 // Never migrate an existing Worker to an unexpected signer credential implicitly.
 const existingBindings=previous?.result?.bindings;
 const installedToken=previous?.success===true&&Array.isArray(existingBindings)&&existingBindings.some(matchesTokenBinding);
 // Only an inert, zero-capability bootstrap placeholder may be upgraded when its
 // Secrets Store credential exists. No routes or private signing callbacks are enabled.
 const dormant=previous?.success===true&&Array.isArray(existingBindings)&&
   existingBindings.length===2&&
   existingBindings.some(b=>b.name==='ENABLED'&&b.type==='plain_text'&&b.text==='false')&&
   existingBindings.some(b=>b.name==='SIGNING_CONTROL_CONFIG_JSON'&&b.type==='plain_text'&&b.text==='{}');
 need(previous===null||installedToken||dormant,
   'Existing signer Worker has mismatched token custody; explicit migration required');
 const storeURL=`https://api.cloudflare.com/client/v4/accounts/${accountID}/secrets_store/stores/${input.signerTokenSecret.store_id}/secrets?search=${encodeURIComponent(input.signerTokenSecret.secret_name)}&per_page=100`;
 const store=await readJSON(storeURL,env.CLOUDFLARE_API_TOKEN);
 need(store?.success===true&&Array.isArray(store.result)&&store.result.filter(secret=>
   secret?.name===input.signerTokenSecret.secret_name&&secret.status==='active'&&
   Array.isArray(secret.scopes)&&secret.scopes.includes('workers')).length===1,
   'Signer Secrets Store token is missing, inactive, or not scoped to Workers');
 for(const binding of input.bindings){const metadata=await readJSON(`https://api.cloudflare.com/client/v4/accounts/${accountID}/workers/scripts/${binding.service}/settings`,env.CLOUDFLARE_API_TOKEN);need(metadata?.success===true,`Missing private service for ${binding.binding}`);}
 const directory=await mkdtemp(join(root,'.signing-deploy-'));const publicImageFile=join(root,'image-runtime-config.json');let wroteImage=false;
 const wrangler=resolve(root,'node_modules/wrangler/bin/wrangler.js');const tag='signer:'+sourceSHA;
 const common={PATH:env.PATH,LANG:'C',CI:'true',WRANGLER_SEND_METRICS:'false',CLOUDFLARE_ACCOUNT_ID:accountID,XDG_CONFIG_HOME:join(directory,'config'),DOCKER_CONFIG:join(directory,'docker')};
 // Only Wrangler receives the deploy credential. No signing token is in any child environment.
 const providerEnv={...common,CLOUDFLARE_API_TOKEN:env.CLOUDFLARE_API_TOKEN};
 const invoke=(program,args,provider=false)=>run(program,args,{cwd:root,env:provider?providerEnv:common});
 try{
  await writeFile(publicImageFile,JSON.stringify(input.imageConfig),{flag:'wx',mode:0o600});wroteImage=true;
  await invoke('docker',['build','--platform','linux/amd64','--file','runtime/Dockerfile','--tag',tag,'--build-arg','SIGNING_BASE_IMAGE='+input.baseImage,'--build-arg','SIGNING_NODE_SHA256='+input.nodeSHA256,'--build-arg','SIGNING_SETPRIV_SHA256='+input.setprivSHA256,'.']);
  await invoke(process.execPath,[wrangler,'containers','push',tag],true);
  const image=publishedImage(JSON.parse(await invoke('docker',['image','inspect',`registry.cloudflare.com/${accountID}/${tag}`,'--format','{{json .RepoDigests}}'])));
  const config=deploymentConfig(input,image);const configPath=join(directory,'wrangler.json');await writeFile(configPath,JSON.stringify(config),{mode:0o600});
  const args=[wrangler,'deploy','--config',configPath,'--message','signer '+sourceSHA];
  await assertCurrentMain();await invoke(process.execPath,args,true);
  const installed=await readJSON(settingsURL,env.CLOUDFLARE_API_TOKEN);const bindings=installed?.result?.bindings??[];
  need(installed?.success===true&&bindings.some(matchesTokenBinding)&&bindings.some(b=>b.name==='ENABLED'&&b.text==='true')&&bindings.some(b=>b.name==='SIGNING_CONTROL_CONFIG_JSON'&&b.text===config.vars.SIGNING_CONTROL_CONFIG_JSON)&&input.bindings.every(expected=>bindings.some(b=>b.type==='service'&&b.name===expected.binding&&b.service===expected.service&&b.entrypoint===expected.entrypoint)),'Deployment readback differs; inspect provider deployment before retrying');
  return {worker:'signer',commit:sourceSHA,image};
 }finally{if(wroteImage)await rm(publicImageFile,{force:true});await rm(directory,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){deploy().then(result=>console.log(JSON.stringify(result))).catch(error=>{console.error(error.message);process.exitCode=1;});}

