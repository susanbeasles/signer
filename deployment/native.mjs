import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {bounded} from '../native/protocol.mjs';
const ACCOUNT='1a799c6e699d2ef7e87398692ce3ad7b',REPOSITORY='susanbeasles/signer';
const need=(ok,message)=>{if(!ok)throw Error(message);};
export async function deployNative({env=process.env,fetcher=fetch,bundle}={}){
  const sha=env.WORKERS_CI_COMMIT_SHA;
  need(env.WORKERS_CI==='1'&&env.CI==='true'&&env.WORKERS_CI_BRANCH==='main'&&/^[a-f0-9]{40}$/.test(sha||''),'Production Cloudflare Builds main commit required');
  need(env.CLOUDFLARE_API_TOKEN,'Cloudflare deployment credential unavailable');
  need(!env.SIGNER_SESSION&&!env.SIGNER_WORKLOAD_TOKEN&&!env.CREDENTIAL_WRAPPING_KEY,'Runtime secrets cannot enter builds');
  const read=async(url,options={})=>{
    const response=await fetcher(url,{...options,redirect:'error',signal:AbortSignal.timeout(30000)});
    const value=JSON.parse(new TextDecoder().decode(await bounded(response.body,1048576)));
    need(response.ok&&value.success!==false,'Provider operation failed ('+response.status+'); inspect state before retrying');return value;
  };
  const github=path=>read('https://api.github.com/repos/'+REPOSITORY+path,{headers:{accept:'application/vnd.github+json','user-agent':'signer','x-github-api-version':'2026-03-10'}});
  const assertSource=async()=>{
    const head=await github('/git/ref/heads/main'),commit=await github('/commits/'+sha);
    need(head.object?.sha===sha&&commit.sha===sha&&commit.commit?.verification?.verified===true,'Current main must match the verified signed source');
  };
  await assertSource();
  const root=`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/signer`,headers={authorization:'Bearer '+env.CLOUDFLARE_API_TOKEN};
  const current=await read(root+'/settings',{headers});
  const key=current.result?.bindings?.find(b=>b.name==='CREDENTIAL_WRAPPING_KEY');
  need(key?.type==='secret_key','Native wrapping-key binding must be commissioned before deployment');
  const access=current.result.bindings.find(b=>b.name==='ACCESS_AUD'&&b.type==='plain_text');
  need(/^[a-f0-9]{64}$/.test(access?.text||''),'Signer owner Access audience must be commissioned');
  const policy=current.result.bindings.find(b=>b.name==='WORKLOAD_POLICY'&&b.type==='plain_text');
  const code=await (bundle?bundle():(async()=>{const {build}=await import('esbuild');const result=await build({entryPoints:[new URL('../native/worker.mjs',import.meta.url).pathname],bundle:true,write:false,format:'esm',platform:'neutral',target:'es2022',external:['cloudflare:workers'],legalComments:'none'});return result.outputFiles[0].text;})());
  const artifact=createHash('sha256').update(code).digest('hex');
  const bindings=[{name:'SIGNER',type:'durable_object_namespace',class_name:'Signer'},{name:'ACCESS_AUD',type:'plain_text',text:access.text},{name:'SOURCE_SHA',type:'plain_text',text:sha},{name:'ARTIFACT_SHA256',type:'plain_text',text:artifact},...(policy?[policy]:[])];
  const metadata={main_module:'worker.mjs',compatibility_date:'2026-10-13',bindings,keep_bindings:['secret_key'],observability:{enabled:true,logs:{enabled:true,invocation_logs:false},redact_query_string:true},annotations:{'workers/message':'signer '+sha}};
  if(!current.result.bindings.some(b=>b.name==='SIGNER'&&b.type==='durable_object_namespace'))metadata.migrations={new_tag:'signer-v1',steps:[{new_sqlite_classes:['Signer']}]};
  const body=new FormData();body.set('metadata',new Blob([JSON.stringify(metadata)],{type:'application/json'}));body.set('worker.mjs',new Blob([code],{type:'application/javascript+module'}),'worker.mjs');
  // Recheck after bundling; a superseded build cannot publish old main.
  await assertSource();
  const uploaded=await read(root,{method:'PUT',headers,body});
  const installed=await read(root+'/settings',{headers}),actual=installed.result?.bindings||[];
  need(actual.some(b=>b.name==='CREDENTIAL_WRAPPING_KEY'&&b.type==='secret_key')&&actual.some(b=>b.name==='SOURCE_SHA'&&b.text===sha)&&actual.some(b=>b.name==='ARTIFACT_SHA256'&&b.text===artifact)&&actual.some(b=>b.name==='SIGNER'&&b.class_name==='Signer'),'Deployment readback mismatch; inspect provider before retrying');
  const deployments=await read(root+'/deployments',{headers});
  return {worker:'signer',sourceSHA:sha,artifactSHA256:artifact,uploadID:uploaded.result?.deployment_id??null,deployment:deployments.result?.deployments?.[0]??null};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)deployNative().then(value=>console.log(JSON.stringify(value))).catch(error=>{console.error(error.message);process.exitCode=1;});
