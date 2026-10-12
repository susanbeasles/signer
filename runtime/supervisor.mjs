import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {canonical} from '../src/vendor/repoctl/ledger.mjs';
import {createPrivateTransport} from '../src/service/adapters.mjs';
import {IMAGE_CONFIG,validateHandoff} from './handoff.mjs';
import {readPrivateFD,readJSONFD} from './private-fd.mjs';
import {assertPrivateMemory} from './op-git-signer.mjs';

function publicResult(result,secrets){
 const serialized=canonical(result);if(Buffer.byteLength(serialized)>524288||secrets.some(value=>value&&serialized.includes(value)))throw Error('Unsafe result');
 const inspect=value=>{if(typeof value==='string'){if(/-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/.test(value))throw Error('Unsafe result');}else if(Array.isArray(value))value.forEach(inspect);else if(value&&typeof value==='object')for(const [key,item]of Object.entries(value)){if(/^(privateKey|privateKeyPKCS8|serviceAccountToken|opServiceAccountToken|OP_SERVICE_ACCOUNT_TOKEN|callbackToken)$/i.test(key))throw Error('Unsafe result');inspect(item);}};
 inspect(result);return structuredClone(result);
}
export async function runSupervisor({body,immutableConfig,execute,transportFactory=createPrivateTransport,clock=()=>Math.floor(Date.now()/1000)}){
 body=validateHandoff(body,immutableConfig,clock());const {job,config}=body;
 const transport=transportFactory({callbackToken:body.callbackToken,jobID:job.id,deadline:job.deadline,clock});let completion;
 try{
  if(job.deadline<=clock())throw Error();
  const result=await execute({job,config,serviceAccountToken:body.serviceAccountToken,transport});
  if(job.deadline<=clock())throw Error();completion={state:'completed',result:publicResult(result,[body.serviceAccountToken,body.callbackToken])};
 }catch{completion={state:'uncertain'};}finally{body.serviceAccountToken=null;}
 let recorded=false;
 try{if(job.deadline>clock())recorded=(await transport.call('/v1/jobs/complete',completion))?.recorded===true;}catch{}finally{body.callbackToken=null;}
 // No retry, including when a completion response is lost. The controller's
 // retained terminal state and alarm reconcile the container independently.
 return {jobId:job.id,state:recorded&&completion.state==='completed'?'completed':'uncertain'};
}
export async function main(){
 await assertPrivateMemory();
 const [message,serviceAccountToken,callbackToken,bytes]=await Promise.all([readJSONFD(0,{maxBytes:524288}),readPrivateFD(3,{maxBytes:8194}),readPrivateFD(4,{maxBytes:45}),readFile(IMAGE_CONFIG)]);
 if(!message||Object.keys(message).sort().join()!=='config,job'||bytes.length>262144)throw Error();
 const immutableConfig=JSON.parse(bytes),body={...message,serviceAccountToken,callbackToken};validateHandoff(body,immutableConfig);
 const {runTrustedJob}=await import('../src/service/run.mjs');
 const result=await runSupervisor({body,immutableConfig,execute:runTrustedJob});
 process.stdout.write(JSON.stringify(result));return result.state==='completed'?0:1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){main().then(code=>{process.exitCode=code;},()=>{process.exitCode=1;});}
