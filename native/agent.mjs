#!/usr/bin/env node
import {spawn} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {ORIGIN, bounded} from './protocol.mjs';
import {request} from './client.mjs';
export async function acquire(repository,{workloadToken,fetcher=fetch,notify=message=>process.stderr.write(message+'\n'),wait=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
  if(!/^susanbeasles\/[A-Za-z0-9_.-]{1,100}$/.test(repository))throw Error('Invalid repository');
  const call=async(path,body,token)=>{
    const res=await fetcher(ORIGIN+path,{method:'POST',redirect:'error',signal:AbortSignal.timeout(20000),headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},body:JSON.stringify(body)});
    const value=JSON.parse(new TextDecoder().decode(await bounded(res.body,16384)));return {status:res.status,value};
  };
  if(workloadToken){const result=await call('/v1/session',{},workloadToken);if(result.status!==200||result.value.repository!==repository)throw Error('Workload identity rejected');return result.value;}
  const pending=await call('/v1/bootstrap',{repository});if(pending.status!==200)throw Error('Owner bootstrap unavailable');
  if(!/^[A-Za-z0-9_-]{43}$/.test(pending.value.id||'')||!/^[A-Za-z0-9_-]{43}$/.test(pending.value.secret||'')||!Number.isFinite(pending.value.expires)||pending.value.expires>Date.now()+600000)throw Error('Invalid bootstrap response');
  notify('Approve request '+pending.value.id+' for '+repository+' at '+ORIGIN+'/owner/pending');
  while(Date.now()<pending.value.expires){
    const result=await call('/v1/redeem',{id:pending.value.id,secret:pending.value.secret});
    if(result.status===200)return result.value;
    if(result.status!==409||result.value.error!=='owner-approval-pending')throw Error('Owner bootstrap rejected');
    await wait(5000);
  }
  throw Error('Owner approval expired');
}
export async function agent(args,env=process.env){
  if(args[0]!=='--repository'||!args[1]||args[2]!=='--'||!args[3])throw Error('Usage: agent.mjs --repository owner/repo -- command [args]');
  const repository=args[1],session=await acquire(repository,{workloadToken:env.SIGNER_WORKLOAD_TOKEN});
  if(typeof session.session!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(session.session)||!Number.isFinite(session.expires)||session.expires<=Date.now())throw Error('Invalid signing session');
  const childEnv={...env,SIGNER_SESSION:session.session,SIGNER_REPOSITORY:repository};delete childEnv.SIGNER_WORKLOAD_TOKEN;
  const identity=await request('/v1/key',{},session.session);
  if(!/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/.test(identity.publicKey||''))throw Error('Invalid signing public key');
  const count=Number(env.GIT_CONFIG_COUNT||0);if(!Number.isSafeInteger(count)||count<0||count>64)throw Error('Invalid inherited Git configuration');
  const settings=[['gpg.format','ssh'],['gpg.ssh.program',fileURLToPath(new URL('./client.mjs',import.meta.url))],['user.signingkey','key::'+identity.publicKey],['commit.gpgsign','true']];
  settings.forEach(([name,value],index)=>{childEnv['GIT_CONFIG_KEY_'+(count+index)]=name;childEnv['GIT_CONFIG_VALUE_'+(count+index)]=value;});childEnv.GIT_CONFIG_COUNT=String(count+settings.length);
  const child=spawn(args[3],args.slice(4),{env:childEnv,stdio:'inherit',shell:false});
  return new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve(signal?1:code??1));});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){agent(process.argv.slice(2)).then(code=>{process.exitCode=code;}).catch(()=>{process.stderr.write('signer: remote session unavailable\n');process.exitCode=1;});}
