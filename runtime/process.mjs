import {spawn} from 'node:child_process';
import {readFile,realpath,stat,lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';

const failure=()=>Error('Signer subprocess unavailable');
export async function pinExecutable(tool){
 if(!tool||typeof tool.path!=='string'||!/^\/[A-Za-z0-9_./-]+$/.test(tool.path)||! /^[a-f0-9]{64}$/.test(tool.sha256??''))throw failure();
 const path=await realpath(tool.path),info=await stat(path);
 if(!info.isFile()||info.mode&0o022||!(info.mode&0o111)||createHash('sha256').update(await readFile(path)).digest('hex')!==tool.sha256)throw failure();return path;
}
function killGroup(child){if(child.pid){try{process.kill(-child.pid,'SIGKILL');}catch{try{child.kill('SIGKILL');}catch{}}}}
export function runBounded(program,args,{input,env,timeoutMs=10000,limit=32768,signal}={}){
 return new Promise((resolve,reject)=>{
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000||!Number.isSafeInteger(limit)||limit<1||limit>65536||signal?.aborted){reject(failure());return;}
  let child;try{child=spawn(program,args,{env,stdio:['pipe','pipe','pipe'],detached:true,windowsHide:true});}catch{reject(failure());return;}
  const chunks=[];let count=0,failed=false,settled=false;
  const stop=()=>{failed=true;killGroup(child);},timer=setTimeout(stop,timeoutMs);
  signal?.addEventListener('abort',stop,{once:true});
  const finish=code=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',stop);if(failed||code!==0){for(const b of chunks)b.fill(0);reject(failure());}else{const result=Buffer.concat(chunks);for(const b of chunks)b.fill(0);resolve(result);}};
  child.on('error',()=>{failed=true;finish(1);});child.on('close',finish);
  for(const [stream,save]of [[child.stdout,true],[child.stderr,false]])stream.on('data',data=>{count+=data.length;if(count>limit){stop();data.fill(0);return;}if(save)chunks.push(data);else data.fill(0);});
  child.stdin.on('error',stop);child.stdin.end(input);
 });
}
export async function startAgent(program,socket,{env,timeoutMs=5000,signal}={}){
 if(signal?.aborted)throw failure();
 const child=spawn(program,['-D','-a',socket],{env,stdio:['ignore','pipe','pipe'],detached:true,windowsHide:true});
 let failed=false,closed=false,count=0;const closedPromise=new Promise(resolve=>{child.once('close',()=>{closed=true;resolve();});child.once('error',()=>{failed=true;resolve();});});
 const stop=()=>{failed=true;killGroup(child);};signal?.addEventListener('abort',stop,{once:true});
 for(const stream of [child.stdout,child.stderr])stream.on('data',data=>{count+=data.length;data.fill(0);if(count>8192)stop();});
 const close=async()=>{signal?.removeEventListener('abort',stop);killGroup(child);await closedPromise;};
 try{
  const deadline=Date.now()+Math.min(timeoutMs,5000);
  while(Date.now()<deadline&&!closed&&!failed&&!signal?.aborted){
   try{if((await lstat(socket)).isSocket())return {close};}catch(error){if(error.code!=='ENOENT')throw error;}
   await new Promise(resolve=>setTimeout(resolve,10));
  }
  throw failure();
 }catch{await close();throw failure();}
}
