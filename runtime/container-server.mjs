import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {Readable} from 'node:stream';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {IMAGE_CONFIG,validateHandoff,validateImageConfiguration} from './handoff.mjs';
import {assertPrivateMemory} from './op-git-signer.mjs';
const MAX_BODY=524288;
async function readBody(request,timeoutMs,beforeParse){
 if(!request.body)throw Error();const reader=request.body.getReader(),chunks=[];let count=0,expired=false,bytes;
 const timer=setTimeout(()=>{expired=true;void reader.cancel().catch(()=>{});},timeoutMs);
 try{for(;;){const {done,value}=await reader.read();if(expired)throw Error();if(done)break;count+=value.length;if(count>MAX_BODY)throw Error();chunks.push(value);}await beforeParse();if(expired)throw Error();bytes=Buffer.concat(chunks);return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 finally{clearTimeout(timer);void reader.cancel().catch(()=>{});bytes?.fill(0);for(const chunk of chunks)chunk.fill(0);}
}
export function createContainerHandler({immutableConfig,launch,onTerminal,clock=()=>Math.floor(Date.now()/1000),bodyTimeoutMs=5000,preflight=assertPrivateMemory}){
 immutableConfig=validateImageConfiguration(immutableConfig);let reserved=false;
 if(typeof launch!=='function'||typeof onTerminal!=='function')throw Error('Installed lifecycle required');
 return async request=>{
  const url=new URL(request.url);
  if(request.method==='GET'&&url.pathname==='/ready'&&!url.search){try{await preflight();return new Response(null,{status:reserved?409:204});}catch{return new Response(null,{status:503});}}
  if(request.method!=='POST'||url.pathname!=='/v1/execute'||url.search)return new Response(null,{status:404});
  if(reserved)return new Response(null,{status:409});reserved=true;
  try{
   await preflight();let body=validateHandoff(await readBody(request,bodyTimeoutMs,preflight),immutableConfig,clock());
   // Claim before reading, and launch at most once. A failed or lost reply never
   // reopens the container lifetime; controller reconciliation destroys it.
   setImmediate(()=>{if(body.job.deadline<=clock()){body=null;onTerminal();return;}Promise.resolve().then(()=>launch(body)).catch(()=>{}).finally(()=>{body=null;onTerminal();});});
   return new Response(null,{status:202});
  }catch{setImmediate(onTerminal);return new Response(null,{status:400});}
 };
}
export async function launchSupervisor(body,{spawnImpl=spawn,clock=()=>Math.floor(Date.now()/1000)}={}){
 await assertPrivateMemory();
 return new Promise((resolve,reject)=>{
  if(body.job.deadline<=clock()){reject(Error('Signing supervisor unavailable'));return;}
  const child=spawnImpl(process.execPath,[fileURLToPath(new URL('./supervisor.mjs',import.meta.url))],{env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',LC_ALL:'C.UTF-8',NODE_EXTRA_CA_CERTS:'/etc/cloudflare/certs/cloudflare-containers-ca.crt'},stdio:['pipe','pipe','pipe','pipe','pipe'],detached:true,windowsHide:true});
  let failed=false,size=0;const output=[];
  const stop=()=>{failed=true;try{process.kill(-child.pid,'SIGKILL');}catch{try{child.kill('SIGKILL');}catch{}}};
  const timer=setTimeout(stop,Math.max(1,(body.job.deadline-clock())*1000));
  child.on('error',stop);for(const stream of [child.stdin,child.stdio[3],child.stdio[4]])stream.on('error',stop);
  child.stdout.on('data',chunk=>{size+=chunk.length;if(size>1024){chunk.fill(0);stop();}else output.push(chunk);});child.stderr.on('data',chunk=>{size+=chunk.length;chunk.fill(0);if(size>1024)stop();});
  child.once('close',code=>{clearTimeout(timer);try{const receipt=JSON.parse(Buffer.concat(output).toString());if(failed||code!==0||receipt.jobId!==body.job.id||receipt.state!=='completed'||Object.keys(receipt).sort().join()!=='jobId,state')throw Error();resolve(receipt);}catch{reject(Error('Signing supervisor unavailable'));}finally{for(const chunk of output)chunk.fill(0);}});
  child.stdin.end(JSON.stringify({job:body.job,config:body.config}));child.stdio[3].end(JSON.stringify(body.serviceAccountToken));child.stdio[4].end(JSON.stringify(body.callbackToken));body.serviceAccountToken=null;body.callbackToken=null;
 });
}
export async function serve(){
 await assertRuntimeIdentity();await assertPrivateMemory();
 const bytes=await readFile(IMAGE_CONFIG);if(bytes.length>262144)throw Error('Image configuration unavailable');const immutableConfig=JSON.parse(bytes);
 const terminate=()=>setTimeout(()=>process.exit(0),25);const handler=createContainerHandler({immutableConfig,launch:launchSupervisor,onTerminal:terminate});
 const server=createServer(async(req,res)=>{try{const request=new Request('http://container'+req.url,{method:req.method,headers:req.headers,...(req.method==='GET'||req.method==='HEAD'?{}:{body:Readable.toWeb(req),duplex:'half'})});const response=await handler(request);res.writeHead(response.status,{'cache-control':'no-store','connection':'close'});res.end();}catch{res.writeHead(400);res.end();}});
 server.requestTimeout=5000;server.headersTimeout=5000;server.maxRequestsPerSocket=1;
 process.once('SIGTERM',()=>process.exit(1));process.once('SIGINT',()=>process.exit(1));
 // This entrypoint is container PID1. Its exit must destroy the entire container
 // cgroup, including detached op/ssh-agent descendants. This is a mandatory
 // platform qualification, not a guarantee provided by JavaScript timers.
 const idle=setTimeout(()=>process.exit(1),300000);server.once('close',()=>clearTimeout(idle));server.listen(8080,'0.0.0.0');return server;
}
export async function assertRuntimeIdentity({pid=process.pid,readStatus=()=>readFile('/proc/self/status','utf8')}={}){
 const status=await readStatus();
 if(pid!==1||!/^Uid:\s+10001\s+10001\s+10001\s+10001\s*$/m.test(status)||!/^Gid:\s+10001\s+10001\s+10001\s+10001\s*$/m.test(status)||!/^Groups:[ \t]*$/m.test(status)||!/^NoNewPrivs:\s+1\s*$/m.test(status)||!['Inh','Prm','Eff','Bnd','Amb'].every(name=>new RegExp('^Cap'+name+':\\s+0+\\s*$','m').test(status)))throw Error('Container identity unavailable');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){serve().catch(()=>process.exit(1));}
