import {spawn} from 'node:child_process';

// The acquisition adapter supplies the pinned executable, fixed Git arguments,
// and an empty-base environment. No request may invoke this directly.
export function runGitProcess(program,args,{cwd,input='',env={},limit=8388608,timeoutMs=30000}={}){
 return new Promise((resolve,reject)=>{
  if(!Number.isSafeInteger(limit)||limit<1||limit>8388608||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>120000){reject(Error('Git process bounds unavailable'));return;}
  const child=spawn(program,args,{cwd,env,stdio:['pipe','pipe','pipe'],shell:false,detached:true});let failed=false,settled=false,count=0;const chunks=[];
  const stop=()=>{failed=true;if(child.pid){try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}}};
  const timer=setTimeout(stop,timeoutMs),finish=code=>{if(settled)return;settled=true;clearTimeout(timer);if(failed||code!==0){chunks.forEach(chunk=>chunk.fill(0));reject(Error('Fixed Git process failed or exceeded bounds'));}else resolve(Buffer.concat(chunks));};
  child.on('error',()=>{failed=true;finish(1);});child.on('close',finish);child.stdin.on('error',stop);
  for(const [stream,save]of [[child.stdout,true],[child.stderr,false]])stream.on('data',chunk=>{count+=chunk.length;if(count>limit){stop();chunk.fill(0);}else if(save)chunks.push(chunk);else chunk.fill(0);});
  child.stdin.end(input);
 });
}
