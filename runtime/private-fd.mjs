import {Socket} from 'node:net';

// Read the inherited descriptor itself: reopening /proc/self/fd fails for the
// socketpair that Node uses for private child_process stdio pipes.
export function readJSONFD(fd,{maxBytes=32770,timeoutMs=5000}={}){
 return new Promise((resolve,reject)=>{
  const chunks=[];let size=0,settled=false;const stream=new Socket({fd,readable:true,writable:false});
  const finish=(error)=>{if(settled)return;settled=true;clearTimeout(timer);stream.destroy();const bytes=Buffer.concat(chunks);try{if(error)throw error;resolve(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));}catch{reject(Error('Private handoff unavailable'));}finally{bytes.fill(0);for(const chunk of chunks)chunk.fill(0);}};
  const timer=setTimeout(()=>finish(Error()),timeoutMs);
  stream.on('data',chunk=>{size+=chunk.length;if(size>maxBytes){chunk.fill(0);finish(Error());}else chunks.push(chunk);});
  stream.once('end',()=>finish());stream.once('error',()=>finish(Error()));
 });
}
export async function readPrivateFD(fd,options){const value=await readJSONFD(fd,options);if(value!==null&&typeof value!=='string')throw Error('Private handoff unavailable');return value;}
