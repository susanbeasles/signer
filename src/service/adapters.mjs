import {canonical} from '../vendor/repoctl/ledger.mjs';

const clone=structuredClone;
export function createRemoteStorage(transport){
 if(typeof transport?.call!=='function')throw Error('Private durable transport required');
 async function snapshot(){
  const value=await transport.call('/v1/state/snapshot',{});
  if(!Number.isSafeInteger(value?.revision)||value.revision<0||!Array.isArray(value.entries)||value.entries.length>10000)throw Error('Invalid durable snapshot');
  const rows=new Map();for(const entry of value.entries){if(typeof entry?.key!=='string'||rows.has(entry.key)||!Object.hasOwn(entry,'value'))throw Error('Invalid durable entries');rows.set(entry.key,clone(entry.value));}
  return {revision:value.revision,rows};
 }
 const storage={
  async get(key){return clone((await snapshot()).rows.get(key));},
  async put(key,value){return storage.transaction(tx=>tx.put(key,value));},
  async transaction(fn){
   const {revision,rows}=await snapshot(),writes=new Map();
   const result=await fn({get:async key=>clone(rows.get(key)),put:async(key,value)=>{if(typeof key!=='string'||value===undefined)throw Error('Invalid durable write');rows.set(key,clone(value));writes.set(key,clone(value));}});
   if(writes.size){const response=await transport.call('/v1/state/transaction',{expectedRevision:revision,writes:[...writes].map(([key,value])=>({key,value}))});if(response?.revision!==revision+1)throw Error('Durable commit acknowledgement differs');}
   return result;
  }
 };return Object.freeze(storage);
}

export function createCapabilities(transport){
 if(typeof transport?.call!=='function')throw Error('Installed private capabilities required');
 const invoke=(capability,method,input)=>transport.call(`/v1/capability/${capability}/${method}`,{input});
 const caps={};
 for(const [name,methods] of Object.entries({policy:['current','authorizeCandidate','authorizeFeatureCommit','consumeFeatureCommit','checkFeatureCommit'],hardware:['verify'],ci:['verify'],scans:['verify'],review:['verify'],source:['credential']}))caps[name]=Object.fromEntries(methods.map(method=>[method,input=>invoke(name,method,input)]));
 caps.inventory={classify:({repositoryID,treeSHA,entries})=>invoke('inventory','classify',{repositoryID,treeSHA,entries})};
 caps.publisher={putObject:(type,payload)=>{if(!['commit','tag'].includes(type)||typeof payload!=='string'||Buffer.byteLength(payload)>32768||payload.includes('\0')||!(type==='commit'?/^tree [a-f0-9]{40}\nparent [a-f0-9]{40}\nauthor /:/^object [a-f0-9]{40}\ntype commit\ntag promotion\//).test(payload))throw Error('Signed Git metadata only');return invoke('publisher','putObject',{type,payload});},readRef:ref=>invoke('publisher','readRef',{ref}),createRef:(ref,objectSHA)=>invoke('publisher','createRef',{ref,objectSHA}),findPullRequest:input=>invoke('publisher','findPullRequest',input),createPullRequest:input=>invoke('publisher','createPullRequest',input),deleteRef:input=>invoke('publisher','deleteRef',input),closePullRequest:input=>invoke('publisher','closePullRequest',input)};
 return Object.freeze(caps);
}

export function createPrivateTransport({callbackToken,jobID,fetchImpl=fetch,deadline,clock=()=>Math.floor(Date.now()/1000)}){
 if(!/^[A-Za-z0-9_-]{43}$/.test(callbackToken??'')||!/^[a-f0-9-]{36}$/i.test(jobID??'')||!Number.isSafeInteger(deadline))throw Error('Private callback identity required');
 return Object.freeze({async call(path,input){
  if(!/^\/v1\/(?:state\/(?:snapshot|transaction)|jobs\/complete|capability\/[a-z]+\/[A-Za-z]+)$/.test(path)||clock()>=deadline)throw Error('Private callback unavailable');
  const body=canonical(input);if(Buffer.byteLength(body)>2*1024*1024)throw Error('Private callback exceeds bounds');
  const response=await fetchImpl('https://signing-control.internal'+path,{method:'POST',redirect:'error',headers:{'content-type':'application/json',authorization:'Bearer '+callbackToken,'x-signing-job':jobID},body,signal:AbortSignal.timeout(Math.min(30000,Math.max(1,(deadline-clock())*1000)))});
  if(!response.ok)throw Error('Installed private capability denied');
  const reader=response.body?.getReader();if(!reader)throw Error('Empty private capability response');const chunks=[];let size=0;
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>2*1024*1024){await reader.cancel();throw Error('Private capability response exceeds bounds');}chunks.push(value);}
  let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Error('Invalid private capability response');}return value;
 }});
}
