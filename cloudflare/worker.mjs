import {DurableObject,WorkerEntrypoint} from 'cloudflare:workers';
import {CAPABILITIES,READS,configDigest,validateInstallation,installationConfigurations,selectConfiguration,createSigningController} from './controller.mjs';
const BINDINGS={policy:'SOURCE_POLICY',hardware:'OWNER_HARDWARE',ci:'SOURCE_CI',scans:'SOURCE_SCANS',review:'SOURCE_REVIEW',inventory:'SOURCE_INVENTORY',publisher:'SOURCE_PUBLISHER',source:'SOURCE_READ_CREDENTIAL'};
const denied=()=>{throw Error('signing-control-unavailable');};
const unavailable=()=>Response.json({error:'signing-control-unavailable'},{status:503,headers:{'cache-control':'no-store'}});
function installation(env){if(env.ENABLED!=='true'||typeof env.SIGNING_CONTROL_CONFIG_JSON!=='string'||env.SIGNING_CONTROL_CONFIG_JSON.length>262144)denied();return validateInstallation(JSON.parse(env.SIGNING_CONTROL_CONFIG_JSON));}
function configuration(env,repositoryID){return selectConfiguration(installation(env),repositoryID);}
function repository(env,repositoryID){const config=configuration(env,repositoryID);if(!env.SIGNING_CONTROL_STATE)denied();return env.SIGNING_CONTROL_STATE.getByName(String(config.service.repositoryID));}
async function guarded(fn){try{return await fn();}catch{denied();}}
function installedCapabilities(env){return Object.fromEntries(Object.entries(CAPABILITIES).map(([name,methods])=>[name,Object.fromEntries(methods.filter(method=>typeof env[BINDINGS[name]]?.[method]==='function').map(method=>[method,input=>env[BINDINGS[name]][method](input)]))]));}

// Binding-only service: public HTTP, including alternate paths, never invokes it.
export default {fetch(){return new Response('Not found',{status:404,headers:{'cache-control':'no-store'}});}};
export class SigningControlRepository extends DurableObject {
 constructor(ctx,env){super(ctx,env);this.controller=null;
  if(env.ENABLED==='true')ctx.blockConcurrencyWhile(async()=>{
   try{const choices=installationConfigurations(installation(env)),config=choices.find(candidate=>env.SIGNING_CONTROL_STATE.idFromName(String(candidate.service.repositoryID)).toString()===ctx.id.toString());if(!config)denied();this.repositoryID=config.service.repositoryID;this.controller=createSigningController({storage:ctx.storage,container:ctx.container,containerId:ctx.id.toString(),config,capabilities:installedCapabilities(env),serviceToken:()=>env.OP_SERVICE_ACCOUNT_TOKEN,interceptor:props=>ctx.exports.SigningControlEgress({props}),waitUntil:promise=>ctx.waitUntil(promise)});await this.controller.resume();}catch{this.controller=null;}
  });
 }
 requireController(){configuration(this.env,this.repositoryID);if(!this.controller)denied();return this.controller;}
 execute(job){return guarded(()=>this.requireController().execute(job));}
 status(input){return guarded(()=>{if(!input||Object.keys(input).join()!=='id')denied();return this.requireController().status(input.id);});}
 verifyPublication(input){return guarded(()=>this.requireController().verifyPublication(input));}
 alarm(){return guarded(()=>this.requireController().alarm());}
 outbound(request,props){return guarded(()=>this.requireController().outbound(request,props));}
}
export class SourceActions extends WorkerEntrypoint {
 execute(job){return guarded(()=>repository(this.env,job?.input?.repositoryID).execute(job));}
 status(input){return guarded(()=>{if(!input||!['id','id,repositoryID'].includes(Object.keys(input).sort().join()))denied();return repository(this.env,input.repositoryID).status({id:input.id});});}
 fetch(){return new Response('Not found',{status:404});}
}
async function readProof(env,action,input){
 const config=configuration(env,input?.repositoryID);if(!READS.includes(action))denied();const stub=repository(env,input?.repositoryID),deadline=Math.floor(Date.now()/1000)+60;
 const job={version:1,id:crypto.randomUUID(),action,input,configDigest:configDigest(config),deadline};
 let status=await stub.execute(job);
 while(['launching','running','finishing'].includes(status.state)&&Math.floor(Date.now()/1000)<deadline){await new Promise(resolve=>setTimeout(resolve,100));status=await stub.status({id:job.id});}
 if(status.state!=='completed')denied();return status.result;
}
export class SourceCandidates extends WorkerEntrypoint {
 lookupCandidate(input){return guarded(()=>readProof(this.env,'lookupCandidate',input));}
 lookupReviewPolicy(input){return guarded(()=>readProof(this.env,'lookupReviewPolicy',input));}
 lookupFeature(input){return guarded(()=>readProof(this.env,'lookupFeature',input));}
 fetch(){return new Response('Not found',{status:404});}
}
export class SigningReceipts extends WorkerEntrypoint {
 lookupReceipt(input){return guarded(()=>readProof(this.env,'lookupReceipt',input));}
 verifyPromotion(input){return guarded(()=>readProof(this.env,'verifyPromotion',input));}
 fetch(){return new Response('Not found',{status:404});}
}
// Installed publisher consumes only an already retained one-use effect grant.
export class PublicationAuthority extends WorkerEntrypoint {
 verify(input){return guarded(()=>repository(this.env,input?.repositoryID).verifyPublication(input));}
 fetch(){return new Response('Not found',{status:404});}
}
export class SigningControlEgress extends WorkerEntrypoint {
 async fetch(request){try{const props=this.ctx.props,config=configuration(this.env,props?.repositoryID);if(!props||props.repositoryID!==config.service.repositoryID)return unavailable();return await repository(this.env,props.repositoryID).outbound(request,props);}catch{return unavailable();}}
}
