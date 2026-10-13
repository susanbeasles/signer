import {canonical} from '../vendor/repoctl/ledger.mjs';
import {sha256,gitObjectID} from '../vendor/repoctl/source-signing/core.mjs';
import {FEATURE_INPUT_FIELDS,featureRequest,validateFeatureAuthorization} from './feature-contract.mjs';
export {featureRequest,validateFeatureAuthorization} from './feature-contract.mjs';

const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join()===keys.slice().sort().join();
const HASH=/^[a-f0-9]{64}$/;
function assemble(payload,signature){const split=payload.indexOf('\n\n');return payload.slice(0,split)+'\ngpgsig '+signature.trimEnd().replaceAll('\n','\n ')+'\n'+payload.slice(split+1);}
function receiptFor(request,authorization,signedCommit){return {schema:'signing-control-feature-receipt/v1',claim:'authenticated-producer-intent',repositoryID:request.repositoryID,repository:request.repository,featureRef:request.featureRef,baseSHA:request.baseSHA,treeSHA:request.treeSHA,commitSHA:gitObjectID('commit',signedCommit),objectDigest:request.objectDigest,signerKeyID:request.signerKeyID,policyDigest:authorization.policyDigest,requestDigest:authorization.requestDigest,producerID:authorization.producerID,producerEvidenceDigest:authorization.producerEvidenceDigest,grantID:authorization.grantID,nonce:request.nonce};}

// workflow_depot authenticates and authorizes the exact producer intent. No
// source objects or local tree proof are accepted or claimed by this service.
export function createFeatureSigning({config,storage,policy,signer,clock=()=>Math.floor(Date.now()/1000)}){
 requireValue(Number.isSafeInteger(config?.repositoryID)&&config.repositoryID>0&&['authorizeFeatureCommit','consumeFeatureCommit','checkFeatureCommit'].every(name=>typeof policy?.[name]==='function')&&typeof storage?.transaction==='function'&&typeof signer?.signGit==='function'&&typeof signer?.verifyGit==='function'&&signer.keyID===config.signer?.keyID,'Installed feature capabilities required');
 config=structuredClone(config);const key=nonce=>`source-feature:${config.repositoryID}:${nonce}`;
 const inputFor=request=>Object.fromEntries(FEATURE_INPUT_FIELDS.map(k=>[k,request[k]]));
 const live=record=>requireValue(record.request.expiresAt>clock()&&record.authorization.expiresAt>clock(),'Feature authority expired');
 async function accepted(request){return validateFeatureAuthorization(request,await policy.authorizeFeatureCommit(structuredClone(request)),clock());}
 function unchanged(record,grant){const checked=validateFeatureAuthorization(record.request,grant,clock());requireValue(canonical(checked)===canonical(record.authorization),'Feature policy or producer grant changed');live(record);return checked;}
 const api={
  async prepare(input){
   const request=featureRequest(input,config,clock());requireValue(!await storage.get(key(request.nonce)),'Feature operation already reserved');
   const authorization=await accepted(request),record={repositoryID:config.repositoryID,request,authorization,state:'signing'};
   await storage.transaction(async tx=>{requireValue(!await tx.get(key(request.nonce)),'Feature operation already reserved');live(record);await tx.put(key(request.nonce),record);});
   try{
    live(record);
    const signature=await signer.signGit({type:'commit',payload:request.unsignedCommit,authorization:{kind:'feature-policy',repositoryID:config.repositoryID,nonce:request.nonce,requestDigest:authorization.requestDigest,grantID:authorization.grantID}});
    requireValue(typeof signature==='string'&&signature.length>0&&signature.length<=16384&&!/[\0\r]/.test(signature)&&await signer.verifyGit({type:'commit',payload:request.unsignedCommit,signature}),'Installed feature signature verification failed');live(record);
    unchanged(record,await policy.checkFeatureCommit({request:structuredClone(request),grantID:authorization.grantID}));
    const signedCommit=assemble(request.unsignedCommit,signature),receipt=receiptFor(request,authorization,signedCommit);
    await storage.transaction(async tx=>{const current=await tx.get(key(request.nonce));requireValue(current?.state==='signing'&&current.signingConsumed===true&&canonical(current.request)===canonical(request)&&canonical(current.authorization)===canonical(authorization),'Feature reservation changed or unconsumed');live(record);await tx.put(key(request.nonce),{...current,state:'signed',signature,signedCommit,receipt});});live(record);return {receipt,signature};
   }catch(error){await storage.transaction(async tx=>{const current=await tx.get(key(request.nonce));if(current?.state==='signing')await tx.put(key(request.nonce),{...current,state:'uncertain'});});throw error;}
  },
  async lookup(input){
   requireValue(exact(input,['repositoryID','nonce'])&&input.repositoryID===config.repositoryID&&typeof input.nonce==='string'&&HASH.test(input.nonce),'Invalid feature metadata lookup');
   const record=await storage.get(key(input.nonce));requireValue(record?.state==='signed'&&record.signingConsumed===true,'Completed signed feature metadata unavailable');
   const request=featureRequest(inputFor(record.request),config);requireValue(canonical(request)===canonical(record.request)&&request.nonce===input.nonce,'Retained feature request changed');validateFeatureAuthorization(request,record.authorization);
   requireValue(record.signedCommit===assemble(request.unsignedCommit,record.signature)&&canonical(record.receipt)===canonical(receiptFor(request,record.authorization,record.signedCommit))&&await signer.verifyGit({type:'commit',payload:request.unsignedCommit,signature:record.signature}),'Completed signed feature metadata unavailable');
   return {receipt:structuredClone(record.receipt),signedCommit:record.signedCommit};
  },
  async authorize({type,payload,authorization}){
   requireValue(type==='commit'&&exact(authorization,['kind','repositoryID','nonce','requestDigest','grantID'])&&authorization.kind==='feature-policy'&&authorization.repositoryID===config.repositoryID&&typeof authorization.nonce==='string'&&HASH.test(authorization.nonce),'Invalid feature signing effect');
   const record=await storage.get(key(authorization.nonce));requireValue(record?.state==='signing'&&!record.signingConsumed&&record.request.unsignedCommit===payload&&record.authorization.requestDigest===authorization.requestDigest&&record.authorization.grantID===authorization.grantID,'Feature effect is not an exact reserved commit');
   requireValue(canonical(featureRequest(inputFor(record.request),config,clock()))===canonical(record.request),'Feature metadata changed');live(record);unchanged(record,await accepted(record.request));
   await storage.transaction(async tx=>{const current=await tx.get(key(authorization.nonce));requireValue(current?.state==='signing'&&!current.signingConsumed&&canonical(current.request)===canonical(record.request)&&canonical(current.authorization)===canonical(record.authorization),'Feature signing effect already consumed or changed');live(record);await tx.put(key(authorization.nonce),{...current,signingConsumed:true});});live(record);
   const consumed=unchanged(record,await policy.consumeFeatureCommit({request:structuredClone(record.request),grantID:record.authorization.grantID}));
   return {authorized:true,keyID:signer.keyID,objectDigest:sha256(payload),expiresAt:consumed.expiresAt};
  }
 };return Object.freeze(api);
}
