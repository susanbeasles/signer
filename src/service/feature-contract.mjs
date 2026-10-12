import {canonical} from '../vendor/repoctl/ledger.mjs';
import {sha256} from '../vendor/repoctl/source-signing/core.mjs';

export const FEATURE_INPUT_FIELDS=Object.freeze(['repositoryID','baseSHA','treeSHA','featureRef','message','author','committer','nonce','expiresAt']);
export const FEATURE_GRANT_FIELDS=Object.freeze(['authorized','requestDigest','policyDigest','signerKeyID','producerID','producerEvidenceDigest','grantID','expiresAt']);
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.slice().sort().join();
const need=(ok,message)=>{if(!ok)throw Error(message);};
const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
function identity(value){
 if(typeof value!=='string'||!value.isWellFormed()||Buffer.byteLength(value)>300)return false;
 const match=/^([^<>\r\n\x00-\x1f]+) <([^<>\s\x00-\x1f]+)> ([0-9]{1,12}) ([+-])([0-9]{2})([0-9]{2})$/.exec(value);
 return !!match&&match[1].trim()===match[1]&&Number(match[5])<=23&&Number(match[6])<=59;
}
// Only bounded commit metadata crosses this boundary. The tree hash is a
// producer claim; this function does not inspect, scan or attest tree contents.
export function featureRequest(input,service,now){
 need(exact(input,FEATURE_INPUT_FIELDS)&&Number.isSafeInteger(service?.repositoryID)&&service.repositoryID>0&&input.repositoryID===service.repositoryID&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(service.repository)&&/^SHA256:[A-Za-z0-9+/]{43}$/.test(service.signer?.keyID),'Invalid exact feature request');
 need(typeof input.baseSHA==='string'&&sha.test(input.baseSHA)&&typeof input.treeSHA==='string'&&sha.test(input.treeSHA)&&typeof input.nonce==='string'&&hash.test(input.nonce),'Invalid feature object identity');
 need(typeof input.featureRef==='string'&&input.featureRef.length<=240&&/^refs\/heads\/(?:feat|fix|feature)\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(input.featureRef),'Feature ref only');
 need(identity(input.author)&&identity(input.committer)&&typeof input.message==='string'&&input.message.isWellFormed()&&Buffer.byteLength(input.message)>0&&Buffer.byteLength(input.message)<=8000&&!/[\x00-\x08\x0b-\x1f\x7f]/.test(input.message)&&input.message.endsWith('\n'),'Invalid exact feature commit metadata');
 need(Number.isSafeInteger(input.expiresAt)&&input.expiresAt>0&&(now===undefined||(Number.isSafeInteger(now)&&input.expiresAt>now&&input.expiresAt<=now+300)),'Feature authorization expired');
 const unsignedCommit=`tree ${input.treeSHA}\nparent ${input.baseSHA}\nauthor ${input.author}\ncommitter ${input.committer}\n\n${input.message}`;
 return {schema:'signing-control-feature-request/v1',repositoryID:service.repositoryID,repository:service.repository,...structuredClone(input),unsignedCommit,objectDigest:sha256(unsignedCommit),signerKeyID:service.signer.keyID};
}
export function validateFeatureAuthorization(request,grant,now){
 need(exact(grant,FEATURE_GRANT_FIELDS)&&grant.authorized===true&&grant.requestDigest===sha256(canonical(request))&&typeof grant.policyDigest==='string'&&hash.test(grant.policyDigest)&&grant.signerKeyID===request.signerKeyID&&typeof grant.grantID==='string'&&hash.test(grant.grantID)&&typeof grant.producerEvidenceDigest==='string'&&hash.test(grant.producerEvidenceDigest)&&typeof grant.producerID==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/.test(grant.producerID)&&Number.isSafeInteger(grant.expiresAt)&&grant.expiresAt>0&&grant.expiresAt<=request.expiresAt&&(now===undefined||(Number.isSafeInteger(now)&&grant.expiresAt>now&&grant.expiresAt<=now+300)),'Independent feature producer authorization unavailable');
 return structuredClone(grant);
}
