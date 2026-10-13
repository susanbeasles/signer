import {createHash} from 'node:crypto';
import {canonical} from '../src/vendor/repoctl/ledger.mjs';
import {validateSignerConfig} from './op-git-signer.mjs';
import {validateGitConfig} from '../src/service/source.mjs';
export const IMAGE_CONFIG='/opt/signing-control/config/runtime.json';
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.slice().sort().join();
const check=ok=>{if(!ok)throw Error('Private handoff denied');};
const actions=['prepareFeature','prepare','retireShadow','publishShadow','approvalIntent','approve','publish','lookupCandidate','lookupReviewPolicy','lookupReceipt','verifyPromotion','lookupFeature'];
export const signingActions=['prepareFeature','prepare','approve'];
export function validateImageConfiguration(config){
 check(exact(config,['services','runtime'])&&Array.isArray(config.services)&&config.services.length>=1&&config.services.length<=32);validateSignerConfig(config.runtime);
 const ids=new Set(),names=new Set();
 for(const service of config.services){
  check(exact(service,['schema','repositoryID','repository','git','signer'])&&service.schema==='signing-control-service/v1'&&Number.isSafeInteger(service.repositoryID)&&service.repositoryID>0&&typeof service.repository==='string'&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(service.repository)&&exact(service.signer,['keyID'])&&service.signer.keyID===config.runtime.keyID&&!ids.has(service.repositoryID)&&!names.has(service.repository));
  validateGitConfig(service.git);ids.add(service.repositoryID);names.add(service.repository);
 }
 return structuredClone(config);
}
export function validateImageService(config,immutableConfig){
 const image=validateImageConfiguration(immutableConfig);check(exact(config,['service','runtime','platform'])&&canonical(config.runtime)===canonical(image.runtime)&&image.services.some(service=>canonical(service)===canonical(config.service)));return structuredClone(config);
}
export function validateHandoff(body,immutableConfig,now=Math.floor(Date.now()/1000)){
 check(exact(body,['job','config','serviceAccountToken','callbackToken']));const {job,config}=body;
 validateImageService(config,immutableConfig);
 check(exact(config.platform,['provider','imageDigest'])&&config.platform.provider==='cloudflare-containers'&&/^sha256:[a-f0-9]{64}$/.test(config.platform.imageDigest??''));
 check(exact(job,['version','id','action','input','configDigest','deadline'])&&job.version===1&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(job.id??'')&&actions.includes(job.action));
 check(Number.isSafeInteger(job.deadline)&&job.deadline>now&&job.deadline<=now+300);
 check(job.configDigest===createHash('sha256').update(canonical(config)).digest('hex'));
 check(['lookupReceipt','verifyPromotion'].includes(job.action)?exact(job.input,['receiptDigest'])&&/^[a-f0-9]{64}$/.test(job.input.receiptDigest??''):job.input?.repositoryID===config.service.repositoryID);
 check(typeof body.callbackToken==='string'&&/^[A-Za-z0-9_-]{43}$/.test(body.callbackToken));
 check(signingActions.includes(job.action)?typeof body.serviceAccountToken==='string'&&/^[\x21-\x7e]{1,8192}$/.test(body.serviceAccountToken):body.serviceAccountToken===null);
 return structuredClone(body);
}
