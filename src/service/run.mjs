import {canonical} from '../vendor/repoctl/ledger.mjs';
import {createSourceSigning,ownerApprovalVerifier,sha256} from '../vendor/repoctl/source-signing/core.mjs';
import {createOpGitSigner,validateSignerConfig} from '../../runtime/op-git-signer.mjs';
import {createRemoteStorage,createCapabilities} from './adapters.mjs';
import {acquireSource,validateGitConfig} from './source.mjs';
import {createSigningAuthorization} from './authorization.mjs';
import {createFeatureSigning} from './feature.mjs';
import {featureRequest} from './feature-contract.mjs';
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.slice().sort().join();
const check=value=>{if(!value)throw Error('Trusted source job unavailable');};
export const ACTIONS=Object.freeze(['prepare','retireShadow','publishShadow','approvalIntent','approve','publish','lookupCandidate','lookupReviewPolicy','lookupReceipt','verifyPromotion','prepareFeature','lookupFeature']);
const INPUT_FIELDS={prepare:['repositoryID','sourcePR','author','committer','message','artifactIntentDigest','expiresAt'],retireShadow:['repositoryID','sequence'],publishShadow:['repositoryID','sequence'],approvalIntent:['repositoryID','sequence','expiresAt'],approve:['repositoryID','sequence','ownerApproval'],publish:['repositoryID','sequence'],lookupCandidate:['repositoryID','commitSHA','shadowRef'],lookupReviewPolicy:['repositoryID','commitSHA','shadowRef'],lookupReceipt:['receiptDigest'],verifyPromotion:['receiptDigest'],prepareFeature:['repositoryID','baseSHA','treeSHA','featureRef','message','author','committer','nonce','expiresAt'],lookupFeature:['repositoryID','nonce']};
export function validateJobConfiguration(job,config,now=Math.floor(Date.now()/1000)){
 check(exact(config,['service','runtime','platform']));const service=config.service;
 check(exact(service,['schema','repositoryID','repository','git','signer'])&&service.schema==='signing-control-service/v1'&&Number.isSafeInteger(service.repositoryID)&&service.repositoryID>0&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(service.repository)&&exact(service.signer,['keyID']));
 validateGitConfig(service.git);validateSignerConfig(config.runtime);check(service.signer.keyID===config.runtime.keyID&&exact(config.platform,['provider','imageDigest'])&&config.platform.provider==='cloudflare-containers'&&/^sha256:[a-f0-9]{64}$/.test(config.platform.imageDigest));
 check(exact(job,['version','id','action','input','configDigest','deadline'])&&job.version===1&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(job.id)&&ACTIONS.includes(job.action)&&job.configDigest===sha256(canonical(config))&&Number.isSafeInteger(job.deadline)&&job.deadline>now&&job.deadline<=now+300&&job.input&&Object.getPrototypeOf(job.input)===Object.prototype);
 check(exact(job.input,INPUT_FIELDS[job.action]));check(['lookupReceipt','verifyPromotion'].includes(job.action)?/^[a-f0-9]{64}$/.test(job.input.receiptDigest):job.input.repositoryID===service.repositoryID);if(job.action==='prepareFeature')featureRequest(job.input,service,now);return structuredClone(config);
}

// The only production composition. No page-selected module, executable, signer,
// policy object, evidence boolean, publisher URL, or source bytes enter here.
export async function runTrustedJob({job,config,serviceAccountToken,transport}){
 config=validateJobConfiguration(job,config);const clock=()=>Math.floor(Date.now()/1000),live=()=>check(clock()<job.deadline);
 const guarded={async call(path,input){live();const value=await transport.call(path,input);live();return value;}},storage=createRemoteStorage(guarded),caps=createCapabilities(guarded);
 const acceptedPolicy={...caps.policy,async current(input){check(input?.repositoryID===config.service.repositoryID);const value=await caps.policy.current(input);check(value?.authority==='workflow_depot'&&value.repositoryID===config.service.repositoryID&&value.repository===config.service.repository&&value.signerKeyID===config.service.signer.keyID);return value;}};
 let signer,source,feature,authorize;
 try{
  signer=await createOpGitSigner({config:config.runtime,serviceToken:serviceAccountToken,deadline:job.deadline,authorize:input=>input.authorization?.kind==='feature-policy'?feature.authorize(input):authorize(input)});
  if(['prepareFeature','lookupFeature'].includes(job.action)){
   feature=createFeatureSigning({config:config.service,storage,policy:caps.policy,signer,clock});return await (job.action==='prepareFeature'?feature.prepare(job.input):feature.lookup(job.input));
  }
  let sourcePRNumber=job.input.sourcePR?.number;
  if(!sourcePRNumber){let sequence=job.input.sequence;if(job.input.commitSHA)sequence=(await storage.get(`source-commit:${config.service.repositoryID}:${job.input.commitSHA}`))?.sequence;if(job.input.receiptDigest)sequence=(await storage.get('source-receipt:'+job.input.receiptDigest))?.sequence;sourcePRNumber=(await storage.get(`source-signing:${config.service.repositoryID}:${sequence}`))?.sourcePR?.number;}
  const policy=await acceptedPolicy.current({repositoryID:config.service.repositoryID,sourcePRNumber});source=await acquireSource({service:config.service,policy,capabilities:caps,deadline:job.deadline,needSnapshot:job.action==='prepare',clock});
  const approvalVerifier=ownerApprovalVerifier({currentPolicy:acceptedPolicy.current,currentHardware:caps.hardware,clock});
  authorize=createSigningAuthorization({storage,policy:acceptedPolicy,git:source.git,signerKeyID:signer.keyID,approvalVerifier,ci:caps.ci,scans:caps.scans,review:caps.review,clock});
  let core;
  const publisher={...caps.publisher,
   async putObject(type,payload){const retained=await storage.get(`source-signing:${config.service.repositoryID}:${job.input.sequence}`);check(retained&&((type==='commit'&&retained.signedCommit===payload)||(type==='tag'&&Object.values(retained.tags??{}).some(tag=>tag.object===payload))));return caps.publisher.putObject(type,payload);},
   async createRef(ref,objectSHA){await core.authorizePublication({repository:config.service.repository,repositoryID:config.service.repositoryID,operation:'create-ref',ref,objectSHA});return caps.publisher.createRef(ref,objectSHA);},
   async deleteRef(input){await core.authorizePublication({repository:config.service.repository,repositoryID:config.service.repositoryID,operation:'delete-ref',...input});return caps.publisher.deleteRef(input);},
   async closePullRequest(input){await core.authorizePublication({repository:config.service.repository,repositoryID:config.service.repositoryID,operation:'close-pull-request',...input});return caps.publisher.closePullRequest(input);},
   async createPullRequest(input){await core.authorizePublication({repository:config.service.repository,repositoryID:config.service.repositoryID,operation:'create-pull-request',...input});return caps.publisher.createPullRequest(input);}
  };
  core=createSourceSigning({storage,policy:acceptedPolicy,git:source.git,signer,approvalVerifier,ci:caps.ci,scans:caps.scans,review:caps.review,publisher,clock});live();return await core[job.action](job.input);
 }finally{await signer?.close();await source?.close();}
}
