import {canonical} from '../vendor/repoctl/ledger.mjs';
import {sha256,validateReviewReceipt} from '../vendor/repoctl/source-signing/core.mjs';
import {validateScanEvidence} from '../vendor/repoctl/source-signing/scans.mjs';
const check=(value,message='Exact retained signing authority unavailable')=>{if(!value)throw Error(message);};
export function candidateRequest(r){const s=r.snapshot,c=r.config;return {repositoryID:r.repositoryID,repository:c.repository,sourceRef:c.sourceRef,targetRef:c.targetRef,sourcePR:r.sourcePR,sourceSHA:s.sourceSHA,sourceBaseSHA:s.sourceBaseSHA,baseSHA:s.mainSHA,treeSHA:s.treeSHA,historyDigest:s.historyDigest,unsignedCommit:r.unsignedCommit,unsignedCommitDigest:r.unsignedCommitDigest,artifactIntentDigest:r.artifactIntentDigest,sequence:r.sequence,shadowRef:r.shadowRef,signerKeyID:c.signerKeyID,policyDigest:c.policyDigest};}
export function createSigningAuthorization({storage,policy,git,signerKeyID,approvalVerifier,ci,scans,review,clock=()=>Math.floor(Date.now()/1000)}){
 async function current(r){check(canonical(await policy.current({repositoryID:r.repositoryID,sourcePRNumber:r.sourcePR.number}))===canonical(r.config),'Source policy changed');check(r.config.signerKeyID===signerKeyID&&await git.main(r.config)===r.snapshot.mainSHA&&await git.source(r.config)===r.snapshot.sourceSHA,'Source or main changed');}
 return async({type,payload,authorization})=>{
  check(authorization&&Number.isSafeInteger(authorization.repositoryID)&&authorization.repositoryID>0&&Number.isSafeInteger(authorization.sequence)&&authorization.sequence>0&&typeof payload==='string'&&Buffer.byteLength(payload)<=24000);
  const recordKey=`source-signing:${authorization.repositoryID}:${authorization.sequence}`,r=await storage.get(recordKey);check(r&&r.expiresAt>clock());await current(r);let kind,expiresAt;
  if(type==='commit'&&authorization.kind==='candidate-policy'){
   check(r.state==='signing'&&payload===r.unsignedCommit&&sha256(payload)===r.unsignedCommitDigest&&canonical(authorization)===canonical({kind:'candidate-policy',...r.candidateAuthorization,repositoryID:r.repositoryID,sequence:r.sequence}));
   const request=candidateRequest(r),accepted=await policy.authorizeCandidate(request);
   check(accepted?.eligible===true&&accepted.requestDigest===sha256(canonical(request))&&accepted.policyDigest===r.config.policyDigest&&accepted.signerKeyID===signerKeyID&&Number.isSafeInteger(accepted.expiresAt)&&accepted.expiresAt<=clock()+300);
   expiresAt=Math.min(r.expiresAt,r.candidateAuthorization.expiresAt,accepted.expiresAt);kind='commit';
  }else if(type==='tag'&&authorization.kind==='owner-approved-tags'){
   check(r.state==='tag-signing');kind=['source','main'].find(name=>payload===r.approvalPayload?.[`${name}TagPayload`]);check(kind&&canonical(authorization)===canonical({kind:'owner-approved-tags',approvalReference:r.approvalPayload.approvalReference,approvalDigest:r.approvalDigest,repositoryID:r.repositoryID,sequence:r.sequence,objectDigest:sha256(payload)}));
   const owner=await approvalVerifier.verify(r.ownerApproval,r.approvalPayload,{repositoryID:r.repositoryID});check(owner?.hardwareVerified===true&&owner.validUntil>clock()&&sha256(canonical(r.ownerApproval))===r.approvalDigest);
   const input={repositoryID:r.repositoryID,sourcePRNumber:r.sourcePR.number,sourceSHA:r.snapshot.sourceSHA,baseSHA:r.snapshot.mainSHA,commitSHA:r.finalSignedCommitSHA,treeSHA:r.snapshot.treeSHA,policyDigest:r.config.policyDigest,artifactIntentDigest:r.artifactIntentDigest,shadowRef:r.shadowRef};
   const checked=await ci.verify(input);check(checked?.verified===true&&checked.requestDigest===sha256(canonical(input)));
   const scanned=await scans.verify(input);check(scanned?.verified===true);validateScanEvidence(scanned.receipt,input,r.config.scanPolicy,r.snapshot.inventory,clock());
   const reviewed=await review.verify(input);check(reviewed?.verified===true);validateReviewReceipt(reviewed.receipt,input,r.config.reviewPolicy,clock());expiresAt=Math.min(r.expiresAt,owner.validUntil,clock()+60);
  }else throw Error('No generic signing capability');
  await current(r);check(Number.isSafeInteger(expiresAt)&&expiresAt>clock());const effectKey=`source-signing-effect:${r.repositoryID}:${r.sequence}:${kind}`,effect={repositoryID:r.repositoryID,sequence:r.sequence,kind,objectDigest:sha256(payload),expiresAt};
  await storage.transaction(async tx=>{const retained=await tx.get(recordKey);check(retained&&canonical(retained)===canonical(r),'Retained signing generation changed');check(!await tx.get(effectKey),'Signing effect already consumed');check(expiresAt>clock());await tx.put(effectKey,effect);});
  await current(r);check(expiresAt>clock(),'Signing authority expired after reservation');return {authorized:true,keyID:signerKeyID,objectDigest:sha256(payload),expiresAt};
 };
}
