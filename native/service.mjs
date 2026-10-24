import {GitHub} from './github.mjs';
import {commitBytes, digest, exact, fail, random, repository} from './protocol.mjs';
import {base64, signCommit, sshPublicBlob, sshPublicKey} from './ssh.mjs';
export const POLICY = Object.freeze({repositories:['susanbeasles/signer'],repositoryIDs:{'susanbeasles/signer':'1416201242'},actors:['215839550'],workflows:[]});
const SESSION_MS=15*60*1000, KEY_RETENTION_MS=24*60*60*1000;
export class SignerService {
  constructor(storage, wrappingKey, {github, policy=POLICY, now=Date.now} = {}) {
    this.storage=storage;this.github=github || new GitHub(storage,wrappingKey);this.policy=policy;this.now=now;this.identities=new Map();
  }
  async rate(scope, maximum=30) {
    const bucket=Math.floor(this.now()/60000), key='rate:'+await digest(scope)+':'+bucket;
    await this.storage.transaction(async tx=>{const count=await tx.get(key)||0;if(count>=maximum)fail('rate-limited',429);await tx.put(key,count+1);});
  }
  async bootstrap(input, clientHash) {
    exact(input,['repository']);repository(input.repository,this.policy.repositories);
    await this.rate('bootstrap:global',30);
    await this.rate('bootstrap:'+clientHash,5);
    const secret=random(), id=random();
    await this.storage.put('pending:'+id,{repository:input.repository,secretHash:await digest(secret),expires:this.now()+600000});
    return {id,secret,repository:input.repository,expires:this.now()+600000};
  }
  async approve(input, owner) {
    exact(input,['id']);if(typeof input.id!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.id))fail('invalid-request',400);
    await this.storage.transaction(async tx=>{const key='pending:'+input.id,pending=await tx.get(key);if(!pending||pending.expires<=this.now()||pending.approved)fail('pending-denied');await tx.put(key,{...pending,approved:true,owner:owner.subject});});
    return {approved:true};
  }
  async redeem(input) {
    exact(input,['id','secret']);if(typeof input.id!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.id)||typeof input.secret!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.secret))fail('invalid-request',400);
    const secretHash=await digest(input.secret), session=random(), sessionHash=await digest(session);
    const record=await this.storage.transaction(async tx=>{
      const key='pending:'+input.id,pending=await tx.get(key);
      if(!pending||pending.secretHash!==secretHash||pending.expires<=this.now())fail('pending-denied');
      if(!pending.approved)fail('owner-approval-pending',409);
      if(pending.used)fail('pending-consumed',409);
      const record={repository:pending.repository,repositoryID:this.policy.repositoryIDs[pending.repository],subject:'owner-grant:'+pending.owner,expires:this.now()+SESSION_MS,revoked:false};
      await tx.put('session:'+sessionHash,record);await tx.put(key,{...pending,used:true});return record;
    });
    return {session,expires:record.expires,repository:record.repository};
  }
  async workloadSession(identity) {
    repository(identity.repository,this.policy.repositories);
    if(identity.repositoryID!==this.policy.repositoryIDs[identity.repository])fail('repository-denied');
    await this.rate('workload:'+identity.subject,10);
    const session=random(),hash=await digest(session),expires=Math.min(identity.expires,this.now()+SESSION_MS);
    await this.storage.transaction(async tx=>{const replay='oidc:'+await digest(identity.replayID);if(await tx.get(replay))fail('identity-replayed',409);await tx.put(replay,{expires:identity.expires});await tx.put('session:'+hash,{...identity,expires,revoked:false});});
    return {session,expires,repository:identity.repository};
  }
  async session(token) {
    if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token))fail('unauthorized',401);
    const hash=await digest(token),record=await this.storage.get('session:'+hash);
    if(!record||record.revoked||record.expires<=this.now())fail('unauthorized',401);
    repository(record.repository,this.policy.repositories);return {...record,hash};
  }
  async revoke(input) {
    exact(input,['sessionID']);if(typeof input.sessionID!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.sessionID))fail('invalid-request',400);
    await this.storage.transaction(async tx=>{const key='session:'+input.sessionID,record=await tx.get(key);if(!record)fail('session-not-found',404);await tx.put(key,{...record,revoked:true});});
    this.identities.delete(input.sessionID);return {revoked:true};
  }
  async identity(session) {
    if(!this.identities.has(session.hash)){
      const pending=(async()=>{
        const pair=await crypto.subtle.generateKey('Ed25519',false,['sign','verify']);
        if(pair.privateKey.extractable!==false)fail('key-generation-denied',503);
        const raw=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey));
        const id=random(),publicKey=sshPublicKey(raw),fingerprint='SHA256:'+base64(new Uint8Array(await crypto.subtle.digest('SHA-256',sshPublicBlob(raw)))).replace(/=+$/,'');
        const record={id,publicKey,fingerprint,title:'signer:'+id,sessionID:session.hash,expires:session.expires,cleanupAfter:session.expires+KEY_RETENTION_MS};
        // Only public registration metadata is durable, including before external creation.
        await this.storage.put('key:'+id,record);
        const githubID=await this.github.registerKey(record);
        await this.storage.put('key:'+id,{...record,githubID});
        return {privateKey:pair.privateKey,raw,record:{...record,githubID}};
      })();
      this.identities.set(session.hash,pending);
      pending.catch(()=>{this.identities.delete(session.hash);});
    }
    return this.identities.get(session.hash);
  }
  async key(token) {
    const session=await this.session(token);await this.rate('key:'+session.hash,10);
    const {record}=await this.identity(session);return {publicKey:record.publicKey,fingerprint:record.fingerprint,expires:record.expires,sessionID:session.hash};
  }
  async grant(input, token) {
    exact(input,['repository','commit']);const session=await this.session(token);
    if(input.repository!==session.repository)fail('repository-denied');
    await this.rate('grant:'+session.hash,30);
    const bytes=commitBytes(input.commit);
    if(!input.commit.split('\n\n')[0].split('\n').some(line=>line.startsWith('committer ') && line.includes('<215839550+susanbeasles@users.noreply.github.com>')))fail('committer-denied');
    const grant=random(),key='grant:'+await digest(grant),record={repository:session.repository,repositoryID:session.repositoryID,subject:session.subject,sessionID:session.hash,action:'sign-commit',digest:await digest(bytes),expires:Math.min(session.expires,this.now()+60000),used:false};
    await this.storage.put(key,record);return {grant,expires:record.expires,digest:record.digest};
  }
  async sign(input, token) {
    exact(input,['repository','commit','grant']);const session=await this.session(token);
    if(input.repository!==session.repository)fail('repository-denied');
    if(typeof input.grant!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.grant))fail('grant-denied');
    const bytes=commitBytes(input.commit),hash=await digest(bytes);
    const identity=await this.identity(session);
    const key='grant:'+await digest(input.grant);
    await this.storage.transaction(async tx=>{
      const grant=await tx.get(key),current=await tx.get('session:'+session.hash);
      if(!current||current.revoked||current.expires<=this.now())fail('unauthorized',401);
      if(!grant||grant.used||grant.expires<=this.now()||grant.sessionID!==session.hash||grant.subject!==session.subject||grant.action!=='sign-commit'||grant.digest!==hash||grant.repository!==input.repository||grant.repositoryID!==session.repositoryID)fail('grant-denied',409);
      await tx.put(key,{...grant,used:true,usedAt:this.now()});
    });
    const signature=await signCommit(identity.privateKey,identity.raw,bytes);
    const receipt={id:random(),digest:hash,repository:session.repository,repositoryID:session.repositoryID,subject:session.subject,sessionID:session.hash,action:'sign-commit',fingerprint:identity.record.fingerprint,issuedAt:this.now()};
    await this.storage.put('receipt:'+receipt.id,receipt);
    return {signature,publicKey:identity.record.publicKey,receipt};
  }
  async cleanup() {
    for(const [hash,promise] of this.identities){const value=await promise.catch(()=>null);if(!value||value.record.expires<=this.now())this.identities.delete(hash);}
    const keys=await this.storage.list({prefix:'key:',limit:1000});
    for(const [name,record] of keys){
      if(record.cleanupAfter>this.now())continue;
      if(!record.githubID){const match=(await this.github.keys()).filter(k=>k.key===record.publicKey&&k.title===record.title);if(match.length>1)fail('key-inventory-conflict',503);if(match.length===1)record.githubID=match[0].id;}
      if(record.githubID)await this.github.removeKey(record);
      await this.storage.delete(name);
    }
    for(const prefix of ['pending:','session:','grant:','oidc:','rate:','oauth:','manifest:','receipt:']){
      const cursorKey='cleanup-cursor:'+prefix,cursor=await this.storage.get(cursorKey);
      const entries=await this.storage.list({prefix,limit:1000,...(cursor?{startAfter:cursor}:{})});
      for(const [name,value]of entries){const expiry=value.expires??(value.issuedAt?value.issuedAt+30*86400000:prefix==='rate:'?Number(name.split(':').at(-1))*60000+120000:Infinity);if(expiry<this.now()-60000)await this.storage.delete(name);}
      if(entries.size===1000)await this.storage.put(cursorKey,[...entries.keys()].at(-1));else await this.storage.delete(cursorKey);
    }
  }
}
