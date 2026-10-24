import {OWNER, OWNER_ID, ORIGIN, encode, b64url, bounded, digest, fail, random} from './protocol.mjs';
import {seal, open} from './sealed.mjs';
const VERSION = '2026-03-10';
export function manifest() {
  return {name:'signer',url:ORIGIN,public:false,description:'Remote Git commit signing',hook_attributes:{url:ORIGIN+'/github/events',active:false},redirect_url:ORIGIN+'/github/manifest',callback_urls:[ORIGIN+'/github/callback'],default_permissions:{git_signing_ssh_public_keys:'write'},default_events:[],request_oauth_on_install:false};
}
export class GitHub {
  constructor(storage, wrappingKey, fetcher = fetch) { this.storage=storage; this.key=wrappingKey; this.fetcher=fetcher; this.refreshing=null; }
  async secret(name) { const envelope=await this.storage.get('sealed:'+name); return envelope ? open(this.key,name,envelope) : null; }
  async save(name, value) { await this.storage.put('sealed:'+name,await seal(this.key,name,value)); }
  async request(path, {method='GET',token,body,oauth=false} = {}) {
    if (!((oauth && path==='/login/oauth/access_token') || (!oauth && (/^\/app-manifests\/[A-Za-z0-9_-]{10,200}\/conversions$/.test(path) || /^\/user(?:\/ssh_signing_keys(?:\/[0-9]+)?(?:\?per_page=100&page=[0-9]+)?)?$/.test(path) || /^\/repos\/susanbeasles\/[A-Za-z0-9_.-]+$/.test(path))))) fail('provider-path-denied');
    const res=await this.fetcher((oauth?'https://github.com':'https://api.github.com')+path,{method,redirect:'error',signal:AbortSignal.timeout(15000),headers:{accept:'application/json','user-agent':'signer','x-github-api-version':VERSION,...(token?{authorization:'Bearer '+token}:{}),...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
    const raw=await bounded(res.body,262144);
    if (!res.ok) throw Object.assign(new Error('provider-request-failed'),{status:503,providerStatus:res.status});
    if (res.status===204) return null;
    const value=JSON.parse(new TextDecoder().decode(raw)); if(value.error) fail('provider-authorization-failed',503);
    return value;
  }
  async register(code) {
    if (await this.storage.get('app')) fail('app-already-registered',409);
    await this.storage.transaction(async tx=>{if(await tx.get('app-registration-in-flight'))fail('registration-recovery-required',409);await tx.put('app-registration-in-flight',{started:Date.now()});});
    const app=await this.request('/app-manifests/'+code+'/conversions',{method:'POST'});
    if (String(app.owner?.id)!==OWNER_ID || app.owner?.login!==OWNER || !Number.isSafeInteger(app.id) || typeof app.client_id!=='string' || typeof app.client_secret!=='string' || typeof app.pem!=='string' || app.permissions?.git_signing_ssh_public_keys!=='write') fail('app-owner-or-permissions-denied');
    const metadata={id:app.id,clientID:app.client_id,slug:app.slug,owner:OWNER,permissions:app.permissions};
    const envelope=await seal(this.key,'app',{clientSecret:app.client_secret,pem:app.pem,webhookSecret:app.webhook_secret});
    await this.storage.transaction(async tx=>{await tx.put('sealed:app',envelope);await tx.put('app',metadata);await tx.delete('app-registration-in-flight');});return metadata;
  }
  async oauthStart() {
    const app=await this.storage.get('app'); if(!app) fail('app-not-registered',409);
    const verifier=random(); const state=random(); const challenge=await digest(verifier);
    await this.storage.put('oauth:'+await digest(state),{verifier:await seal(this.key,'oauth:'+await digest(state),verifier),expires:Date.now()+600000});
    const query=new URLSearchParams({client_id:app.clientID,redirect_uri:ORIGIN+'/github/callback',state,code_challenge:challenge,code_challenge_method:'S256',login:OWNER,allow_signup:'false',scope:'offline_access'});
    return {state,url:'https://github.com/login/oauth/authorize?'+query};
  }
  async consumeState(kind, state) {
    if (typeof state!=='string' || !/^[A-Za-z0-9_-]{43}$/.test(state)) fail('state-denied');
    const key=kind+':'+await digest(state);
    return this.storage.transaction(async tx=>{const record=await tx.get(key); if(!record || record.expires<=Date.now() || record.used) fail('state-denied'); await tx.put(key,{...record,used:true});return record;});
  }
  async oauthComplete(code, state) {
    const record=await this.consumeState('oauth',state);const app=await this.storage.get('app'),secret=await this.secret('app');
    const verifier=await open(this.key,'oauth:'+await digest(state),record.verifier);
    const tokens=await this.request('/login/oauth/access_token',{oauth:true,method:'POST',body:{client_id:app.clientID,client_secret:secret.clientSecret,code,code_verifier:verifier,redirect_uri:ORIGIN+'/github/callback'}});
    const owner=await this.request('/user',{token:tokens.access_token});
    if(String(owner.id)!==OWNER_ID || owner.login!==OWNER) fail('owner-denied');
    await this.installTokens(tokens);
    await this.request('/user/ssh_signing_keys?per_page=100&page=1',{token:tokens.access_token});
    await this.storage.put('authorization',{owner:OWNER,id:OWNER_ID,authorizedAt:Date.now(),refreshable:true});
    return {owner:OWNER,authorized:true};
  }
  async installTokens(tokens) {
    if(typeof tokens.access_token!=='string' || typeof tokens.refresh_token!=='string' || !Number.isInteger(tokens.expires_in) || tokens.expires_in<60 || !Number.isInteger(tokens.refresh_token_expires_in) || tokens.refresh_token_expires_in<60) fail('refreshable-token-required',503);
    await this.save('tokens',{access:tokens.access_token,refresh:tokens.refresh_token,expires:Date.now()+tokens.expires_in*1000,refreshExpires:Date.now()+tokens.refresh_token_expires_in*1000});
    await this.storage.delete('refresh-in-flight');
  }
  async token() {
    if (this.refreshing) return this.refreshing;
    this.refreshing=this.refresh();
    try {return await this.refreshing;} finally {this.refreshing=null;}
  }
  async refresh() {
    const tokens=await this.secret('tokens');if(!tokens) fail('owner-authorization-required',503);
    if(tokens.expires>Date.now()+60000) return tokens.access;
    // A lost response may have consumed the refresh token. Never replay it blindly.
    if(tokens.refreshExpires<=Date.now() || await this.storage.get('refresh-in-flight')) fail('owner-reauthorization-required',503);
    await this.storage.put('refresh-in-flight',{started:Date.now()});
    const app=await this.storage.get('app'),secret=await this.secret('app');
    const next=await this.request('/login/oauth/access_token',{oauth:true,method:'POST',body:{client_id:app.clientID,client_secret:secret.clientSecret,grant_type:'refresh_token',refresh_token:tokens.refresh}});
    await this.installTokens(next);return next.access_token;
  }
  async keys() {
    const token=await this.token();const keys=[];
    for(let page=1;page<=10;page++){const next=await this.request('/user/ssh_signing_keys?per_page=100&page='+page,{token});if(!Array.isArray(next))fail('provider-response-invalid',503);keys.push(...next);if(next.length<100)return keys;}
    fail('key-inventory-limit',503);
  }
  async registerKey(record) {
    const existing=(await this.keys()).filter(k=>k.key===record.publicKey && k.title===record.title);
    if(existing.length>1)fail('key-inventory-conflict',503);
    if(existing.length===1)return existing[0].id;
    const key=await this.request('/user/ssh_signing_keys',{method:'POST',token:await this.token(),body:{key:record.publicKey,title:record.title}});
    if(!Number.isSafeInteger(key.id) || key.key!==record.publicKey)fail('provider-response-invalid',503);return key.id;
  }
  async removeKey(record) {
    if(!Number.isSafeInteger(record.githubID) || !record.title.startsWith('signer:'))fail('key-ownership-denied');
    const matches=(await this.keys()).filter(k=>k.id===record.githubID);
    if(!matches.length)return;
    if(matches.length!==1 || matches[0].key!==record.publicKey || matches[0].title!==record.title)fail('key-ownership-denied');
    await this.request('/user/ssh_signing_keys/'+record.githubID,{method:'DELETE',token:await this.token()});
  }
}
