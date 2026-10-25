import {DurableObject} from 'cloudflare:workers';
import {ORIGIN, bounded, digest, exact, fail, jsonBody, output, random} from './protocol.mjs';
import {ownerAccess, workload} from './identity.mjs';
import {manifest} from './github.mjs';
import {SignerService, POLICY} from './service.mjs';
const cookieName='__Host-signer';
const securityHeaders={'cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; form-action 'self' https://github.com; base-uri 'none'; frame-ancestors 'none'"};
const escape=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function html(value,headers={}){return new Response('<!doctype html><meta charset="utf-8"><title>signer</title>'+value,{headers:{...securityHeaders,'content-type':'text/html;charset=utf-8',...headers}});}
function cookie(value,name=cookieName+'-'+value){return `${name}=${value}; Secure; HttpOnly; Path=/; SameSite=Lax; Max-Age=${value?600:0}`;}
function callback(request,url){
  const deny=reason=>{throw Object.assign(new Error('callback-denied'),{status:403,reason});};
  const state=url.searchParams.get('state'),code=url.searchParams.get('code');
  if(url.searchParams.getAll('state').length!==1||!state||!/^[A-Za-z0-9_-]{43}$/.test(state))deny('state');
  if(url.searchParams.getAll('code').length!==1||!code||!/^[A-Za-z0-9_-]{10,200}$/.test(code))deny('code');
  if([...url.searchParams.keys()].some(k=>!['state','code'].includes(k)))deny('parameters');
  const cookies=(request.headers.get('cookie')||'').split(';').map(x=>x.trim());
  const names=[cookieName+'-'+state,cookieName];
  const matching=cookies.filter(value=>names.some(name=>value===name+'='+state));
  if(matching.length!==1)deny('cookie');
  return {state,code,cookieKey:matching[0].slice(0,matching[0].indexOf('='))};
}
const bearer=request=>{const value=request.headers.get('authorization')||'';if(!/^Bearer [A-Za-z0-9._-]{43,12288}$/.test(value))fail('unauthorized',401);return value.slice(7);};
export class Signer extends DurableObject {
  constructor(ctx,env){
    super(ctx,env);
    // Native issuer allowlists are configured by the owner, never by request metadata.
    let policy=POLICY;
    if(env.WORKLOAD_POLICY){const supplied=JSON.parse(env.WORKLOAD_POLICY);exact(supplied,['repositories','repositoryIDs','actors','workflows']);if(!Array.isArray(supplied.repositories)||!Array.isArray(supplied.actors)||!Array.isArray(supplied.workflows)||Object.getPrototypeOf(supplied.repositoryIDs)!==Object.prototype)fail('invalid-policy',503);policy=supplied;}
    this.service=new SignerService(ctx.storage,env.CREDENTIAL_WRAPPING_KEY,{policy});
  }
  async owner(request){return ownerAccess(request.headers.get('cf-access-jwt-assertion'),this.env.ACCESS_AUD);}
  async handle(request){
    const url=new URL(request.url),path=url.pathname;
    try{
      if(url.origin!==ORIGIN)fail('not-found',404);
      if(!path.startsWith('/github/')&&url.search)fail('not-found',404);
      if(!await this.ctx.storage.getAlarm())await this.ctx.storage.setAlarm(Date.now()+60000);
      if(request.method==='GET'&&path==='/health')return output({service:'signer',sourceSHA:this.env.SOURCE_SHA||null,artifactSHA256:this.env.ARTIFACT_SHA256||null,ready:!!await this.ctx.storage.get('authorization')});
      if(request.method==='GET'&&path==='/setup'){
        await this.owner(request);
        const app=await this.ctx.storage.get('app'),authorized=await this.ctx.storage.get('authorization');
        return html(`<h1>signer</h1><p>${authorized?'GitHub owner authorization completed.':app?'GitHub App registered. Owner authorization required.':'GitHub App registration required.'}</p><p><a href="${app?'/owner/authorize':'/owner/register'}">${app?'Authorize GitHub account':'Register GitHub App'}</a></p>`);
      }
      if(request.method==='GET'&&path==='/owner/register'){
        await this.owner(request);await this.service.rate('owner-register',3);
        if(!this.env.CREDENTIAL_WRAPPING_KEY)fail('custody-unavailable',503);
        if(await this.ctx.storage.get('app'))fail('app-already-registered',409);
        const state=random();await this.ctx.storage.put('manifest:'+await digest(state),{expires:Date.now()+600000});
        return html(`<h1>Register signer</h1><form action="https://github.com/settings/apps/new?state=${state}" method="post"><input type="hidden" name="manifest" value="${escape(JSON.stringify(manifest()))}"><button>Continue to GitHub</button></form>`,{'set-cookie':cookie(state)});
      }
      if(request.method==='GET'&&path==='/github/manifest'){
        const {state,code,cookieKey}=callback(request,url);await this.service.github.consumeState('manifest',state);
        await this.service.github.register(code);
        return html('<p>GitHub App registered.</p><a href="/owner/authorize">Authorize GitHub account</a>',{'set-cookie':cookie('',cookieKey)});
      }
      if(request.method==='GET'&&path==='/owner/authorize'){
        await this.owner(request);await this.service.rate('owner-authorize',5);
        const next=await this.service.github.oauthStart();return new Response(null,{status:302,headers:{...securityHeaders,location:next.url,'set-cookie':cookie(next.state)}});
      }
      if(request.method==='GET'&&path==='/github/callback'){
        const {code,state,cookieKey}=callback(request,url);await this.service.github.oauthComplete(code,state);
        return html('<h1>signer authorized</h1><p>GitHub signing-key administration is enabled.</p>',{'set-cookie':cookie('',cookieKey)});
      }
      if(path.startsWith('/owner/')){
        const owner=await this.owner(request);
        if(request.method==='GET'&&path==='/owner/status')return output({app:await this.ctx.storage.get('app'),authorization:await this.ctx.storage.get('authorization')});
        if(request.method==='GET'&&path==='/owner/pending'){
          const pending=await this.ctx.storage.list({prefix:'pending:',limit:100});
          return html('<h1>Pending agent sessions</h1><p>Approve only the request ID shown by your remote agent. Each session permits commit signing for 15 minutes.</p>'+[...pending].filter(([,v])=>v.expires>Date.now()&&!v.used&&!v.approved).map(([id,v])=>`<section><p>Repository: ${escape(v.repository)}<br>Request: ${escape(id.slice(8))}</p><form method="post" action="/owner/approve"><input type="hidden" name="id" value="${escape(id.slice(8))}"><button>Approve session</button></form></section>`).join(''));
        }
        if(request.method!=='POST'||request.headers.get('origin')!==ORIGIN)fail('owner-action-denied');
        await this.service.rate('owner-action',30);
        let input;
        if(request.headers.get('content-type')?.startsWith('application/x-www-form-urlencoded')){const form=new URLSearchParams(new TextDecoder().decode(await bounded(request.body,4096)));if([...form.keys()].length!==new Set(form.keys()).size)fail('invalid-request',400);input=Object.fromEntries(form);}else input=await jsonBody(request,4096);
        if(path==='/owner/approve')return output(await this.service.approve(input,owner));
        if(path==='/owner/revoke')return output(await this.service.revoke(input));
        fail('not-found',404);
      }
      if(request.method!=='POST')fail('not-found',404);
      const input=await jsonBody(request);
      if(path==='/v1/bootstrap')return output(await this.service.bootstrap(input,await digest(request.headers.get('cf-connecting-ip')||'unknown')));
      if(path==='/v1/redeem')return output(await this.service.redeem(input));
      if(path==='/v1/session'){
        exact(input,[]);const identity=await workload(bearer(request),this.service.policy);return output(await this.service.workloadSession(identity));
      }
      const token=bearer(request);
      if(path==='/v1/key'){exact(input,[]);return output(await this.service.key(token));}
      if(path==='/v1/grants')return output(await this.service.grant(input,token));
      if(path==='/v1/sign'){
        const result=await this.service.sign(input,token);
        console.log(JSON.stringify({event:'commit-signed',receiptID:result.receipt.id,repository:result.receipt.repository,digest:result.receipt.digest,fingerprint:result.receipt.fingerprint}));
        return output(result);
      }
      fail('not-found',404);
    }catch(error){return output({error:error.status?error.message:'unavailable',...(error.message==='callback-denied'?{reason:error.reason}:{})},error.status||503);}
  }
  async alarm(){try{await this.service.cleanup();}finally{await this.ctx.storage.setAlarm(Date.now()+60000);}}
  fetch(){return output({error:'not-found'},404);}
}
export default {
  async fetch(request,env){
    if(new URL(request.url).origin!==ORIGIN)return output({error:'not-found'},404);
    if(!env.SIGNER)return output({error:'unavailable'},503);
    try{return await env.SIGNER.getByName('account:215839550').handle(request);}catch{return output({error:'unavailable'},503);}
  }
};
