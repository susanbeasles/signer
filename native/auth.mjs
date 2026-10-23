// Authentication authority is limited to verified issuer signatures and hardcoded audience/identity.
const dec=new TextDecoder();
const unb64=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-x.length%4)%4)),c=>c.charCodeAt(0));
const AUTH_ISSUERS=Object.freeze({
 github:Object.freeze({issuer:'https://token.actions.githubusercontent.com',jwks:'https://token.actions.githubusercontent.com/.well-known/jwks',aud:'susanbeasles:signing-control'}),
 access:Object.freeze({issuer:'https://vespoli.cloudflareaccess.com',jwks:'https://vespoli.cloudflareaccess.com/cdn-cgi/access/certs'})
});
const no=()=>{throw Error('unauthorized');};
function parse(token) {
 if(typeof token!=='string'||token.length>12288||token.length<90)no();
 const parts=token.split('.');if(parts.length!==3||parts.some(x=>!/^[A-Za-z0-9_-]+$/.test(x)))no();
 try {const header=JSON.parse(dec.decode(unb64(parts[0]))),payload=JSON.parse(dec.decode(unb64(parts[1])));if(header?.alg!=='RS256'||typeof header?.kid!=='string'||header.kid.length>256||!payload||typeof payload!=='object')no();return {parts,header,payload};}catch{no();}
}
async function verified(token,source,{fetcher=fetch,now=Math.floor(Date.now()/1000)}={}) {
 const {parts,header,payload}=parse(token);
 if(payload.iss!==source.issuer||payload.aud!==source.aud||!Number.isInteger(payload.exp)||payload.exp<=now||payload.exp>now+86400||!Number.isInteger(payload.iat)||payload.iat>now+60||payload.iat<now-86400||(payload.nbf!==undefined&&(!Number.isInteger(payload.nbf)||payload.nbf>now+60)))no();
 const res=await fetcher(source.jwks,{redirect:'manual',cache:'no-store',signal:AbortSignal.timeout(9000),headers:{accept:'application/json'}});
 if(!res.ok||res.status>=300||Number(res.headers.get('content-length')||0)>65536)no();
 const raw=await res.text();if(raw.length>65536)no();
 let keys;try{keys=JSON.parse(raw).keys}catch{no()}
 const selected=Array.isArray(keys)?keys.filter(k=>k.kid===header.kid&&k.kty==='RSA'&&(!k.use||k.use==='sig')&&(!k.alg||k.alg==='RS256')):[];
 if(selected.length!==1)no();
 let ok=false;try{const key=await crypto.subtle.importKey('jwk',selected[0],{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);ok=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unb64(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1]));}catch{no()}
 if(!ok)no();return payload;
}
export async function authorize(token,repository,{accessAud,ownerEmail,allowedActors=[],now,fetcher}={}) {
 if(typeof repository!=='string'||!/^susanbeasles\/[A-Za-z0-9_.-]{1,100}$/.test(repository))no();
 const parsed=parse(token);let p;
 if(parsed.payload.iss===AUTH_ISSUERS.github.issuer){
  p=await verified(token,AUTH_ISSUERS.github,{now,fetcher});
  if(p.repository_owner_id!=='215839550'||p.repository!==repository||!['push','workflow_dispatch','repository_dispatch'].includes(p.event_name)||!Array.isArray(allowedActors)||!allowedActors.includes(String(p.actor_id))||!/^refs\/heads\/[A-Za-z0-9_./-]+$/.test(p.ref||'')||p.ref.includes('..'))no();
  return {kind:'github-oidc',subject:String(p.actor_id),repository};
 }
 if(parsed.payload.iss===AUTH_ISSUERS.access.issuer){
  if(typeof accessAud!=='string'||accessAud.length!==64||!/^[a-f0-9]{64}$/.test(accessAud)||typeof ownerEmail!=='string')no();
  p=await verified(token,{...AUTH_ISSUERS.access,aud:accessAud},{now,fetcher});
  if(p.email?.toLowerCase()!==ownerEmail.toLowerCase()||!p.sub)no();
  return {kind:'cloudflare-access',subject:p.sub,repository};
 }
 no();
}
