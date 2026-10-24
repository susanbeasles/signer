import {mkdtemp,readFile,writeFile,rm,statfs,chmod} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {pinExecutable,runBounded,startAgent} from './process.mjs';
import {parseSSHKeyReference} from '../src/service/op-reference.mjs';
export {pinExecutable,runBounded} from './process.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const fingerprint=value=>'SHA256:'+createHash('sha256').update(value).digest('base64').replace(/=+$/,'');
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.slice().sort().join();
const check=value=>{if(!value)throw Error('Installed Git signer unavailable');};
const paths={op:'/usr/local/bin/op',sshAgent:'/usr/bin/ssh-agent',sshAdd:'/usr/bin/ssh-add',sshKeygen:'/usr/bin/ssh-keygen'};
export function validateSignerConfig(config){
 check(exact(config,['schema','opRef','publicKey','keyID','toolchain','opOrigins'])&&config.schema==='signing-control-op-agent/v1');
 check(Array.isArray(config.opOrigins)&&config.opOrigins.length>=1&&config.opOrigins.length<=8&&new Set(config.opOrigins).size===config.opOrigins.length);
 for(const origin of config.opOrigins){check(typeof origin==='string'&&/^https:\/\/(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(origin));check(!['https://signing-control.internal','https://github.com'].includes(origin));}
 try{parseSSHKeyReference(config.opRef);}catch{check(false);}
 check(typeof config.publicKey==='string'&&/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/.test(config.publicKey));
 const encoded=config.publicKey.split(' ')[1],blob=Buffer.from(encoded,'base64');
 check(blob.toString('base64')===encoded&&blob.length===51&&blob.readUInt32BE(0)===11&&blob.subarray(4,15).toString()==='ssh-ed25519'&&blob.readUInt32BE(15)===32&&fingerprint(blob)===config.keyID);
 check(exact(config.toolchain,Object.keys(paths)));
 for(const [name,path]of Object.entries(paths)){const tool=config.toolchain[name];check(exact(tool,['path','sha256'])&&tool.path===path&&typeof tool.sha256==='string'&&/^[a-f0-9]{64}$/.test(tool.sha256));}
 return structuredClone(config);
}
// Same SSHSIG wire checks as the reviewed repoctl installed signer; namespace is
// fixed to git and the embedded key must match the independently pinned key.
function signatureKeyID(signature){
 check(typeof signature==='string'&&signature.length<=16384&&/^-----BEGIN SSH SIGNATURE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END SSH SIGNATURE-----\n?$/.test(signature));
 const encoded=signature.split('\n').slice(1,-(signature.endsWith('\n')?2:1)).join(''),raw=Buffer.from(encoded,'base64');
 check(raw.toString('base64')===encoded&&raw.length>=10&&raw.subarray(0,6).toString()==='SSHSIG'&&raw.readUInt32BE(6)===1);let offset=10;
 const field=()=>{check(offset+4<=raw.length);const length=raw.readUInt32BE(offset);offset+=4;check(length<=16384&&offset+length<=raw.length);const value=raw.subarray(offset,offset+length);offset+=length;return value;};
 const key=field();check(field().toString()==='git'&&field().length===0&&['sha256','sha512'].includes(field().toString()));field();check(offset===raw.length);return fingerprint(key);
}
export async function assertPrivateMemory({statfsImpl=statfs,readFileImpl=readFile}={}){
 check((await statfsImpl('/dev/shm')).type===0x01021994);
 const swaps=await readFileImpl('/proc/swaps','utf8'),limits=await readFileImpl('/proc/self/limits','utf8');
 check(swaps.trim().split('\n').length===1&&/^Max core file size\s+0\s/m.test(limits));
}
async function workspace(preflight=assertPrivateMemory){
 await preflight();
 const directory=await mkdtemp('/dev/shm/signing-control-');await chmod(directory,0o700);return directory;
}
export async function createOpGitSigner({config,serviceToken=null,authorize,deadline,clock=()=>Math.floor(Date.now()/1000),effects={}}){
 config=validateSignerConfig(config);check(typeof authorize==='function'&&Number.isSafeInteger(deadline)&&deadline>clock());
 const pin=effects.pin??pinExecutable,run=effects.run??runBounded,agentStart=effects.startAgent??startAgent,preflight=effects.preflight??assertPrivateMemory;
 const abort=new AbortController();let closed=false,busy=false;const operations=new Set();
 const live=proof=>{check(!closed&&!abort.signal.aborted&&deadline>clock());if(proof)check(proof.expiresAt>clock());};
 const timeout=proof=>{live(proof);return Math.max(1,Math.min(10000,(Math.min(deadline,proof?.expiresAt??deadline)-clock())*1000));};
 const terminate=()=>abort.abort();process.on('SIGTERM',terminate);process.on('SIGINT',terminate);
 const env=directory=>({PATH:'/usr/bin:/bin',HOME:directory,TMPDIR:directory,LANG:'C.UTF-8',LC_ALL:'C.UTF-8'});
 async function verifyGit({payload,signature}={}){
  let directory;
  try{
   live();check(typeof payload==='string'&&Buffer.byteLength(payload)<=24000&&signatureKeyID(signature)===config.keyID);
   const program=await pin(config.toolchain.sshKeygen);directory=await workspace(preflight);const file=join(directory,'signature');await writeFile(file,signature,{mode:0o600});live();
   const output=await run(program,['-Y','check-novalidate','-n','git','-s',file],{input:Buffer.from(payload),env:env(directory),limit:16384,timeoutMs:timeout(),signal:abort.signal});output.fill(0);live();return true;
  }catch{return false;}finally{if(directory)await rm(directory,{recursive:true,force:true});}
 }
 async function signing(input){
  let directory,agent,privateKey;let secretEnv;
  try{
   live();check(exact(input,['type','payload','authorization'])&&['commit','tag'].includes(input.type)&&typeof input.payload==='string'&&Buffer.byteLength(input.payload)<=24000&&!input.payload.includes('\0')&&input.authorization&&typeof input.authorization==='object');
   check(typeof serviceToken==='string'&&/^[\x21-\x7e]{1,8192}$/.test(serviceToken));
   const proof=await authorize(structuredClone(input));
   check(exact(proof,['authorized','keyID','objectDigest','expiresAt'])&&proof.authorized===true&&proof.keyID===config.keyID&&proof.objectDigest===hash(input.payload)&&Number.isSafeInteger(proof.expiresAt));live(proof);
   directory=await workspace(preflight);const childEnv=env(directory),socket=join(directory,'agent.sock');
   const agentProgram=await pin(config.toolchain.sshAgent);live(proof);agent=await agentStart(agentProgram,socket,{env:childEnv,timeoutMs:timeout(proof),signal:abort.signal});
   const opProgram=await pin(config.toolchain.op);live(proof);
   secretEnv={...childEnv,OP_SERVICE_ACCOUNT_TOKEN:serviceToken,OP_CONFIG_DIR:join(directory,'op'),OP_CACHE:'false',SSL_CERT_FILE:'/etc/cloudflare/certs/cloudflare-containers-ca.crt'};
   privateKey=await run(opProgram,['read',config.opRef,'--no-newline'],{env:secretEnv,limit:32768,timeoutMs:timeout(proof),signal:abort.signal});delete secretEnv.OP_SERVICE_ACCOUNT_TOKEN;
   check(Buffer.isBuffer(privateKey)&&privateKey.length>0&&privateKey.length<=16384&&privateKey.subarray(0,36).toString()==='-----BEGIN OPENSSH PRIVATE KEY-----\n');live(proof);
   const agentEnv={...childEnv,SSH_AUTH_SOCK:socket},addProgram=await pin(config.toolchain.sshAdd);live(proof);
   const added=await run(addProgram,['-t','30','-'],{input:privateKey,env:agentEnv,limit:8192,timeoutMs:timeout(proof),signal:abort.signal});added.fill(0);privateKey.fill(0);privateKey=null;
   const list=await run(addProgram,['-L'],{env:agentEnv,limit:8192,timeoutMs:timeout(proof),signal:abort.signal});
   try{const keys=list.toString('utf8').trim().split('\n');check(keys.length===1&&keys[0].split(' ').slice(0,2).join(' ')===config.publicKey);}finally{list.fill(0);}live(proof);
   const publicPath=join(directory,'signer.pub');await writeFile(publicPath,config.publicKey+'\n',{mode:0o600});const program=await pin(config.toolchain.sshKeygen);live(proof);
   const output=await run(program,['-Y','sign','-U','-n','git','-f',publicPath],{input:Buffer.from(input.payload),env:agentEnv,limit:16384,timeoutMs:timeout(proof),signal:abort.signal});
   const signature=output.toString('utf8');output.fill(0);check(await verifyGit({payload:input.payload,signature}));live(proof);return signature;
  }catch{throw Error('Installed Git signer unavailable');}
  finally{if(secretEnv)delete secretEnv.OP_SERVICE_ACCOUNT_TOKEN;privateKey?.fill(0);await agent?.close();if(directory)await rm(directory,{recursive:true,force:true});}
 }
 const track=async promise=>{operations.add(promise);try{return await promise;}finally{operations.delete(promise);}};
 return Object.freeze({keyID:config.keyID,verifyGit:input=>track(verifyGit(input)),async signGit(input){check(!busy);busy=true;try{return await track(signing(structuredClone(input)));}finally{busy=false;}},async close(){closed=true;serviceToken=null;abort.abort();await Promise.allSettled([...operations]);process.removeListener('SIGTERM',terminate);process.removeListener('SIGINT',terminate);}});
}

