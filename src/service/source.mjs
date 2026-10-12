import {validHeadRef} from '../vendor/repoctl/source-signing/integration-ref.mjs';
import {readFile,mkdir,realpath,lstat,statfs,open,rm} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,dirname,isAbsolute,resolve} from 'node:path';
import {pinnedExecutable,runFixed} from '../vendor/repoctl/source-signing/process.mjs';
import {createLocalGitSource} from '../vendor/repoctl/source-signing/git.mjs';
import {sha256,gitObjectID} from '../vendor/repoctl/source-signing/core.mjs';
import {canonical} from '../vendor/repoctl/ledger.mjs';
import {runGitProcess} from './git-process.mjs';
const HASH=/^[a-f0-9]{64}$/,SHA=/^[a-f0-9]{40}$/;
const check=(ok,message='Fixed normal Git source unavailable')=>{if(!ok)throw Error(message);};
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.slice().sort().join();
const baseEnv={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0',GIT_CONFIG_COUNT:'0'};
const safeArgs=['-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','credential.helper=','-c','http.followRedirects=false','-c','protocol.allow=never','-c','protocol.https.allow=always'];
export function validateGitConfig(config){check(exact(config,['program','sha256','directory','maxObjects','maxBytes','authenticated'])&&config.program==='/usr/bin/git'&&HASH.test(config.sha256)&&config.directory==='/run/signing-control/git'&&Number.isSafeInteger(config.maxObjects)&&config.maxObjects>0&&config.maxObjects<=100000&&Number.isSafeInteger(config.maxBytes)&&config.maxBytes>0&&config.maxBytes<=8388608&&typeof config.authenticated==='boolean');return structuredClone(config);}
async function trustedDirectory(directory){check(isAbsolute(directory)&&await realpath(directory)===directory,'Local source custody directory is missing or indirect');let path=directory;while(path!=='/'){const info=await lstat(path);check(info.isDirectory()&&!info.isSymbolicLink()&&!(info.mode&0o022),'Local source custody permissions are unsafe');path=dirname(path);}return directory;}

// The Cloudflare image has no such durable mount by default. A missing or
// ephemeral filesystem is a denial, never a durable-retention success receipt.
export async function createDurableArchive({directory='/var/lib/signing-control/history',maxBytes=12*1024*1024,custody}={}){
 check(exact(custody,['schema','mountPoint','device','mountSource','filesystem'])&&custody.schema==='signing-control-history-custody/v1'&&custody.mountPoint===directory&&directory==='/var/lib/signing-control/history'&&/^\d+:\d+$/.test(custody.device)&&typeof custody.mountSource==='string'&&/^\/[A-Za-z0-9_./-]+$/.test(custody.mountSource)&&['ext4','xfs','btrfs'].includes(custody.filesystem),'Independently accepted durable custody identity required');
 await trustedDirectory(directory);const filesystem=await statfs(directory);
 check([0xef53,0x58465342,0x9123683e].includes(filesystem.type),'A durable operator-owned history filesystem is required');
 const mounts=(await readFile('/proc/self/mountinfo','utf8')).trim().split('\n').map(line=>{const [before,after]=line.split(' - ');return {fields:before?.split(' '),kind:after?.split(' ')};});
 check(mounts.some(({fields,kind})=>fields?.[2]===custody.device&&fields[3]==='/'&&fields[4]===directory&&kind?.[0]===custody.filesystem&&kind[1]===custody.mountSource),'Approved durable mount identity is absent');
 const location=reference=>{check(/^local-history:[a-f0-9]{64}$/.test(reference),'Invalid local history reference');return join(directory,reference.slice(14)+'.json');};
 async function read(reference){await trustedDirectory(directory);const file=await open(location(reference),constants.O_RDONLY|constants.O_NOFOLLOW);try{const info=await file.stat();check(info.isFile()&&info.size<=maxBytes&&!(info.mode&0o022));const value=JSON.parse(await file.readFile('utf8'));check(sha256(canonical(value))===reference.slice(14),'Retained history digest differs');return value;}finally{await file.close();}}
 return Object.freeze({read,async retain({digest,closure}){check(HASH.test(digest)&&sha256(canonical(closure))===digest);const bytes=canonical(closure);check(Buffer.byteLength(bytes)<=maxBytes);await trustedDirectory(directory);const reference='local-history:'+digest;let file;try{file=await open(location(reference),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);await file.writeFile(bytes);await file.sync();}catch(error){if(error.code!=='EEXIST')throw error;}finally{await file?.close();}const dir=await open(directory,constants.O_RDONLY|constants.O_DIRECTORY);try{await dir.sync();}finally{await dir.close();}check(sha256(canonical(await read(reference)))===digest);return {digest,reference};}});
}

export function createLocalTreeProof({directory='/var/lib/signing-control/git',program='/usr/bin/git',programSHA256,maxObjects=100000,maxBytes=8388608,requireCustody=true}){
 check(isAbsolute(directory)&&program==='/usr/bin/git'&&HASH.test(programSHA256)&&Number.isSafeInteger(maxObjects)&&maxObjects>0&&maxObjects<=100000&&Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=8388608);
 return Object.freeze({async verify({repositoryID,repository,baseSHA,treeSHA}){
  check(Number.isSafeInteger(repositoryID)&&repositoryID>0&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository)&&SHA.test(baseSHA)&&SHA.test(treeSHA));if(requireCustody)await trustedDirectory(directory);
  const git=async(args,limit=maxBytes)=>{const exe=await pinnedExecutable(program,programSHA256);return runFixed(exe,[...safeArgs,...args],{cwd:directory,env:baseEnv,limit,timeoutMs:30000});};
  check((await git(['rev-parse','--is-shallow-repository'],100)).toString().trim()==='false'&&(await git(['rev-parse','--show-object-format'],100)).toString().trim()==='sha1');
  for(const name of ['info/grafts','objects/info/alternates','objects/info/http-alternates']){const path=(await git(['rev-parse','--git-path',name],4096)).toString().trim();let present=false;try{await lstat(resolve(directory,path));present=true;}catch(error){if(error.code!=='ENOENT')throw error;}check(!present,'Grafts or alternate object stores are not eligible');}
  const configuration=(await git(['config','--includes','--list'],65536)).toString();check(!/^extensions\.partialclone=|^remote\..*\.promisor=|^include(?:if)?\./mi.test(configuration));
  check((await git(['cat-file','-t',baseSHA],100)).toString().trim()==='commit'&&(await git(['cat-file','-t',treeSHA],100)).toString().trim()==='tree');
  const ids=[...new Set((await git(['rev-list','--objects','--no-object-names',baseSHA,treeSHA])).toString().trim().split('\n'))].sort();check(ids.length>0&&ids.length<=maxObjects&&ids.every(x=>SHA.test(x)));
  const objects=[];let size=0;for(const objectSHA of ids){const type=(await git(['cat-file','-t',objectSHA],100)).toString().trim();check(['commit','tree','blob','tag'].includes(type));const bytes=await git(['cat-file',type,objectSHA]);size+=bytes.length;check(size<=maxBytes&&gitObjectID(type,bytes)===objectSHA);objects.push({sha:objectSHA,type,size:bytes.length,sha256:sha256(bytes)});}
  // Reject gitlinks: a submodule object is not a locally verified complete tree.
  const entries=(await git(['ls-tree','-r','-z',treeSHA])).toString().split('\0').filter(Boolean);check(entries.every(e=>/^(100644|100755|120000) blob [a-f0-9]{40}\t/.test(e)));
  return {repositoryID,repository,baseSHA,treeSHA,closureDigest:sha256(canonical(objects)),complete:true};
 }});
}

export async function acquireSource({service,policy,capabilities,deadline,needSnapshot=true,clock=()=>Math.floor(Date.now()/1000)}){
 const config=validateGitConfig(service.git);check(policy?.authority==='workflow_depot'&&policy.repositoryID===service.repositoryID&&policy.repository===service.repository&&policy.targetRef==='refs/heads/main'&&validHeadRef(policy.sourceRef)&&!policy.sourceRef.startsWith('refs/heads/int/')&&policy.sourceRef!==policy.targetRef);
 // Fail before network acquisition if the independently provisioned durable
 // custody directory is absent; never substitute the disposable container FS.
 const archive=needSnapshot?await createDurableArchive({custody:policy.historyCustody}):null;
 const remote=`https://github.com/${service.repository}.git`;check(/^https:\/\/github\.com\/[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+\.git$/.test(remote));
 let credential=null;const live=()=>check(clock()<deadline&&(!credential||credential.expiresAt>clock()),'Source acquisition authority expired');
 if(config.authenticated){credential=await capabilities.source.credential({repositoryID:service.repositoryID,repository:service.repository});check(exact(credential,['token','repositoryID','expiresAt','permissions'])&&credential.repositoryID===service.repositoryID&&typeof credential.token==='string'&&/^[\x21-\x7e]{1,8192}$/.test(credential.token)&&exact(credential.permissions,['contents','metadata'])&&credential.permissions.contents==='read'&&credential.permissions.metadata==='read'&&Number.isSafeInteger(credential.expiresAt)&&credential.expiresAt<=clock()+900);live();}
 const env={...baseEnv,GIT_SSL_CAINFO:'/etc/cloudflare/certs/cloudflare-containers-ca.crt'};if(credential){env.GIT_CONFIG_COUNT='1';env.GIT_CONFIG_KEY_0='http.https://github.com/.extraheader';env.GIT_CONFIG_VALUE_0='Authorization: Basic '+Buffer.from('x-access-token:'+credential.token).toString('base64');}
 const git=async(args,limit=config.maxBytes)=>{const exe=await pinnedExecutable(config.program,config.sha256);live();return runGitProcess(exe,[...safeArgs,...args],{cwd:config.directory,env,limit,timeoutMs:Math.max(1,Math.min(120000,(deadline-clock())*1000))});};
 await mkdir(dirname(config.directory),{recursive:true,mode:0o700});await mkdir(config.directory,{mode:0o700});
 try{
  await git(['init','--bare','--quiet'],4096);if(needSnapshot)await git(['fetch','--no-tags','--no-write-fetch-head',remote,`${policy.sourceRef}:${policy.sourceRef}`,`${policy.targetRef}:${policy.targetRef}`],65536);
  const local=needSnapshot?await createLocalGitSource({repositoryPath:config.directory,gitProgram:config.program,gitProgramSHA256:config.sha256,archive,inventory:capabilities.inventory,maxObjects:config.maxObjects,maxBytes:config.maxBytes}):null;
  const remoteRef=async ref=>{check([policy.sourceRef,policy.targetRef].includes(ref));const text=(await git(['ls-remote','--refs','--exit-code',remote,ref],1024)).toString();const match=/^([a-f0-9]{40})\t([^\r\n]+)\n$/.exec(text);check(match&&match[2]===ref);return match[1];};
  return {git:{snapshot:config=>{check(local,'Durable history custody unavailable');return local.snapshot(config);},main:config=>remoteRef(config.targetRef),source:config=>remoteRef(config.sourceRef)},async close(){credential=null;delete env.GIT_CONFIG_VALUE_0;await rm(config.directory,{recursive:true,force:true});}};
 }catch(error){credential=null;delete env.GIT_CONFIG_VALUE_0;await rm(config.directory,{recursive:true,force:true});throw error;}
}
