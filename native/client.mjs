#!/usr/bin/env node
import {pathToFileURL} from 'node:url';
import {open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {basename} from 'node:path';
import {ORIGIN, MAX_COMMIT, commitBytes, digest, bounded} from './protocol.mjs';
import {verifyCommit} from './ssh.mjs';
export async function request(path, body, token, fetcher=fetch) {
  if(!['/v1/key','/v1/grants','/v1/sign'].includes(path))throw Error('Invalid signer operation');
  const response=await fetcher(ORIGIN+path,{method:'POST',redirect:'error',signal:AbortSignal.timeout(20000),headers:{'content-type':'application/json',authorization:'Bearer '+token},body:JSON.stringify(body)});
  const value=JSON.parse(new TextDecoder().decode(await bounded(response.body,MAX_COMMIT*2)));
  if(!response.ok)throw Error('Signer rejected the operation ('+response.status+')');return value;
}
export async function remoteSign(commit, {session, repository, fetcher=fetch}) {
  if(typeof session!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(session)||!/^susanbeasles\/[A-Za-z0-9_.-]{1,100}$/.test(repository||''))throw Error('Missing authorized signer session or repository');
  const data=commitBytes(commit),hash=await digest(data);
  const grant=await request('/v1/grants',{repository,commit},session,fetcher);
  if(grant.digest!==hash||typeof grant.grant!=='string')throw Error('Signer grant does not match commit');
  // Never automatically retry a one-use signing request, including a lost response.
  const result=await request('/v1/sign',{repository,commit,grant:grant.grant},session,fetcher);
  if(result.receipt?.repository!==repository||result.receipt?.sessionID!==await digest(session)||result.receipt?.action!=='sign-commit'||result.receipt?.digest!==hash||!await verifyCommit(result.publicKey,result.signature,data))throw Error('Signer signature verification failed');
  return result.signature;
}
export async function main(args,env=process.env,stdin=process.stdin) {
  if(args[0]!=='-Y'||args[1]!=='sign'||args[2]!=='-n'||args[3]!=='git'||args[4]!=='-f'||!args[5])throw Error('Only Git SSH commit signing is supported');
  const tail=args.slice(6);if(tail[0]==='-U')tail.shift();
  if(tail.length>1 || (tail.length===1 && !/^\.git_signing_buffer_tmp[A-Za-z0-9]+$/.test(basename(tail[0]))))throw Error('Invalid Git signing input');
  // Git supplies a public-key hint via -f. The service may rotate it after eviction;
  // the returned registered public identity is verified with the exact commit bytes.
  const chunks=[];let size=0;
  if(tail.length){
    const file=await open(tail[0],constants.O_RDONLY|constants.O_NOFOLLOW);
    try{
      const stat=await file.stat();if(!stat.isFile()||stat.size>MAX_COMMIT)throw Error('Invalid Git signing input');
      for(;;){const buffer=Buffer.alloc(8192),{bytesRead}=await file.read(buffer);if(!bytesRead)break;size+=bytesRead;if(size>MAX_COMMIT)throw Error('Commit exceeds signer input limit');chunks.push(buffer.subarray(0,bytesRead));}
    }finally{await file.close();}
  }else for await(const chunk of stdin){size+=chunk.length;if(size>MAX_COMMIT)throw Error('Commit exceeds signer input limit');chunks.push(chunk);}
  const bytes=Buffer.concat(chunks),commit=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const signature=await remoteSign(commit,{session:env.SIGNER_SESSION,repository:env.SIGNER_REPOSITORY});
  if(tail.length){const file=await open(tail[0]+'.sig',constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);try{await file.writeFile(signature);}finally{await file.close();}return '';}
  return signature;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  main(process.argv.slice(2)).then(signature=>process.stdout.write(signature)).catch(()=>{process.stderr.write('signer: authenticated commit signing unavailable; no unsigned commit created\n');process.exitCode=1;});
}
