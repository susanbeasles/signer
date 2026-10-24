// RFC 4253 and OpenSSH PROTOCOL.sshsig. This module handles only public values.
const text = new TextEncoder();
const u8 = x => typeof x === 'string' ? text.encode(x) : new Uint8Array(x);
export const concat = (...items) => { const parts=items.map(u8);const output=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let offset=0;for(const part of parts){output.set(part,offset);offset+=part.length;}return output; };
export const uint32 = n => {if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)throw Error('invalid length');return new Uint8Array([n>>>24,(n>>>16)&255,(n>>>8)&255,n&255]);};
export const sshString = value => {const bytes=u8(value);return concat(uint32(bytes.length),bytes);};
export const base64 = bytes => {let s='';for(const b of u8(bytes))s+=String.fromCharCode(b);return btoa(s);};
export const rawFromBase64 = b64 => Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
export function sshPublicBlob(raw) {const b=u8(raw);if(b.length!==32)throw Error('invalid Ed25519 public key');return concat(sshString('ssh-ed25519'),sshString(b));}
export function sshPublicKey(raw) {return `ssh-ed25519 ${base64(sshPublicBlob(raw))}`;}
export function sshsigPayload(digest) {const b=u8(digest);if(b.length!==64)throw Error('invalid SHA-512 digest');return concat('SSHSIG',sshString('git'),sshString(''),sshString('sha512'),sshString(b));}
export function sshsigArmor(publicKeyRaw,signature) {
  const key=u8(publicKeyRaw),sig=u8(signature);if(key.length!==32||sig.length!==64)throw Error('invalid signing parameters');
  const pub=concat(sshString('ssh-ed25519'),sshString(key));
  const sigBlob=concat(sshString('ssh-ed25519'),sshString(sig));
  const data=concat('SSHSIG',uint32(1),sshString(pub),sshString('git'),sshString(''),sshString('sha512'),sshString(sigBlob));
  const b64=base64(data);return `-----BEGIN SSH SIGNATURE-----\n${b64.match(/.{1,70}/g).join('\n')}\n-----END SSH SIGNATURE-----\n`;
}
export async function signCommit(privateKey,publicKeyRaw,commitBytes,subtle=crypto.subtle) {
 const bytes=u8(commitBytes),digest=await subtle.digest('SHA-512',bytes);
 const signature=await subtle.sign('Ed25519',privateKey,sshsigPayload(digest));
 return sshsigArmor(publicKeyRaw,signature);
}

export async function verifyCommit(publicKey, armor, commitBytes, subtle=crypto.subtle) {
 if(typeof publicKey!=='string'||typeof armor!=='string'||armor.length>2048)return false;
 try {
  const fields=publicKey.split(' ');if(fields.length!==2||fields[0]!=='ssh-ed25519')return false;
  const publicBlob=rawFromBase64(fields[1]);if(publicBlob.length!==51)return false;
  const raw=publicBlob.slice(-32);if(base64(sshPublicBlob(raw))!==fields[1])return false;
  const encoded=armor.replace('-----BEGIN SSH SIGNATURE-----\n','').replace('-----END SSH SIGNATURE-----\n','').replace(/\n/g,'');
  const bytes=rawFromBase64(encoded),signature=bytes.slice(-64);
  if(sshsigArmor(raw,signature)!==armor)return false;
  const key=await subtle.importKey('raw',raw,'Ed25519',false,['verify']);
  return await subtle.verify('Ed25519',key,signature,sshsigPayload(await subtle.digest('SHA-512',u8(commitBytes))));
 }catch{return false;}
}

