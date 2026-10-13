import {readFile,mkdir,chown,chmod} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {pinExecutable} from './op-git-signer.mjs';
import {IMAGE_CONFIG,validateImageConfiguration} from './handoff.mjs';
const check=value=>{if(!value)throw Error('Reviewed image inputs required');};
export function validateImageInputs({baseImage,nodeSHA256,setprivSHA256,config}){
 check(typeof baseImage==='string'&&/^[a-z0-9.-]+(?::[0-9]+)?\/[A-Za-z0-9_./-]+@sha256:[a-f0-9]{64}$/.test(baseImage));
 check(/^[a-f0-9]{64}$/.test(nodeSHA256??'')&&/^[a-f0-9]{64}$/.test(setprivSHA256??''));
 return validateImageConfiguration(config);
}
async function main(){
 const bytes=await readFile(IMAGE_CONFIG);check(bytes.length<=262144);
 const config=validateImageInputs({baseImage:process.env.SIGNING_BASE_IMAGE,nodeSHA256:process.env.SIGNING_NODE_SHA256,setprivSHA256:process.env.SIGNING_SETPRIV_SHA256,config:JSON.parse(bytes)});
 for(const tool of [...Object.values(config.runtime.toolchain),...config.services.map(service=>({path:service.git.program,sha256:service.git.sha256})),{path:'/usr/bin/node',sha256:process.env.SIGNING_NODE_SHA256},{path:'/usr/bin/setpriv',sha256:process.env.SIGNING_SETPRIV_SHA256}])await pinExecutable(tool);
 await chmod(IMAGE_CONFIG,0o444);await mkdir('/run/signing-control',{mode:0o700});await chown('/run/signing-control',10001,10001);await chmod('/run/signing-control',0o700);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){main().catch(()=>{process.exitCode=1;});}
