import test from 'node:test';
import assert from 'node:assert/strict';
import {deployNative} from '../deployment/native.mjs';
const sha='a'.repeat(40),env={WORKERS_CI:'1',CI:'true',WORKERS_CI_BRANCH:'main',WORKERS_CI_COMMIT_SHA:sha,CLOUDFLARE_API_TOKEN:'synthetic'};
function fixture(){
  let uploaded=false,metadata,writes=0,head=sha,signed=true;const access='b'.repeat(64);
  const fetcher=async(url,options)=>{
    if(url.includes('/git/ref/'))return Response.json({object:{sha:head}});
    if(url.includes('/commits/'))return Response.json({sha,commit:{verification:{verified:signed}}});
    if(url.endsWith('/settings'))return Response.json({success:true,result:{bindings:[{name:'CREDENTIAL_WRAPPING_KEY',type:'secret_key'},{name:'ACCESS_AUD',type:'plain_text',text:access},...(uploaded?metadata.bindings:[])]}});
    if(url.endsWith('/deployments'))return Response.json({success:true,result:{deployments:[{id:'test-deployment',versions:[{version_id:'test-version'}]}]}});
    assert.equal(options.method,'PUT');assert(url.endsWith('/scripts/signer'));writes++;metadata=JSON.parse(await options.body.get('metadata').text());uploaded=true;return Response.json({success:true,result:{deployment_id:'test-upload'}});
  };
  return {fetcher,bundle:async()=>{return 'export default {fetch(){return new Response("disabled")}}';},get writes(){return writes;},get metadata(){return metadata;},unsigned:()=>{signed=false;},stale:()=>{head='c'.repeat(40);}};
}
test('native production deployment checks signed current main, preserves opaque custody and reads back artifact identity',async()=>{
  const f=fixture(),result=await deployNative({env,...f});assert.equal(result.worker,'signer');assert.equal(result.sourceSHA,sha);assert.match(result.artifactSHA256,/^[a-f0-9]{64}$/);assert.equal(f.writes,1);assert.deepEqual(f.metadata.keep_bindings,['secret_key']);assert.equal(f.metadata.observability.logs.invocation_logs,false);assert.equal(JSON.stringify(f.metadata).includes('synthetic'),false);assert.equal(f.metadata.containers,undefined);
});
test('unsigned source, superseded main, wrong branch and injected runtime credentials fail before mutation',async()=>{
  for(const type of ['unsigned','stale']){const f=fixture();f[type]();await assert.rejects(deployNative({env,...f}),/verified signed source/);assert.equal(f.writes,0);}
  for(const change of [{WORKERS_CI_BRANCH:'feature'},{SIGNER_SESSION:'synthetic'}]){const f=fixture();await assert.rejects(deployNative({env:{...env,...change},...f}));assert.equal(f.writes,0);}
});
