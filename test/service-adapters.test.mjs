import test from 'node:test';
import assert from 'node:assert/strict';
import {createRemoteStorage,createCapabilities} from '../src/service/adapters.mjs';

test('durable adapter commits one exact CAS and never retries a conflict',async()=>{
 let revision=0,calls=0;const rows=new Map();
 const transport={async call(path,input){if(path==='/v1/state/snapshot')return {revision,entries:[...rows].map(([key,value])=>({key,value}))};assert.equal(path,'/v1/state/transaction');calls++;assert.equal(input.expectedRevision,revision);for(const {key,value} of input.writes)rows.set(key,value);return {revision:++revision};}};
 const storage=createRemoteStorage(transport);await storage.transaction(async tx=>{assert.equal(await tx.get('k'),undefined);await tx.put('k',{state:'reserved'});});assert.equal(calls,1);assert.deepEqual(await storage.get('k'),{state:'reserved'});
 transport.call=async path=>{if(path==='/v1/state/snapshot')return {revision,entries:[]};calls++;throw Error('CAS conflict');};
 await assert.rejects(storage.put('k',{}),/CAS conflict/);assert.equal(calls,2);
});
test('fixed capability adapters strip history objects before classification and expose no generic route',async()=>{
 const calls=[],caps=createCapabilities({call:async(path,body)=>{calls.push({path,body});return {};}});
 await caps.inventory.classify({repositoryID:7,treeSHA:'a'.repeat(40),entries:[{mode:'100644',sha:'b'.repeat(40),path:'index.js'}],objects:[{payload:'SOURCE MUST NOT LEAVE'}]});
 assert.equal(calls[0].path,'/v1/capability/inventory/classify');assert.equal(JSON.stringify(calls).includes('SOURCE MUST NOT LEAVE'),false);assert.equal(caps.history,undefined);assert.equal(caps.sign,undefined);
 for(const type of ['tree','blob','commit','tag'])assert.throws(()=>caps.publisher.putObject(type,'arbitrary payload'));assert.equal(calls.length,1);
});
