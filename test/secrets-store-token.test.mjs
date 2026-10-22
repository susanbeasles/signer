import test from 'node:test';
import assert from 'node:assert/strict';
import {readSignerServiceToken} from '../cloudflare/service-token.mjs';
test('native Secrets Store get retrieves dedicated signer token with no legacy fallback',async()=>{
 let reads=0;const env={SIGNER_SERVICE_ACCOUNT_TOKEN:{get:async()=>{reads++;return 'SYNTHETIC-SIGNER-ONLY';}},OP_SERVICE_ACCOUNT_TOKEN:'SYNTHETIC-LEGACY'};
 assert.equal(await readSignerServiceToken(env),'SYNTHETIC-SIGNER-ONLY');assert.equal(reads,1);
 await assert.rejects(readSignerServiceToken({OP_SERVICE_ACCOUNT_TOKEN:'SYNTHETIC-LEGACY'}),/signer-service-token-unavailable/);
});
test('empty, multiline, oversized or unavailable tokens fail closed with no material in errors',async()=>{
 for(const value of [undefined,'','private\nvalue','x'.repeat(8193)])await assert.rejects(readSignerServiceToken({SIGNER_SERVICE_ACCOUNT_TOKEN:{get:async()=>value}}),/signer-service-token-unavailable/);
 await assert.rejects(readSignerServiceToken({SIGNER_SERVICE_ACCOUNT_TOKEN:{get:async()=>{throw Error('PRIVATE-CONTENT');}}}),e=>e.message==='signer-service-token-unavailable');
});
