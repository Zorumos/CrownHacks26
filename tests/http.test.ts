import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handle } from '../src/http.ts';
import { loadConfig } from '../src/config.ts';
test('health never claims VPN protection',async()=>{const response=await handle(new Request('http://127.0.0.1:3000/api/health'));assert.equal(response.status,200);assert.equal((await response.json()).deviceProtection,'not_verified');assert.equal(response.headers.get('cache-control'),'no-store');});
test('missing Redis credentials explicitly advertise browser-only preview',async()=>{const response=await handle(new Request('http://127.0.0.1:3000/api/config'));const data=await response.json();assert.equal(data.demoMode,'local_preview');assert.equal(data.nativeClientRequired,true);});
test('foreign-origin mutations are rejected before services initialize',async()=>{const response=await handle(new Request('http://127.0.0.1:3000/api/demo/rooms',{method:'POST',headers:{origin:'https://other.example','content-type':'application/json'},body:'{}'}));assert.equal(response.status,403);});
test('oversized and malformed JSON never echo secret input',async()=>{
  const large=await handle(new Request('http://127.0.0.1:3000/api/demo/rooms',{method:'POST',headers:{'content-type':'application/json'},body:'x'.repeat(17000)}));assert.equal(large.status,413);
  const invalid=await handle(new Request('http://127.0.0.1:3000/api/demo/rooms',{method:'POST',headers:{'content-type':'application/json'},body:'{"password":"SECRET"'}));assert.equal(invalid.status,422);assert.ok(!(await invalid.text()).includes('SECRET'));
});
test('production origin must use HTTPS',()=>{assert.throws(()=>loadConfig({NODE_ENV:'production',APP_ORIGIN:'http://127.0.0.1:3000'}),{code:'BAD_CONFIG'});});
