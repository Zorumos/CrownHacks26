import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TestStore } from './helpers.ts';
import { Rooms,ROOM_TTL,HEARTBEAT_TTL,SESSION_TTL } from '../src/demo/rooms.ts';
import { LocalPreview } from '../src/demo/local-preview.ts';
import { decrypt } from '../src/crypto.ts';
import { RedisStore,CAS_LUA,SharedLimiter } from '../src/store.ts';

async function fixture(){const store=new TestStore();const rooms=new Rooms(store,'https://example.test',()=>store.now);const created=await rooms.create();const joined=await rooms.join(created.state.roomCode,1);return {store,rooms,created,joined,code:created.state.roomCode,presenter:created.presenterToken,judge:joined.sessionToken};}

test('public state never returns a key, hash of credential or protection claim',async()=>{
  const f=await fixture(),snapshot=JSON.stringify(f.created.state);
  const raw=JSON.parse((await f.store.read(f.rooms.roomKey(f.code)))!);
  assert.equal(f.created.state.protected,false);assert.equal(f.created.state.simulation,true);
  assert.ok(!snapshot.includes(raw.key));assert.ok(!snapshot.includes(raw.presenterHash));assert.ok(!snapshot.includes(f.presenter));
});
test('join links use configured public origin and generation',async()=>{const f=await fixture();assert.equal(f.created.joinUrl,`https://example.test/join/${f.code}?generation=1`);});
test('connection retries count the same judge exactly once',async()=>{const f=await fixture();await f.rooms.connection(f.code,f.judge,1,true);await f.rooms.connection(f.code,f.judge,1,true);assert.equal((await f.rooms.snapshot(f.code,f.presenter,1)).activeConnections,1);});
test('different anonymous sessions count separately',async()=>{const f=await fixture(),second=await f.rooms.join(f.code,1);await Promise.all([f.rooms.connection(f.code,f.judge,1,true),f.rooms.connection(f.code,second.sessionToken,1,true)]);assert.equal((await f.rooms.snapshot(f.code,f.presenter,1)).activeConnections,2);});
test('disconnect retries do not underflow count',async()=>{const f=await fixture();await f.rooms.connection(f.code,f.judge,1,false);await f.rooms.connection(f.code,f.judge,1,false);assert.equal((await f.rooms.snapshot(f.code,f.presenter,1)).activeConnections,0);});
test('heartbeat expiry excludes abandoned connections',async()=>{const f=await fixture();await f.rooms.connection(f.code,f.judge,1,true);f.store.now+=HEARTBEAT_TTL+1;assert.equal((await f.rooms.snapshot(f.code,f.presenter,1)).activeConnections,0);});
test('late heartbeat cannot revive an expired connection lease',async()=>{const f=await fixture();await f.rooms.connection(f.code,f.judge,1,true);f.store.now+=HEARTBEAT_TTL+1;assert.equal((await f.rooms.heartbeat(f.code,f.judge,1)).activeConnections,0);});
test('active heartbeat extends contact within absolute room lifetime',async()=>{const f=await fixture();await f.rooms.connection(f.code,f.judge,1,true);f.store.now+=10000;await f.rooms.heartbeat(f.code,f.judge,1);f.store.now+=10000;assert.equal((await f.rooms.snapshot(f.code,f.presenter,1)).activeConnections,1);});
test('expired judge credential is rejected',async()=>{const f=await fixture();f.store.now+=SESSION_TTL+1;await assert.rejects(f.rooms.snapshot(f.code,f.judge,1),{code:'SESSION_EXPIRED'});});
test('expired room is unavailable',async()=>{const f=await fixture();f.store.now+=ROOM_TTL+1;await assert.rejects(f.rooms.snapshot(f.code,f.presenter,1),{code:'ROOM_NOT_FOUND'});});
test('rotation uses fresh keys and ciphertext for identical plaintext',async()=>{
  const f=await fixture();const first=JSON.parse((await f.store.read(f.rooms.roomKey(f.code)))!);f.store.now+=3000;
  const second=await f.rooms.snapshot(f.code,f.presenter,1),raw=JSON.parse((await f.store.read(f.rooms.roomKey(f.code)))!);
  assert.notEqual(first.key,raw.key);assert.notEqual(first.envelope.ciphertext,raw.envelope.ciphertext);assert.equal(first.payloadHash,second.rotation.payloadHash);
  assert.equal(decrypt(first.envelope,Buffer.from(first.key,'hex')),decrypt(raw.envelope,Buffer.from(raw.key,'hex')));
});
test('parallel polls rotate an epoch only once',async()=>{const f=await fixture();f.store.now+=3000;const results=await Promise.all(Array.from({length:6},()=>f.rooms.snapshot(f.code,f.presenter,1)));assert.equal(new Set(results.map(r=>r.rotation.envelope!.ciphertext)).size,1);});
test('panic clears key and count and freezes ciphertext',async()=>{
  const f=await fixture();await f.rooms.connection(f.code,f.judge,1,true);const before=await f.rooms.snapshot(f.code,f.presenter,1);
  const result=await f.rooms.panic(f.code,f.judge,1,true);f.store.now+=9000;const later=await f.rooms.snapshot(f.code,f.presenter,1);
  assert.equal(result.activeConnections,0);assert.equal(result.rotation.keyPresent,false);assert.equal(later.rotation.envelope!.ciphertext,before.rotation.envelope!.ciphertext);
  assert.equal(JSON.parse((await f.store.read(f.rooms.roomKey(f.code)))!).key,null);
});
test('panic requires explicit confirmation',async()=>{const f=await fixture();await assert.rejects(f.rooms.panic(f.code,f.judge,1,false),{code:'CONFIRM_REQUIRED'});});
test('panic is idempotent',async()=>{const f=await fixture();const first=await f.rooms.panic(f.code,f.judge,1,true);f.store.now+=1;const second=await f.rooms.panic(f.code,f.judge,1,true);assert.equal(first.panickedAt,second.panickedAt);});
test('panic cannot be reversed by racing connect heartbeat or rotation',async()=>{
  const f=await fixture();await f.rooms.connection(f.code,f.judge,1,true);f.store.now+=3000;
  await Promise.allSettled([f.rooms.snapshot(f.code,f.presenter,1),f.rooms.connection(f.code,f.judge,1,true),f.rooms.heartbeat(f.code,f.judge,1),f.rooms.panic(f.code,f.judge,1,true)]);
  const state=await f.rooms.snapshot(f.code,f.presenter,1);assert.equal(state.panic,true);assert.equal(state.rotation.keyPresent,false);assert.equal(state.activeConnections,0);
  await assert.rejects(f.rooms.connection(f.code,f.judge,1,true),{code:'PANIC_ACTIVE'});
});
test('judges cannot reset or decrypt the presenter proof',async()=>{const f=await fixture();await assert.rejects(f.rooms.reset(f.code,f.judge,1),{code:'PRESENTER_REQUIRED'});await assert.rejects(f.rooms.proof(f.code,f.judge,1),{code:'PRESENTER_REQUIRED'});});
test('presenter proof returns synthetic plaintext only before panic',async()=>{const f=await fixture();assert.equal((await f.rooms.proof(f.code,f.presenter,1)).payload.kind,'synthetic-session-metadata');await f.rooms.panic(f.code,f.judge,1,true);await assert.rejects(f.rooms.proof(f.code,f.presenter,1),{code:'KEY_REMOVED'});});
test('reset invalidates old tokens and generation',async()=>{const f=await fixture();const reset=await f.rooms.reset(f.code,f.presenter,1);assert.equal(reset.state.generation,2);await assert.rejects(f.rooms.connection(f.code,f.judge,1,true),{code:'GENERATION_CHANGED'});await assert.rejects(f.rooms.join(f.code,1),{code:'GENERATION_CHANGED'});await assert.rejects(f.rooms.snapshot(f.code,f.presenter,2));assert.equal((await f.rooms.snapshot(f.code,reset.presenterToken,2)).activeConnections,0);});
test('old reset cannot clobber newer state',async()=>{const f=await fixture();const outcomes=await Promise.allSettled([f.rooms.reset(f.code,f.presenter,1),f.rooms.reset(f.code,f.presenter,1)]);assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);});
test('unknown credential cannot observe room data',async()=>{const f=await fixture();await assert.rejects(f.rooms.snapshot(f.code,'not-a-valid-judge-token',1),{code:'SESSION_EXPIRED'});});
test('configured storage failure never creates an isolated fallback',async()=>{const f=await fixture();f.store.fail=true;await assert.rejects(f.rooms.snapshot(f.code,f.presenter,1));});
test('malformed shared state and resurrected panic keys are rejected',async()=>{
  const f=await fixture(),key=f.rooms.roomKey(f.code),original=JSON.parse((await f.store.read(key))!);
  for(const changed of [{...original,epoch:'not-a-number'},{...original,panic:true,key:original.key},{...original,key:[original.key]}]){
    f.store.values.set(key,{value:JSON.stringify(changed),expires:f.store.now+ROOM_TTL});
    await assert.rejects(f.rooms.snapshot(f.code,f.presenter,1),{code:'STATE_INVALID'});
  }
});
test('room state from a different identity is rejected',async()=>{const f=await fixture(),key=f.rooms.roomKey(f.code),room=JSON.parse((await f.store.read(key))!);room.id='f'.repeat(32);f.store.values.set(key,{value:JSON.stringify(room),expires:f.store.now+ROOM_TTL});await assert.rejects(f.rooms.snapshot(f.code,f.presenter,1),{code:'STATE_INVALID'});});
test('bounded CAS conflicts return a retryable error',async()=>{const f=await fixture();f.store.conflicts=100;await assert.rejects(f.rooms.snapshot(f.code,f.presenter,1),{code:'ROOM_BUSY'});});
test('Redis adapter uses atomic compare and set and preserves outage errors',async()=>{
  let script='';const store=new RedisStore({eval:async(s:string)=>{script=s;return 1;},get:async()=>{throw new Error('outage');}});
  assert.equal(await store.compareAndSet('k','old','new',30),true);assert.equal(script,CAS_LUA);await assert.rejects(store.read('k'),{code:'SHARED_STORAGE_UNAVAILABLE'});
});
test('shared rate limit rejects extra attempts',async()=>{const f=await fixture(),limiter=new SharedLimiter(f.store,()=>f.store.now);await limiter.check('test',1);await assert.rejects(limiter.check('test',1),{code:'RATE_LIMIT'});});
test('browser preview encrypts and panic is local',async()=>{let now=1000;const a=new LocalPreview(()=>now),b=new LocalPreview(()=>now);await a.refresh();await b.refresh();await a.connection(true);a.panic();now+=3000;assert.equal((await a.refresh()).rotation.keyPresent,false);assert.equal((await b.refresh()).panic,false);assert.equal(b.snapshot().activeConnections,0);});
