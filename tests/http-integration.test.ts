import { after,before,test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { database } from './helpers.ts';
import { SQLiteDatabase } from '../src/database.ts';
import { readFile } from 'node:fs/promises';
import { totp } from '../src/crypto.ts';
let path='';let handle:typeof import('../src/http.ts').handle;let token='';
before(async()=>{
  path=await mkdtemp(join(tmpdir(),'co-next-'));
  process.env.APP_ORIGIN='http://127.0.0.1:3000';process.env.APP_MASTER_KEY=randomBytes(32).toString('hex');process.env.LOCAL_DB_PATH=join(path,'accounts.db');
  const db=await SQLiteDatabase.open(process.env.LOCAL_DB_PATH);
  const sql=await readFile(new URL('../migrations/001_initial.sql',import.meta.url),'utf8');
  await db.transaction(async tx=>{for(const statement of sql.split(';').map(s=>s.trim()).filter(Boolean))await tx.query(statement);});await db.close();
  ({handle}=await import('../src/http.ts'));
});
after(async()=>{const {getAccounts}=await import('../src/runtime.ts');const service=await getAccounts();await service.dummy;await service.db.close();await rm(path,{recursive:true,force:true});});
async function request(path:string,method='GET',body?:unknown,credential=token){return handle(new Request('http://127.0.0.1:3000/api/'+path,{method,headers:{...(credential?{authorization:'Bearer '+credential}:{}),...(body===undefined?{}:{'content-type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body)}));}
test('HTTP register enrollment and device API flow',async()=>{
  const d=await(await request('disclosure')).json();
  const r=await request('auth/register','POST',{username:'http_user',password:'a long test password',name:'Test User',signature:'Test User',agreed:true,disclosureVersion:d.version,documentHash:d.documentHash});assert.equal(r.status,200);token=(await r.json()).accessToken;
  assert.equal((await request('devices')).status,403);
  const setup=await(await request('auth/mfa/setup')).json();const code=totp(setup.secret,Math.floor(Date.now()/30000));
  const confirmed=await request('auth/mfa/confirm','POST',{code});assert.equal(confirmed.status,200);token=(await confirmed.json()).accessToken;
  const added=await request('devices','POST',{label:'HTTP test',publicKey:randomBytes(32).toString('base64')});assert.equal(added.status,200);
  const device=(await added.json()).id;const connection=await request('connections','POST',{deviceId:device});assert.equal(connection.status,503);assert.equal((await connection.json()).error.code,'NO_USABLE_SERVER');
});
test('HTTP unknown fields and wrong types rejected without secret echoes',async()=>{
  const r=await request('auth/login','POST',{username:'http_user',password:'NEVER_ECHO',extra:'unsupported'});assert.equal(r.status,422);assert.ok(!(await r.text()).includes('NEVER_ECHO'));
  assert.equal((await request('connections','POST',{deviceId:'0'.repeat(32),adblock:'true'})).status,422);
});
