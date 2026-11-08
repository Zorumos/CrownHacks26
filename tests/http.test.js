import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import handler from '../api/index.js';
import {sendEmail as gmailSendEmail} from '../lib/email.js';
process.env.ENCRYPTION_KEY=randomBytes(32).toString('hex');process.env.CODE_PEPPER=randomBytes(32).toString('hex');process.env.DEMO_MODE='true';delete process.env.DATABASE_URL;delete process.env.VERCEL;
test('HTTP integration: encrypted persistence, cookies, cross-origin rejection and session revocation',async()=>{
 const temp=await mkdtemp(join(tmpdir(),'cyber-one-'));const previous=process.cwd();process.chdir(temp);const server=http.createServer(handler);await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;let cookie='';
 async function call(action,body,extra={}){const r=await fetch(base+'/api/index?action='+action,{method:'POST',headers:{'Content-Type':'application/json',Cookie:cookie,...extra},body:JSON.stringify(body)});const set=r.headers.get('set-cookie');if(set)cookie=set.split(';')[0];return {status:r.status,data:await r.json(),set};}
 try {
  let r=await call('register',{username:'http_user',password:'a very long password',confirm:'a very long password',email:'test@example.com',sampleVerified:true,sampleImage:'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6f9sAAAAASUVORK5CYII='});assert.equal(r.status,200);assert.ok(r.set.includes('HttpOnly'));assert.ok(r.set.includes('SameSite=Strict'));assert.equal(r.data.codes.length,10);
  r=await call('me',{});assert.equal(r.data.stage,'disclosure');
  r=await call('codes-saved',{});assert.equal(r.status,409);await new Promise(resolve=>setTimeout(resolve,10050));r=await call('codes-saved',{});assert.equal(r.status,200);
  r=await call('consent',{privacy:true,terms:true,signature:'Integration Test'});assert.equal(r.data.user.username,'http_user');
  r=await call('connect',{location:'Auto'});assert.equal(r.data.user.lease.mode,'simulation');
  r=await call('profile',{name:'blocked',notify:true},{Origin:'https://untrusted.example'});assert.equal(r.status,403);
  const persisted=await readFile('.data/state.json','utf8');assert.ok(!persisted.includes('http_user'));assert.ok(!persisted.includes('a very long password'));
  r=await call('logout',{});assert.equal(r.data.ok,true);r=await call('me',{});assert.equal(r.status,401);
 }finally {await new Promise(r=>server.close(r));process.chdir(previous);await rm(temp,{recursive:true,force:true});}
});
test('HTTP email recovery verifies mailbox, resets credentials and returns fresh codes without leaking links',async()=>{
 const temp=await mkdtemp(join(tmpdir(),'cyber-email-')),previous=process.cwd();process.chdir(temp);let cookie='',messages=[];const fakeTransport=()=>({sendMail:async message=>{messages.push(message);return {accepted:[message.to],rejected:[]};},close(){}});const server=http.createServer((req,res)=>handler(req,res,{sendEmail:mail=>gmailSendEmail(mail,fakeTransport)}));await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;const originalFetch=globalThis.fetch;const env={APP_URL:process.env.APP_URL,GMAIL_APP_PASSWORD:process.env.GMAIL_APP_PASSWORD};
 process.env.APP_URL=base;process.env.GMAIL_APP_PASSWORD='abcdefghijklmnop';
 async function call(action,body){const r=await originalFetch(base+'/api/index?action='+action,{method:'POST',headers:{'Content-Type':'application/json',Cookie:cookie},body:JSON.stringify(body)});const set=r.headers.get('set-cookie');if(set)cookie=set.split(';')[0];return {status:r.status,data:await r.json()};}
 try{
  let r=await call('register',{username:'mail_user',email:'mail@example.com',password:'original email password',confirm:'original email password',sampleVerified:true,sampleImage:'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6f9sAAAAASUVORK5CYII='});assert.equal(r.status,200);assert.equal(r.data.emailSent,true);const firstCodes=r.data.codes;const verify=messages[0].text.match(/#verify-email=([A-Za-z0-9_-]+)/)[1];assert.ok(!JSON.stringify(r.data).includes(verify));assert.equal((await call('verify-email',{token:verify})).data.ok,true);
  r=await call('recovery-request',{email:'mail@example.com',purpose:'all'});assert.equal(r.status,200);const raw=messages[1].text.match(/#recover=([A-Za-z0-9_-]+)/)[1];assert.ok(!JSON.stringify(r.data).includes(raw));assert.equal((await call('recovery-info',{token:raw})).data.username,'mail_user');r=await call('recovery-complete',{token:raw,password:'replacement email password',confirm:'replacement email password'});assert.equal(r.data.codes.length,10);assert.notDeepEqual(r.data.codes,firstCodes);const replacement=r.data.codes;
  assert.equal((await call('recovery-info',{token:raw})).status,400);assert.equal((await call('login',{username:'mail_user',password:'original email password'})).status,401);assert.equal((await call('login',{username:'mail_user',password:'replacement email password'})).data.stage,'code');assert.equal((await call('code',{code:replacement[0]})).data.stage,'disclosure');assert.equal(messages.length,3);
 }finally{globalThis.fetch=originalFetch;for(const [key,value]of Object.entries(env)){if(value===undefined)delete process.env[key];else process.env[key]=value;}await new Promise(r=>server.close(r));process.chdir(previous);await rm(temp,{recursive:true,force:true});}
});
