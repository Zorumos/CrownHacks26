import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { encrypt,decrypt,passwordHash,passwordValid,totp,validTotp } from '../src/crypto.ts';
import { validatePublicKey } from '../src/vpn/service.ts';
import { key } from './helpers.ts';

test('AES GCM round trip with authenticated context',()=>{const key=randomBytes(32);assert.equal(decrypt(encrypt('synthetic',key,'room:1:0'),key),'synthetic');});
test('AES GCM rejects modified ciphertext tag context and wrong key',()=>{const key=randomBytes(32),box=encrypt('synthetic',key,'room:1:0');const flip=(value:string)=>(parseInt(value.slice(0,2),16)^1).toString(16).padStart(2,'0')+value.slice(2);for(const edited of [{...box,ciphertext:flip(box.ciphertext)},{...box,tag:flip(box.tag)},{...box,aad:'different room'}])assert.throws(()=>decrypt(edited,key));assert.throws(()=>decrypt(box,randomBytes(32)));});
test('password hash uses independent random salts and validates safely',async()=>{const a=await passwordHash('a long password'),b=await passwordHash('a long password');assert.notEqual(a,b);assert.equal(await passwordValid('a long password',a),true);assert.equal(await passwordValid('wrong password',a),false);});
test('RFC6238 TOTP vector and replay rejection',()=>{const secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';assert.equal(totp(secret,1),'287082');assert.equal(validTotp(secret,'287082',-1,59000),1);assert.equal(validTotp(secret,'287082',1,59000),null);});
test('canonical public key validation rejects null key and shell text',()=>{assert.equal(validatePublicKey(key()).length,44);assert.throws(()=>validatePublicKey(Buffer.alloc(32).toString('base64')));assert.throws(()=>validatePublicKey('sh; arbitrary command'));});
