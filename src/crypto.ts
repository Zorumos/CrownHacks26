import { createCipheriv,createDecipheriv,createHash,createHmac,randomBytes,scrypt,timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { assert } from './errors.ts';

export const token = () => randomBytes(32).toString('base64url');
export const id = () => randomBytes(16).toString('hex');
export const hash = (input: string) => createHash('sha256').update(input).digest('hex');
export const mac = (key: string, input: string) => createHmac('sha256',key).update(input).digest('hex');
export function equal(a: string,b: string): boolean {
  const x=Buffer.from(a), y=Buffer.from(b);
  return x.length===y.length && timingSafeEqual(x,y);
}
export interface Envelope { nonce: string; ciphertext: string; tag: string; aad: string }
export function encrypt(value: string,key: Buffer,aad: string): Envelope {
  const nonce=randomBytes(12);
  const cipher=createCipheriv('aes-256-gcm',key,nonce);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
  return {nonce:nonce.toString('hex'),ciphertext:ciphertext.toString('hex'),tag:cipher.getAuthTag().toString('hex'),aad};
}
export function decrypt(envelope: Envelope,key: Buffer): string {
  assert(/^[a-f0-9]{24}$/.test(envelope.nonce) && /^[a-f0-9]{32}$/.test(envelope.tag),422,'BAD_ENVELOPE','Invalid encryption envelope.');
  const cipher=createDecipheriv('aes-256-gcm',key,Buffer.from(envelope.nonce,'hex'));
  cipher.setAAD(Buffer.from(envelope.aad)); cipher.setAuthTag(Buffer.from(envelope.tag,'hex'));
  return Buffer.concat([cipher.update(Buffer.from(envelope.ciphertext,'hex')),cipher.final()]).toString('utf8');
}

// Bound memory used by concurrent password derivations; never run slow sync scrypt in a route.
let working=0;
const waiters: Array<()=>void>=[];
async function derive(password: string,salt: Buffer): Promise<Buffer> {
  if(working>=2) await new Promise<void>(resolve=>waiters.push(resolve));
  else working++;
  try {
    return await new Promise((resolve,reject)=>scrypt(password,salt,64,{N:32768,r:8,p:3,maxmem:64*1024*1024},(error,key)=>error?reject(error):resolve(key)));
  } finally {const next=waiters.shift(); if(next)next();else working--;}
}
export async function passwordHash(password: string): Promise<string> {
  const salt=randomBytes(16);
  return 'scrypt-v1$'+salt.toString('hex')+'$'+(await derive(password,salt)).toString('hex');
}
export async function passwordValid(password: string,stored: string): Promise<boolean> {
  const [version,salt,expected]=stored.split('$');
  if(version!=='scrypt-v1' || !/^[a-f0-9]{32}$/.test(salt??'') || !/^[a-f0-9]{128}$/.test(expected??''))return false;
  return equal((await derive(password,Buffer.from(salt,'hex'))).toString('hex'),expected);
}
const ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function newTotpSecret(): string {
  let bits='',out=''; for(const byte of randomBytes(20))bits+=byte.toString(2).padStart(8,'0');
  for(let i=0;i<bits.length;i+=5)out+=ALPHABET[parseInt(bits.slice(i,i+5),2)];
  return out;
}
export function totp(secret: string,step: number): string {
  let bits=''; for(const c of secret){const n=ALPHABET.indexOf(c);if(n<0)throw new Error('Invalid stored TOTP secret');bits+=n.toString(2).padStart(5,'0');}
  const key=Buffer.from((bits.match(/.{8}/g)??[]).map(b=>parseInt(b,2)));
  const counter=Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const value=createHmac('sha1',key).update(counter).digest();
  return String((value.readUInt32BE(value[19]&15)&0x7fffffff)%1_000_000).padStart(6,'0');
}
export function validTotp(secret: string,code: string,last: number,now=Date.now()): number|null {
  const step=Math.floor(now/30000);
  for(const candidate of [step,step-1,step+1])if(candidate>last && equal(totp(secret,candidate),code))return candidate;
  return null;
}
