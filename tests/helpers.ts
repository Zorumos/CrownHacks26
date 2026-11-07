import { readFile } from 'node:fs/promises';
import { SQLiteDatabase } from '../src/database.ts';
import { loadConfig } from '../src/config.ts';
import type { AtomicStore } from '../src/store.ts';
import type { AgentClient } from '../src/vpn/agent-client.ts';
import { randomBytes } from 'node:crypto';

// Test fixtures only. Runtime never uses an in-memory server room store or fake agent.
export class TestStore implements AtomicStore {
  values=new Map<string,{value:string,expires:number}>();now=1000000;fail=false;conflicts=0;
  async read(key:string){if(this.fail)throw new Error('Injected provider failure');const item=this.values.get(key);if(!item || item.expires<=this.now)return null;return item.value;}
  async create(key:string,value:string,ttl:number){if(this.fail)throw new Error('Injected provider failure');const old=this.values.get(key);if(old && old.expires>this.now)return false;this.values.set(key,{value,expires:this.now+ttl*1000});return true;}
  async compareAndSet(key:string,expected:string,value:string,ttl:number){
    if(this.fail)throw new Error('Injected provider failure');
    if(this.conflicts>0){this.conflicts--;return false;}
    const current=this.values.get(key);if(!current || current.expires<=this.now || current.value!==expected)return false;
    this.values.set(key,{value,expires:this.now+ttl*1000});return true;
  }
}
export async function database(){const db=await SQLiteDatabase.open(':memory:');const sql=await readFile(new URL('../migrations/001_initial.sql',import.meta.url),'utf8');await db.transaction(async tx=>{for(const statement of sql.split(';').map(x=>x.trim()).filter(Boolean))await tx.query(statement);});return db;}
export const key=()=>randomBytes(32).toString('base64');
export function config(){return loadConfig({NODE_ENV:'test',APP_ORIGIN:'http://127.0.0.1:3000',APP_MASTER_KEY:randomBytes(32).toString('hex'),DEMO_CREATE_SECRET:randomBytes(32).toString('base64url')});}
export class FakeAgent implements AgentClient {
  peers=new Map<string,number|null>();sequences=new Map<string,number>();fail=false;ambiguous=false;calls:any[]=[];
  async call(server:any,operation:any,payload:any={}){
    this.calls.push({operation,payload});if(this.fail)throw new Error('Injected agent failure');
    const current=this.sequences.get(payload.key)??0;
    if(operation==='provision'||operation==='revoke'){
      if(payload.sequence<current)throw new Error('Stale agent operation');this.sequences.set(payload.key,payload.sequence);
      if(operation==='provision')this.peers.set(payload.key,this.peers.get(payload.key)??null);else this.peers.delete(payload.key);
      if(this.ambiguous)throw new Error('Injected timeout after side effect');
    }
    return {publicKey:server.publicKey,peerPresent:this.peers.has(payload.key),handshake:this.peers.get(payload.key)??null};
  }
}
