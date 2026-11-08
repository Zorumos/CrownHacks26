import {readFile,mkdir,writeFile,rename} from 'node:fs/promises';
import {seal,open} from './security.js';
import {StoreFault,decryptState} from './diagnostics.js';
const fresh=()=>({users:[],sessions:[],backups:[],limits:{},lastBackup:0});
let queue=Promise.resolve(),pool;
export async function transact(fn) {
 const connectionString=process.env.DATABASE_URL;
 if(connectionString){
  try{const url=new URL(connectionString);if(!['postgres:','postgresql:'].includes(url.protocol)||!url.hostname||connectionString!==connectionString.trim())throw Error();}catch{throw new StoreFault('DB_URL_INVALID','configuration');}
  if(!pool){try{const {Pool}=await import('pg');pool=new Pool({connectionString,max:3,connectionTimeoutMillis:10000});}catch(e){throw new StoreFault('DB_DRIVER_FAILED','driver',e);}}
  let c;try{c=await pool.connect();}catch(e){const tls=/certificate|ssl|tls/i.test(String(e.message||''));throw new StoreFault(tls?'DB_TLS_FAILED':'DB_CONNECT_FAILED','connection',e);}
  let stage='transaction';
  try{
   await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(73419321)');
   stage='read';const {rows}=await c.query('SELECT payload FROM cyber_state WHERE id=1');
   const s=rows.length?decryptState(rows[0].payload,open):fresh();
   const result=await fn(s);
   stage='write';await c.query('INSERT INTO cyber_state(id,payload) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload',[seal(s)]);
   await c.query('COMMIT');return result;
  }catch(e){try{await c.query('ROLLBACK');}catch{}if(e instanceof StoreFault)throw e;throw new StoreFault(stage==='read'?'DB_READ_FAILED':stage==='write'?'DB_WRITE_FAILED':'DB_TRANSACTION_FAILED',stage,e);}finally{c.release();}
 }
 if(process.env.VERCEL)throw new StoreFault('DB_NOT_CONFIGURED','configuration');
 const task=queue.then(async()=>{
  await mkdir('.data',{recursive:true,mode:0o700});let s;
  try{s=decryptState(JSON.parse(await readFile('.data/state.json','utf8')),open);}catch(e){if(e.code==='ENOENT')s=fresh();else if(e instanceof StoreFault)throw e;else throw new StoreFault('LOCAL_STATE_READ_FAILED','local-read',e);}
  const result=await fn(s);
  try{await writeFile('.data/state.tmp',JSON.stringify(seal(s)),{mode:0o600});await rename('.data/state.tmp','.data/state.json');}catch(e){throw new StoreFault('LOCAL_STATE_WRITE_FAILED','local-write',e);}
  return result;
 });queue=task.catch(()=>{});return task;
}
export function backup(s,force=false) {const now=Date.now();if(!force&&now-s.lastBackup<600000)return false;for(const u of s.users){s.backups.push({id:crypto.randomUUID(),owner:u.id,at:now,box:seal(u)});}s.backups=s.backups.filter(b=>now-b.at<86400000);s.lastBackup=now;return true;}
