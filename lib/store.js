import {readFile,mkdir,writeFile,rename} from 'node:fs/promises';
import {seal,open} from './security.js';
const fresh=()=>({users:[],sessions:[],backups:[],limits:{},lastBackup:0});
let queue=Promise.resolve(),pool;
export async function transact(fn) {
 if(process.env.DATABASE_URL){
  if(!pool){const {Pool}=await import('pg');pool=new Pool({connectionString:process.env.DATABASE_URL,max:3});}
  const c=await pool.connect();try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(73419321)');const {rows}=await c.query('SELECT payload FROM cyber_state WHERE id=1');const s=rows.length?open(rows[0].payload):fresh();const result=await fn(s);await c.query('INSERT INTO cyber_state(id,payload) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload',[seal(s)]);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 if(process.env.VERCEL)throw new Error('DATABASE_URL is required on Vercel');
 const task=queue.then(async()=>{await mkdir('.data',{recursive:true,mode:0o700});let s;try{s=open(JSON.parse(await readFile('.data/state.json','utf8')));}catch(e){if(e.code!=='ENOENT')throw e;s=fresh();}const result=await fn(s);await writeFile('.data/state.tmp',JSON.stringify(seal(s)),{mode:0o600});await rename('.data/state.tmp','.data/state.json');return result;});queue=task.catch(()=>{});return task;
}
export function backup(s,force=false) {const now=Date.now();if(!force&&now-s.lastBackup<600000)return false;for(const u of s.users){s.backups.push({id:crypto.randomUUID(),owner:u.id,at:now,box:seal(u)});}s.backups=s.backups.filter(b=>now-b.at<86400000);s.lastBackup=now;return true;}
