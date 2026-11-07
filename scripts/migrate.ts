import { readFile } from 'node:fs/promises';
import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/database.ts';
const db=await openDatabase(loadConfig());
try {
  const sql=await readFile(new URL('../migrations/001_initial.sql',import.meta.url),'utf8');
  await db.transaction(async transaction=>{for(const statement of sql.split(';').map(s=>s.trim()).filter(Boolean))await transaction.query(statement);});
  console.log('Applied initial schema version 1.');
}finally{await db.close();}
