import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/database.ts';
const db=await openDatabase(loadConfig());const now=Date.now();
try{for(const table of ['sessions','invites'])await db.query(`DELETE FROM ${table} WHERE expires_at<=$1`,[now]);await db.query('DELETE FROM rate_windows WHERE reset_at<=$1',[now]);console.log('Removed expired sessions, invitations and rate windows. No account or VPN record was deleted.');}finally{await db.close();}
