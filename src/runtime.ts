import { loadConfig } from './config.ts';
import { RedisStore } from './store.ts';
import { Rooms } from './demo/rooms.ts';
import { Accounts } from './accounts/service.ts';
import { openDatabase } from './database.ts';
import { VPN } from './vpn/service.ts';
import { HTTPSAgent } from './vpn/agent-client.ts';
import { fail } from './errors.ts';

// These are connection/service factories, never authoritative shared demo state.
let roomFactory:Promise<Rooms>|undefined;
let accountFactory:Promise<Accounts>|undefined;
export async function getRooms(){
  if(!roomFactory)roomFactory=(async()=>{const config=loadConfig();return new Rooms(await RedisStore.open(config),config.origin);})().catch(error=>{roomFactory=undefined;throw error;});
  return roomFactory;
}
export async function getAccounts(){
  if(!accountFactory)accountFactory=(async()=>{
    const config=loadConfig();const db=await openDatabase(config);
    try{const version=await db.query('SELECT version FROM schema_migrations ORDER BY version DESC');if(Number(version.rows[0]?.version)!==1)throw new Error('Schema version');}
    catch{await db.close();fail(503,'SCHEMA_REQUIRED','Account database needs initialization.','Run npm run setup and npm run migrate.');}
    return new Accounts(db,config);
  })().catch(error=>{accountFactory=undefined;throw error;});
  return accountFactory;
}
export async function getVPN(){return new VPN(await getAccounts(),new HTTPSAgent());}
