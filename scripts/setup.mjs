import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const value=`APP_ORIGIN=http://127.0.0.1:3000\nAPP_MASTER_KEY=${randomBytes(32).toString('hex')}\nDEMO_CREATE_SECRET=${randomBytes(32).toString('base64url')}\nLOCAL_DB_PATH=data/accounts.sqlite3\nREQUIRE_IDENTITY=false\nFAMILY_LIMIT=3\nVPN_SERVERS_JSON=[]\n`;
try {writeFileSync('.env.local',value,{flag:'wx',mode:0o600});console.log('Created private .env.local. Run npm run migrate next. No cloud resources or VPN server configured.');}
catch(error){if(error.code==='EEXIST'){console.log('.env.local already exists; keys were not changed.');}else throw error;}
