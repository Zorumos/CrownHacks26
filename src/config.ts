import { assert } from './errors.ts';
import { isIP } from 'node:net';
export interface ServerConfig {
  id: string; country: string; city: string; publicKey: string;
  endpoint: string; agentUrl: string; agentSecret: string;
  addressPrefix4: string; addressPrefix6: string;
  dnsPlain: string[]; dnsFiltered: string[];
}
export interface Config {
  production: boolean; origin: string; masterKey: string;
  createSecret: string; redisUrl: string; redisToken: string;
  databaseUrl: string; localDbPath: string; requireIdentity: boolean;
  familyLimit: number; servers: ServerConfig[];
}
export function loadConfig(env: NodeJS.ProcessEnv=process.env): Config {
  const production=env.NODE_ENV==='production' || env.VERCEL==='1';
  const origin=env.APP_ORIGIN??'http://127.0.0.1:3000';
  const parsed=new URL(origin);
  assert(parsed.origin===origin && !parsed.username && !parsed.password,500,'BAD_CONFIG','APP_ORIGIN must be an exact origin.');
  assert(parsed.protocol==='https:' || (!production && ['localhost','127.0.0.1'].includes(parsed.hostname)),500,'BAD_CONFIG','HTTPS is required outside local development.');
  const masterKey=env.APP_MASTER_KEY??'';
  assert(!masterKey || /^[a-f0-9]{64}$/.test(masterKey),500,'BAD_CONFIG','APP_MASTER_KEY must be 32 random bytes encoded as hex.');
  const familyLimit=Number(env.FAMILY_LIMIT??3);
  assert(Number.isInteger(familyLimit) && familyLimit>=0 && familyLimit<=10,500,'BAD_CONFIG','FAMILY_LIMIT must be 0 to 10.');
  let servers: ServerConfig[]=[];
  try {servers=JSON.parse(env.VPN_SERVERS_JSON??'[]');}catch{throw new Error('Invalid VPN_SERVERS_JSON');}
  assert(Array.isArray(servers) && servers.length<=8,500,'BAD_CONFIG','Configure at most eight VPN servers.');
  const seen=new Set();
  for(const s of servers){
    assert(/^[a-z0-9-]{1,40}$/.test(s.id) && !seen.has(s.id),500,'BAD_CONFIG','Server IDs must be unique.');seen.add(s.id);
    const agent=new URL(s.agentUrl);
    assert(agent.protocol==='https:' && agent.pathname==='/v1/peer' && !agent.username && !agent.password && !agent.search && !agent.hash,500,'BAD_CONFIG','Agent URL must be a fixed HTTPS /v1/peer endpoint.');
    assert(typeof s.agentSecret==='string' && s.agentSecret.length>=32,500,'BAD_CONFIG','Configure a strong agent secret.');
    const ip4=s.addressPrefix4+'1',parts=ip4.split('.').map(Number);
    assert(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.$/.test(s.addressPrefix4) && isIP(ip4)===4 && (parts[0]===10 || (parts[0]===172 && parts[1]>=16 && parts[1]<=31) || (parts[0]===192 && parts[1]===168)) && /^fd[a-f0-9]{2}(?::[a-f0-9]{0,4})*::$/.test(s.addressPrefix6) && isIP(s.addressPrefix6+'2')===6,500,'BAD_CONFIG','Use the documented private /24 and ULA address prefixes.');
    assert([s.country,s.city].every(v=>typeof v==='string' && v.length>0 && v.length<=80),500,'BAD_CONFIG','Provide real server labels.');
    assert(/^[A-Za-z0-9+/]{43}=$/.test(s.publicKey) && s.publicKey!=='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',500,'BAD_CONFIG','Invalid server public key.');
    assert(/^(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}$/.test(s.endpoint),500,'BAD_CONFIG','Invalid endpoint.');
    assert(Array.isArray(s.dnsPlain) && s.dnsPlain.length>0 && Array.isArray(s.dnsFiltered) && s.dnsFiltered.length>0,500,'BAD_CONFIG','Configure plain and filtered resolvers.');
    assert([...s.dnsPlain,...s.dnsFiltered].every(ip=>typeof ip==='string' && isIP(ip)>0),500,'BAD_CONFIG','Resolver addresses must be IP literals.');
    assert(Number(s.endpoint.split(':').at(-1))>=1 && Number(s.endpoint.split(':').at(-1))<=65535,500,'BAD_CONFIG','Endpoint port is invalid.');
  }
  return {production,origin,masterKey,createSecret:env.DEMO_CREATE_SECRET??'',redisUrl:env.UPSTASH_REDIS_REST_URL??'',redisToken:env.UPSTASH_REDIS_REST_TOKEN??'',databaseUrl:env.DATABASE_URL??'',localDbPath:env.LOCAL_DB_PATH??'data/accounts.sqlite3',requireIdentity:env.REQUIRE_IDENTITY==='true',familyLimit,servers};
}
