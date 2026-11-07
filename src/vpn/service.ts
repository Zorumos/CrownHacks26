import type { Accounts,Account } from '../accounts/service.ts';
import type { Query } from '../database.ts';
import type { Config,ServerConfig } from '../config.ts';
import { AppError,assert,fail,text } from '../errors.ts';
import { id } from '../crypto.ts';
import type { AgentClient,Observation } from './agent-client.ts';

export function validatePublicKey(input:unknown){
  const value=text(input,44,44),raw=Buffer.from(value,'base64');
  assert(raw.length===32 && raw.some(v=>v!==0) && raw.toString('base64')===value,422,'INVALID_PUBLIC_KEY','Use a canonical WireGuard public key. Never submit a private key.');return value;
}
export class VPN {
  accounts:Accounts; config:Config; agent:AgentClient; clock:()=>number;
  constructor(accounts:Accounts,agent:AgentClient,clock=Date.now){this.accounts=accounts;this.config=accounts.config;this.agent=agent;this.clock=clock;}
  async device(db:Query,account:Account,deviceId:string,write=false,allowDisabled=false){
    if(write)await db.query('UPDATE devices SET operation_seq=operation_seq WHERE id=$1 AND account_id=$2',[deviceId,account.id]);
    const row=(await db.query('SELECT d.* FROM devices d JOIN accounts a ON d.account_id=a.id WHERE d.id=$1 AND d.account_id=$2 AND a.disabled=0 AND (d.disabled=0 OR $3=1)',[deviceId,account.id,allowDisabled?1:0])).rows[0];
    assert(row,404,'DEVICE_NOT_FOUND','That device is not available in your profile.');return row;
  }
  async addDevice(account:Account,input:Record<string,unknown>){
    await this.accounts.limit('devices:'+account.id,20);
    const label=text(input.label,1,60).trim(),key=validatePublicKey(input.publicKey);
    assert(label && !/[\x00-\x1f\x7f]/.test(label),422,'INVALID_LABEL','Use a printable device name.');
    const deviceId=id();
    try {
      await this.accounts.db.transaction(async db=>{
        const active=await db.query('UPDATE accounts SET created_at=created_at WHERE id=$1 AND disabled=0 RETURNING id',[account.id]);assert(active.rows[0],401,'ACCOUNT_UNAVAILABLE','This account is unavailable.');
        const count=Number((await db.query('SELECT count(*) AS count FROM devices WHERE account_id=$1',[account.id])).rows[0].count);
        assert(count<5,409,'DEVICE_LIMIT','Remove an old device before adding another.');
        await db.query('INSERT INTO devices(id,account_id,label,public_key,created_at) VALUES($1,$2,$3,$4,$5)',[deviceId,account.id,label,key,this.clock()]);
      });
    }catch(error:any){if(error instanceof AppError)throw error;if(error.code==='23505' || String(error.code).includes('SQLITE_CONSTRAINT'))fail(409,'KEY_ALREADY_REGISTERED','That public key is already registered.');throw error;}
    return {id:deviceId,label};
  }
  async listDevices(account:Account){return {devices:(await this.accounts.db.query('SELECT id,label,public_key,created_at FROM devices WHERE account_id=$1',[account.id])).rows};}
  listServers(){return {servers:this.config.servers.map(s=>({id:s.id,country:s.country,city:s.city,locationSource:'operator-configured'})),autoPolicy:'First responding configured management service in operator priority order; not measured client latency or load.'};}
  server(serverId:string){const server=this.config.servers.find(s=>s.id===serverId);assert(server,503,'SERVER_REMOVED','The configured server is unavailable. Restore its management configuration before revoking existing access.');return server;}
  async select(serverId:string){
    if(serverId!=='auto')assert(this.config.servers.some(s=>s.id===serverId),404,'UNKNOWN_SERVER','Refresh the available server list.');
    const candidates=serverId==='auto'?this.config.servers:this.config.servers.filter(s=>s.id===serverId);
    // Fixed operator inventory only; parallel probes keep eight timeouts from exceeding a function budget.
    const checks=await Promise.all(candidates.map(async candidate=>{try{await this.agent.call(candidate,'health');return candidate;}catch{return null;}}));
    const selected=checks.find(Boolean);if(selected)return selected;
    fail(503,'NO_USABLE_SERVER','No configured VPN management service responded.','Configure a real server or retry. A demo room cannot provide real VPN access.');
  }
  async connect(account:Account,deviceId:string,serverId:string,adblock:boolean){
    assert(!this.config.requireIdentity,503,'IDENTITY_NOT_CONFIGURED','VPN access is paused until required identity verification is integrated.');
    await this.accounts.limit('vpn:'+account.id,20);
    // Verify ownership before any outbound management request.
    await this.device(this.accounts.db,account,deviceId);
    const existing=(await this.accounts.db.query('SELECT * FROM connections WHERE device_id=$1',[deviceId])).rows[0];
    const selected=existing?this.server(existing.server_id):await this.select(serverId);
    const reserved=await this.accounts.db.transaction(async db=>{
      const device=await this.device(db,account,deviceId,true);
      let connection=(await db.query('SELECT * FROM connections WHERE device_id=$1',[deviceId])).rows[0];
      if(connection){
        assert(connection.state!=='revocation_pending',409,'REVOCATION_PENDING','Retry disconnect before requesting another connection.');
        assert((serverId==='auto' || connection.server_id===serverId) && Boolean(connection.adblock)===adblock,409,'DISCONNECT_FIRST','Disconnect before changing server or DNS preferences.');
      }else{
        await db.query('INSERT INTO allocation_locks(server_id) VALUES($1) ON CONFLICT(server_id) DO NOTHING',[selected.id]);
        await db.query('UPDATE allocation_locks SET server_id=server_id WHERE server_id=$1',[selected.id]);
        const used=new Set((await db.query('SELECT address4 FROM connections WHERE server_id=$1',[selected.id])).rows.map(r=>r.address4));
        const reservedDNS=new Set([...selected.dnsPlain,...selected.dnsFiltered]);
        let address4='',address6='';
        for(let n=2;n<=254;n++){const a4=selected.addressPrefix4+n,a6=selected.addressPrefix6+n.toString(16);if(!used.has(a4) && !reservedDNS.has(a4) && !reservedDNS.has(a6)){address4=a4;address6=a6;break;}}
        assert(address4,409,'SERVER_FULL','This server has no free device addresses.');
        const seq=Number(device.operation_seq)+1;
        await db.query('UPDATE devices SET operation_seq=$1 WHERE id=$2',[seq,deviceId]);
        await db.query('INSERT INTO connections(device_id,server_id,address4,address6,state,adblock,requested_at,operation_seq) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[deviceId,selected.id,address4,address6,'provisioning',adblock?1:0,this.clock(),seq]);
        connection=(await db.query('SELECT * FROM connections WHERE device_id=$1',[deviceId])).rows[0];
      }return {device,connection};
    });
    const server=this.server(reserved.connection.server_id);
    const observation=await this.agent.call(server,'provision',{key:reserved.device.public_key,address4:reserved.connection.address4,address6:reserved.connection.address6,sequence:Number(reserved.connection.operation_seq)});
    assert(observation.peerPresent,503,'PROVISION_UNCONFIRMED','The service did not confirm peer setup. Retry or revoke this allocation.');
    const changed=await this.accounts.db.query("UPDATE connections SET state='provisioned' WHERE device_id=$1 AND operation_seq=$2 AND state<>'revocation_pending'",[deviceId,reserved.connection.operation_seq]);
    assert(changed.rowCount===1,409,'OPERATION_SUPERSEDED','A newer device operation replaced this request. Refresh status.');
    return {deviceId,serverId:server.id,configuration:{privateKeySource:'native-device-only',addresses:[reserved.connection.address4+'/32',reserved.connection.address6+'/128'],dns:adblock?server.dnsFiltered:server.dnsPlain,peer:{publicKey:server.publicKey,endpoint:server.endpoint,allowedIPs:['0.0.0.0/0','::/0'],persistentKeepalive:25},adblockRequested:adblock,adblockVerified:null,killSwitchRequired:true},...await this.evidence(deviceId,reserved.connection,observation)};
  }
  async evidence(deviceId:string,connection:Record<string,any>,observation:Observation|null){
    const now=this.clock(),stamp=observation?.handshake??null;
    const fresh=Boolean(observation?.peerPresent && stamp!==null && stamp<=now && now-stamp<=180000);
    const code=!observation?'EVIDENCE_UNAVAILABLE':fresh?'DEVICE_PROTECTION_UNKNOWN':'CONTACT_NOT_RECENT';
    const previous=(await this.accounts.db.query('SELECT * FROM warnings WHERE device_id=$1',[deviceId])).rows[0];
    const announce=!previous || previous.code!==code || now-Number(previous.last_announced)>=60000;
    if(announce)await this.accounts.db.query('INSERT INTO warnings(device_id,code,last_announced) VALUES($1,$2,$3) ON CONFLICT(device_id) DO UPDATE SET code=excluded.code,last_announced=excluded.last_announced',[deviceId,code,now]);
    const elapsed=fresh && stamp!>=Number(connection.requested_at)?stamp!-Number(connection.requested_at):null;
    return {state:!observation?'unknown':fresh?'tunnel_contact_observed':'waiting_for_client',protected:null,protectionStatus:'not_verified',
      evidence:{source:observation?'wireguard-server':'unavailable',observedAt:now,peerPresent:observation?.peerPresent??null,lastHandshake:stamp,recentContact:fresh,publicIP:null,deviceRoutesVerified:null,dnsVerified:null,ipv6Verified:null,killSwitchVerified:null},
      timing:{requestToHandshakeMs:elapsed,handshakeWithin60Seconds:elapsed===null?null:elapsed<60000,protectionWithin60Seconds:null},
      warnings:[{code,severity:'warning',message:!observation?'Server state could not be confirmed.':fresh?'The server saw recent peer contact. Device-wide protection is not verified.':'The server has no recent peer contact. An idle tunnel or connection problem can cause this.',action:'Check the native client, routing, DNS, IPv6 and kill switch before relying on protection.',retryable:!fresh,announce,interrupt:false,delivery:'persistent-banner'},...(connection.adblock?[{code:'ADBLOCK_UNVERIFIED',severity:'info',message:'Filtered DNS was requested but enforcement has not been verified.',action:'Check the native DNS configuration and resolver.',announce:false,interrupt:false}]:[])]};
  }
  async status(account:Account,deviceId:string){
    await this.accounts.limit('vpn-status:'+account.id,120);
    const device=await this.device(this.accounts.db,account,deviceId);
    const connection=(await this.accounts.db.query('SELECT * FROM connections WHERE device_id=$1',[deviceId])).rows[0];
    if(!connection)return {state:'not_provisioned',protected:false,scope:'This service only; other device security is unknown.'};
    if(connection.state==='revocation_pending')return {state:'revocation_pending',protected:null,message:'Revocation is not confirmed. Stop the native tunnel and retry disconnect.'};
    let observation:Observation|null=null;try{observation=await this.agent.call(this.server(connection.server_id),'status',{key:device.public_key});}catch{}
    return {deviceId,serverId:connection.server_id,...await this.evidence(deviceId,connection,observation)};
  }
  async revokeRecord(device:Record<string,any>){
    const connection=await this.accounts.db.transaction(async db=>{
      await db.query('UPDATE devices SET operation_seq=operation_seq WHERE id=$1',[device.id]);
      const existing=(await db.query('SELECT * FROM connections WHERE device_id=$1',[device.id])).rows[0];if(!existing)return null;
      if(existing.state==='revocation_pending')return existing;
      const changed=await db.query('UPDATE devices SET operation_seq=operation_seq+1 WHERE id=$1 RETURNING operation_seq',[device.id]);
      const seq=Number(changed.rows[0].operation_seq);
      await db.query("UPDATE connections SET state='revocation_pending',operation_seq=$1 WHERE device_id=$2",[seq,device.id]);
      return {...existing,state:'revocation_pending',operation_seq:seq};
    });
    if(!connection)return;
    const observation=await this.agent.call(this.server(connection.server_id),'revoke',{key:device.public_key,sequence:Number(connection.operation_seq)});
    assert(!observation.peerPresent,503,'REVOCATION_UNCONFIRMED','Server access removal is not confirmed. Stop the native tunnel and retry.');
    await this.accounts.db.query('DELETE FROM connections WHERE device_id=$1 AND operation_seq=$2 AND state=$3',[device.id,connection.operation_seq,'revocation_pending']);
  }
  async disconnect(account:Account,deviceId:string){const device=await this.device(this.accounts.db,account,deviceId,false,true);await this.revokeRecord(device);return {state:'server_access_revoked',protected:false,message:'Stop the tunnel in the native client too. This service cannot stop the device interface remotely.'};}
  async deleteDevice(account:Account,deviceId:string){
    const device=await this.accounts.db.transaction(async db=>{const row=await this.device(db,account,deviceId,true,true);await db.query('UPDATE devices SET disabled=1 WHERE id=$1',[deviceId]);return row;});
    await this.revokeRecord(device);await this.accounts.db.query('DELETE FROM devices WHERE id=$1 AND account_id=$2',[deviceId,account.id]);return {deleted:true};
  }
  async deleteAccounts(account:Account,input:Record<string,unknown>,memberId?:string){
    await this.accounts.limit('sensitive:'+account.id);
    const ids=await this.accounts.db.transaction(async db=>{
      await this.accounts.reauthenticate(db,account,input,true);
      if(memberId){this.accounts.owner(account);const member=(await db.query('SELECT id FROM accounts WHERE id=$1 AND owner_id=$2',[memberId,account.id])).rows[0];assert(member,404,'MEMBER_NOT_FOUND','That family member is not available.');}
      const affected=memberId?[memberId]:[...(await db.query('SELECT id FROM accounts WHERE owner_id=$1',[account.id])).rows.map(r=>r.id),account.id];
      for(const accountId of affected){await db.query('UPDATE accounts SET disabled=1 WHERE id=$1',[accountId]);}
      return affected;
    });
    // Keep the caller's session until revocation succeeds so deletion can be retried.
    // The API exposes a deletion-retry authentication path only for this operation.
    for(const accountId of ids){const devices=(await this.accounts.db.query('SELECT * FROM devices WHERE account_id=$1',[accountId])).rows;for(const device of devices)await this.revokeRecord(device);}
    await this.accounts.db.transaction(async db=>{for(const accountId of ids)await db.query('DELETE FROM accounts WHERE id=$1',[accountId]);});
    return {deleted:true,message:'Application records removed after confirmed peer revocation. Operator backup retention remains separate.'};
  }
}
