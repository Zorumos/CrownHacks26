import { test } from 'node:test';
import assert from 'node:assert/strict';
import { database,config,key,FakeAgent } from './helpers.ts';
import { Accounts } from '../src/accounts/service.ts';
import { disclosure } from '../src/accounts/disclosure.ts';
import { VPN } from '../src/vpn/service.ts';
import { totp,hash } from '../src/crypto.ts';

const password='a long test password';
async function fixture(){
  const db=await database(),cfg=config();let now=1700000000000;
  const accounts=new Accounts(db,cfg,()=>now),agent=new FakeAgent();
  cfg.servers.push({id:'test',country:'TEST FIXTURE',city:'Not deployed',publicKey:key(),endpoint:'vpn.example.test:51820',agentUrl:'https://agent.example.test/v1/peer',agentSecret:'test-only-not-a-real-secret-at-all',addressPrefix4:'10.42.0.',addressPrefix6:'fd42::',dnsPlain:['10.42.0.1'],dnsFiltered:['10.42.0.53']});
  const vpn=new VPN(accounts,agent,()=>now);
  async function user(username='tester',invitation?:string){
    const d=disclosure(cfg),input={username,password,name:'Test Person',signature:'test person',agreed:true,disclosureVersion:d.version,documentHash:d.documentHash,invitation};
    const registered=await accounts.register(input),pending=await accounts.auth(registered.accessToken,false,false),setup=await accounts.setup(pending);
    const code=totp(setup.secret,Math.floor(now/30000)),confirmed=await accounts.confirm(pending,code),account=await accounts.auth(confirmed.accessToken);
    return {registered,pending,setup,code,confirmed,account,input};
  }
  async function close(){await accounts.dummy;await db.close();}
  return {db,cfg,accounts,agent,vpn,user,close,advance:(ms:number)=>now+=ms};
}
async function run(fn:(f:Awaited<ReturnType<typeof fixture>>)=>Promise<void>){const f=await fixture();try{await fn(f);}finally{await f.close();}}

test('real-service registration records minimal consent evidence and restricts enrollment',()=>run(async f=>{
  const u=await f.user();const consent=(await f.db.query('SELECT * FROM consents')).rows[0];
  assert.ok(!JSON.stringify(consent).toLowerCase().includes('test person'));assert.equal(consent.name_attestation.length,64);
  await assert.rejects(f.accounts.auth(u.registered.accessToken),{code:'SESSION_EXPIRED'});
  assert.equal(u.account.mfa,1);
}));
test('unsigned stale or mismatched agreement is rejected',()=>run(async f=>{
  const d=disclosure(f.cfg),base={username:'new_user',password,name:'Test Person',signature:'Test Person',agreed:true,disclosureVersion:d.version,documentHash:d.documentHash};
  for(const patch of [{agreed:false},{documentHash:'0'.repeat(64)},{signature:'Other Person'}])await assert.rejects(f.accounts.register({...base,...patch}));
}));
test('mandatory identity policy blocks registration',()=>run(async f=>{f.cfg.requireIdentity=true;const d=disclosure(f.cfg);await assert.rejects(f.accounts.register({username:'blocked',password,name:'Test Person',signature:'Test Person',agreed:true,disclosureVersion:d.version,documentHash:d.documentHash}),{code:'IDENTITY_NOT_CONFIGURED'});}));
test('enrollment token cannot authorize devices',()=>run(async f=>{const d=disclosure(f.cfg),r=await f.accounts.register({username:'pending',password,name:'Test Person',signature:'Test Person',agreed:true,disclosureVersion:d.version,documentHash:d.documentHash});await assert.rejects(f.accounts.auth(r.accessToken),{code:'MFA_REQUIRED'});}));
test('TOTP replay is rejected and recovery code is one-use',()=>run(async f=>{
  const u=await f.user();await assert.rejects(f.accounts.login({username:'tester',password,code:u.code}),{code:'INVALID_CREDENTIALS'});
  const data={username:'tester',password,code:u.confirmed.recoveryCodes[0]};assert.equal((await f.accounts.login(data)).scope,'full');await assert.rejects(f.accounts.login(data),{code:'INVALID_CREDENTIALS'});
}));
test('expired sessions and logout are enforced',()=>run(async f=>{const u=await f.user();await f.accounts.logout(u.account);await assert.rejects(f.accounts.auth(u.confirmed.accessToken),{code:'SESSION_EXPIRED'});const login=await f.accounts.login({username:'tester',password,code:u.confirmed.recoveryCodes[0]});f.advance(1800001);await assert.rejects(f.accounts.auth(login.accessToken),{code:'SESSION_EXPIRED'});}));
test('MFA reset invalidates old sessions and recovery codes',()=>run(async f=>{const u=await f.user();const reset=await f.accounts.resetMfa(u.account,{password,code:u.confirmed.recoveryCodes[0]});assert.equal(reset.scope,'enroll');await assert.rejects(f.accounts.auth(u.confirmed.accessToken),{code:'SESSION_EXPIRED'});assert.equal((await f.db.query('SELECT * FROM recovery_codes')).rowCount,0);}));
test('family reservations enforce three slots',()=>run(async f=>{const u=await f.user();await f.accounts.invite(u.account);await f.accounts.invite(u.account);await f.accounts.invite(u.account);await assert.rejects(f.accounts.invite(u.account),{code:'FAMILY_FULL'});}));
test('family invitation is one-use and owner cannot access member devices',()=>run(async f=>{
  const owner=await f.user(),invite=await f.accounts.invite(owner.account),member=await f.user('member',invite.invitation);
  const device=await f.vpn.addDevice(member.account,{label:'Member laptop',publicKey:key()});
  await assert.rejects(f.vpn.status(owner.account,device.id),{code:'DEVICE_NOT_FOUND'});
  await assert.rejects(f.vpn.connect(owner.account,device.id,'auto',true),{code:'DEVICE_NOT_FOUND'});
  assert.equal(f.agent.calls.length,0);
  await assert.rejects(f.user('second_member',invite.invitation),{code:'INVALID_INVITE'});
  await assert.rejects(f.accounts.invite(member.account),{code:'OWNER_REQUIRED'});
}));
test('connection returns actual configuration but never claims device protection',()=>run(async f=>{
  const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});
  const result=await f.vpn.connect(u.account,d.id,'auto',true);
  assert.equal(result.state,'waiting_for_client');assert.equal(result.protected,null);assert.equal(result.configuration.privateKeySource,'native-device-only');assert.equal(result.configuration.adblockVerified,null);
  assert.deepEqual(result.configuration.peer.allowedIPs,['0.0.0.0/0','::/0']);assert.equal(f.agent.peers.size,1);
}));
test('repeat connect reuses addresses and peer',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});const first=await f.vpn.connect(u.account,d.id,'auto',true),second=await f.vpn.connect(u.account,d.id,'auto',true);assert.deepEqual(first.configuration,second.configuration);assert.equal(f.agent.peers.size,1);}));
test('parallel device allocations remain unique',()=>run(async f=>{const u=await f.user(),a=await f.vpn.addDevice(u.account,{label:'A',publicKey:key()}),b=await f.vpn.addDevice(u.account,{label:'B',publicKey:key()});const [one,two]=await Promise.all([f.vpn.connect(u.account,a.id,'auto',true),f.vpn.connect(u.account,b.id,'auto',true)]);assert.notDeepEqual(one.configuration.addresses,two.configuration.addresses);}));
test('DNS preference changes require explicit disconnect',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});await f.vpn.connect(u.account,d.id,'auto',true);await assert.rejects(f.vpn.connect(u.account,d.id,'auto',false),{code:'DISCONNECT_FIRST'});}));
test('recent handshake is not proof of routing or kill switch',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});await f.vpn.connect(u.account,d.id,'auto',true);const k=[...f.agent.peers.keys()][0];f.agent.peers.set(k,1700000000000);const status=await f.vpn.status(u.account,d.id);assert.equal(status.state,'tunnel_contact_observed');assert.equal(status.protected,null);if('evidence'in status){assert.equal(status.evidence.killSwitchVerified,null);assert.equal(status.timing.protectionWithin60Seconds,null);}}));
test('provision timeout preserves an uncertain live allocation',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});f.agent.ambiguous=true;await assert.rejects(f.vpn.connect(u.account,d.id,'auto',true));assert.equal(f.agent.peers.size,1);assert.equal((await f.db.query('SELECT * FROM connections')).rows[0].state,'provisioning');f.agent.ambiguous=false;await f.vpn.disconnect(u.account,d.id);assert.equal(f.agent.peers.size,0);}));
test('failed revocation retains allocation and blocks reconnect',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});await f.vpn.connect(u.account,d.id,'auto',true);f.agent.fail=true;await assert.rejects(f.vpn.disconnect(u.account,d.id));assert.equal((await f.db.query('SELECT * FROM connections')).rows[0].state,'revocation_pending');await assert.rejects(f.vpn.connect(u.account,d.id,'auto',true),{code:'REVOCATION_PENDING'});f.agent.fail=false;await f.vpn.disconnect(u.account,d.id);assert.equal(f.agent.peers.size,0);}));
test('deleting a device disables new connects until revocation succeeds',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});await f.vpn.connect(u.account,d.id,'auto',true);f.agent.fail=true;await assert.rejects(f.vpn.deleteDevice(u.account,d.id));await assert.rejects(f.vpn.connect(u.account,d.id,'auto',true),{code:'DEVICE_NOT_FOUND'});f.agent.fail=false;await f.vpn.deleteDevice(u.account,d.id);assert.equal((await f.db.query('SELECT * FROM devices')).rowCount,0);}));
test('account deletion revokes peers and removes database records',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});await f.vpn.connect(u.account,d.id,'auto',true);await f.vpn.deleteAccounts(u.account,{password,code:u.confirmed.recoveryCodes[0]});assert.equal(f.agent.peers.size,0);for(const name of ['accounts','devices','connections','consents','sessions','recovery_codes'])assert.equal((await f.db.query('SELECT * FROM '+name)).rowCount,0);}));
test('failed account deletion can be retried through deletion-only login',()=>run(async f=>{
  const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});await f.vpn.connect(u.account,d.id,'auto',true);f.agent.fail=true;
  await assert.rejects(f.vpn.deleteAccounts(u.account,{password,code:u.confirmed.recoveryCodes[0]}));await assert.rejects(f.accounts.auth(u.confirmed.accessToken),{code:'DELETION_PENDING'});
  const login=await f.accounts.login({username:'tester',password,code:u.confirmed.recoveryCodes[1]});assert.equal(login.scope,'delete');
  const account=await f.accounts.auth(login.accessToken,true,false,true);f.agent.fail=false;await f.vpn.deleteAccounts(account,{password,code:u.confirmed.recoveryCodes[2]});assert.equal(f.agent.peers.size,0);
}));
test('disclosure changes restrict new activity but allow revocation',()=>run(async f=>{const u=await f.user(),d=await f.vpn.addDevice(u.account,{label:'Laptop',publicKey:key()});await f.vpn.connect(u.account,d.id,'auto',true);f.cfg.requireIdentity=true;await assert.rejects(f.accounts.auth(u.confirmed.accessToken),{code:'DISCLOSURE_CHANGED'});const a=await f.accounts.auth(u.confirmed.accessToken,true,false);await f.vpn.disconnect(a,d.id);assert.equal(f.agent.peers.size,0);}));
