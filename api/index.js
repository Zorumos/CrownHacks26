import {emailReady,sendEmail} from '../lib/email.js';
import {normalizeEmail,validEmail,pruneRecovery,verificationMail,recoveryAction} from '../lib/recovery.js';
import {transact,backup} from '../lib/store.js';
import {id,digest,equal,seal,open,passwordHash,passwordMatches,codes,codeHash,screen} from '../lib/security.js';
const fail=(status,message)=>({status,body:{error:message}});
const view=(u,session={})=>{const member=session.member?u.family.find(f=>f.id===session.member):null;const actor=member||u;const selfActive=member?!!member.active:!!u.selfActive;return {username:actor.username||u.username,name:actor.name,email:actor.email||'',emailVerified:!!actor.emailVerified,notify:actor.notify??true,role:member?'mini':'owner',householdUsername:u.username,family:member?[]:u.family.map(f=>({id:f.id,name:f.name,username:f.username||null,hasLogin:!!f.password,active:!!f.active&&!!u.lease?.active})),lease:u.lease?{...u.lease,active:selfActive&&!!u.lease.active,sharedActive:!!u.lease.active}:null,alerts:u.alerts};};
const syncLease=u=>{if(u.lease)u.lease.active=!u.lease.incident&&(!!u.selfActive||u.family.some(f=>f.active));};
const usernameTaken=(s,name)=>s.users.some(u=>u.username===name||u.family.some(f=>f.username===name));
export async function dispatch(s,path,b,token,method) {
 const now=Date.now();pruneRecovery(s);s.sessions=s.sessions.filter(x=>x.expires>now);for(const k of Object.keys(s.limits))if(s.limits[k].until<now)delete s.limits[k];
 const session=s.sessions.find(x=>x.hash===digest(token||''));const u=session?.user?s.users.find(x=>x.id===session.user):null;
 const member=session?.member?u?.family.find(f=>f.id===session.member):null;const actor=member||u;if(u&&u.selfActive===undefined)u.selfActive=!!u.lease?.active;
 const auth=()=>u&&(!session.member||member)&&session.stage==='ready';
 const issue=(user,stage,memberId)=>{const t=id();s.sessions.push({hash:digest(t),user,stage,...(memberId?{member:memberId}:{}),expires:now+3600000});return t;};
 const throttle=(k,max=10)=>{const a=s.limits[k]||{count:0,until:now+900000};a.count++;s.limits[k]=a;return a.count>max;};
 if(path==='config')return {body:{demo:process.env.DEMO_MODE==='true',storage:process.env.DATABASE_URL?'PostgreSQL':'Local encrypted file',emailRecovery:emailReady()}};
 if(path==='cron') {if(!equal(token,process.env.CRON_SECRET))return fail(401,'Not authorized');backup(s);return {body:{ok:true}};}
 if(method!=='POST')return fail(405,'Use POST for this operation.');
 const recoveryResult=recoveryAction(s,path,b,throttle);if(recoveryResult)return recoveryResult;
 if(path==='register') {
  if(throttle('registrations'))return fail(429,'Registration limit reached. Try again in 15 minutes.');
  if(process.env.DEMO_MODE!=='true')return fail(503,'Identity verification provider is not configured. Registration is unavailable.');
  const username=String(b.username||'').toLowerCase();if(!/^[a-z0-9_]{3,24}$/.test(username))return fail(400,'Use 3–24 letters, numbers or underscores for your username.');
  if(typeof b.password!=='string'||b.password.length<12||b.password.length>128||b.password!==b.confirm)return fail(400,'Use matching passwords with 12–128 characters.');
  const email=normalizeEmail(b.email);if(!validEmail(email))return fail(400,'Enter a valid email address for account recovery.');
  if(b.sampleVerified!==true)return fail(400,'Complete the sample ID step first.');
  if(typeof b.sampleImage!=='string'||b.sampleImage.length>2796204||!/^[A-Za-z0-9+/]+={0,2}$/.test(b.sampleImage))return fail(400,'Upload a PNG or JPG sample image up to 2 MB.');
  const picture=Buffer.from(b.sampleImage,'base64');const png=picture.length>=24&&picture.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex'))&&picture.subarray(12,16).toString()==='IHDR';const jpg=picture.length>=12&&picture[0]===255&&picture[1]===216&&picture[2]===255&&picture.at(-2)===255&&picture.at(-1)===217;
  if(!picture.length||picture.length>2097152||(!png&&!jpg))return fail(400,'Choose a valid PNG or JPG sample image up to 2 MB.');
  if(usernameTaken(s,username))return fail(409,'That username is already taken.');
  const cs=codes(new Set(s.users.flatMap(x=>[...x.codeHashes,...x.family.flatMap(f=>f.codeHashes||[])])));const user={id:id(),username,email,emailVerified:false,password:passwordHash(b.password),codeHashes:cs.map(codeHash),name:'',notify:true,family:[],lease:null,alerts:[],consents:[],created:now};s.users.push(user);
  const cookie=issue(user.id,'disclosure');s.sessions.at(-1).codesReadyAt=now+10000;return {cookie,body:{codes:cs,stage:'codes',verificationRequested:true,emailConfigured:emailReady()},mail:verificationMail(s,user,user)};
 }
 if(path==='login') {const username=String(b.username||'').toLowerCase();if(throttle('login:'+digest(username)))return fail(429,'Too many attempts. Try again in 15 minutes.');let found=s.users.find(x=>x.username===username),mini=null;if(!found){found=s.users.find(x=>x.family.some(f=>f.username===username));mini=found?.family.find(f=>f.username===username);}const account=mini||found;const h=account?.password||passwordHash('constant-dummy-password');if(typeof b.password!=='string'||b.password.length>128||!passwordMatches(b.password,h)||!account?.password)return fail(401,'Username or password is incorrect.');return {cookie:issue(found.id,'code',mini?.id),body:{stage:'code'}};}
 if(path==='code') {if(!u||(session.member&&!member)||session.stage!=='code')return fail(401,'Sign in first.');if(throttle('code:'+actor.id))return fail(429,'Too many code attempts. Try again in 15 minutes.');if(typeof b.code!=='string'||!/^[A-Za-z0-9]{12}$/.test(b.code.replace(/[ -]/g,''))||!actor.codeHashes.some(x=>equal(x,codeHash(b.code))))return fail(401,'That code does not match. Codes are case sensitive.');session.stage='disclosure';return {body:{stage:'disclosure'}};}
 if(path==='codes-saved'){if(!u||(session.member&&!member)||session.stage!=='disclosure')return fail(401,'Sign in first.');if(now<(session.codesReadyAt||0))return fail(409,'Please wait ten seconds and save your backup codes.');return {body:{stage:'disclosure'}};}
 if(path==='consent') {if(!u||(session.member&&!member)||session.stage!=='disclosure')return fail(401,'Sign in first.');if(now<(session.codesReadyAt||0))return fail(409,'Please wait ten seconds and save your backup codes.');if(b.privacy!==true||b.terms!==true||typeof b.signature!=='string'||b.signature.trim().length<2||b.signature.length>100)return fail(400,'Read both sections, check both boxes and sign your name.');actor.consents??=[];actor.consents.push({at:now,version:'2026-11-demo-v2',signature:b.signature.trim()});actor.consents=actor.consents.slice(-20);session.stage='ready';return {body:{user:view(u,session)}};}
 if(path==='logout'){s.sessions=s.sessions.filter(x=>x.hash!==digest(token||''));return {cookie:'',body:{ok:true}};}
 if(path==='me'){if(!u||(session.member&&!member))return fail(401,'Sign in to continue.');return {body:{stage:session.stage,user:auth()?view(u,session):undefined}};}
 if(path==='admin-login') {if(throttle('admin'))return fail(429,'Too many administrator attempts. Try again later.');if(!process.env.ADMIN_SECRET||!equal(b.secret,process.env.ADMIN_SECRET))return fail(401,'Administrator password is incorrect.');return {cookie:issue(null,'admin'),body:{ok:true}};}
 if(path.startsWith('admin-')) {
  if(session?.stage!=='admin')return fail(403,'Administrator access required.');
  if(path==='admin-state')return {body:{users:s.users.length,leases:s.users.filter(x=>x.lease).length,lastBackup:s.lastBackup,backups:s.backups.map(x=>({id:x.id,owner:digest(x.owner).slice(0,10),at:x.at,ciphertext:x.box.data,iv:x.box.iv})),households:s.users.map(x=>({reference:digest(x.id).slice(0,10),lease:x.lease?.id||null})),notice:'Ciphertext snapshots only. No encryption keys, passwords or backup codes are displayed.'}};
  if(path==='admin-backup'){backup(s,true);return {body:{ok:true}};}
  if(path==='admin-incident'){const target=s.users.find(x=>digest(x.id).slice(0,10)===b.reference);if(!target?.lease)return fail(404,'Choose a household with a temporary profile.');target.lease.active=false;target.selfActive=false;target.family.forEach(f=>f.active=false);target.lease.incident=true;target.alerts.push({at:now,text:'Demo incident reported by the operator. Your temporary profile has been paused. Delete it to remove its stored data.',demo:true});target.alerts=target.alerts.slice(-10);return {body:{ok:true}};}
  if(path==='admin-purge'){const cutoff=Date.parse(b.before);if(!Number.isFinite(cutoff)||cutoff>now||b.confirm!=='Delete selected backups')return fail(400,'Choose a past cutoff time and type the confirmation phrase.');const count=s.backups.length;s.backups=s.backups.filter(x=>x.at>cutoff);return {body:{deleted:count-s.backups.length}};}
  return fail(404,'Unknown administrator operation.');
 }
 if(!auth())return fail(401,'Complete sign-in and disclosure first.');
 if(member&&['family-add','family-toggle','family-remove','lease-delete','delete-start','account-delete'].includes(path))return fail(403,'Only the main account can manage the household or delete its shared data.');
 if(path==='email-send-verification'){if(!actor.email)return fail(400,'Add an email address to your account first.');if(actor.emailVerified)return {body:{ok:true,message:'Your email is already verified.'}};if(!emailReady())return fail(503,'Email service is not configured yet.');if(throttle('verify:'+actor.id,3))return fail(429,'Too many verification requests. Try again in 15 minutes.');return {body:{ok:true,message:'Verification email requested.'},mail:verificationMail(s,u,actor)};}
 if(path==='email-add'){if(throttle('email-add:'+actor.id,3))return fail(429,'Too many email changes. Try again in 15 minutes.');if(!validEmail(normalizeEmail(b.email)))return fail(400,'Enter a valid email address.');if(actor.emailVerified)return fail(409,'Your verified recovery email cannot be changed in this version.');if(typeof b.password!=='string'||b.password.length>128||!passwordMatches(b.password,actor.password))return fail(401,'Enter your current password to add your recovery email.');actor.email=normalizeEmail(b.email);actor.emailVerified=false;s.recovery=s.recovery.filter(x=>x.actorId!==actor.id);s.backups=s.backups.filter(x=>x.owner!==u.id);return {body:{user:view(u,session),emailConfigured:emailReady()},mail:verificationMail(s,u,actor)};}
 if(path==='family-codes-saved'){if(member)return fail(403,'Main account access required.');if(!session.familyCodesReadyAt||now<session.familyCodesReadyAt)return fail(409,'Please wait ten seconds and save the mini-user backup codes.');return {body:{ok:true}};}
 if(path==='profile'){if(typeof b.name!=='string'||b.name.length>60||typeof b.notify!=='boolean')return fail(400,'Enter a display name up to 60 characters.');actor.name=b.name.trim();actor.notify=b.notify;return {body:{user:view(u,session)}};}
 if(path==='family-add'){
  const existing=b.id?u.family.find(f=>f.id===b.id):null;if(b.id&&!existing)return fail(404,'Mini user not found in your household.');if(existing?.password)return fail(409,'This mini user already has a login.');
  if(!existing&&u.family.length>=8)return fail(400,'A household can have up to eight mini users.');
  if(typeof b.name!=='string'||!b.name.trim()||b.name.length>40)return fail(400,'Enter a name up to 40 characters.');
  const username=String(b.username||'').toLowerCase();if(!/^[a-z0-9_]{3,24}$/.test(username))return fail(400,'Use 3–24 letters, numbers or underscores for the mini-user username.');
  if(typeof b.password!=='string'||b.password.length<12||b.password.length>128||b.password!==b.confirm)return fail(400,'Use matching passwords with 12–128 characters.');
  if(usernameTaken(s,username))return fail(409,'That username is already taken.');
  const cs=codes(new Set(s.users.flatMap(x=>[...x.codeHashes,...x.family.flatMap(f=>f.codeHashes||[])])));
  const email=normalizeEmail(b.email);if(!validEmail(email))return fail(400,'Enter a valid recovery email for this family account.');
  const credentials={name:b.name.trim(),username,email,emailVerified:false,password:passwordHash(b.password),codeHashes:cs.map(codeHash),notify:true,consents:[]};if(existing){Object.assign(existing,credentials);s.backups=s.backups.filter(x=>x.owner!==u.id);}else u.family.push({id:id(),...credentials,active:false});
  session.familyCodesReadyAt=now+10000;const created=existing||u.family.at(-1);return {body:{user:view(u,session),codes:cs,stage:'codes',familyCreated:true,emailConfigured:emailReady()},mail:verificationMail(s,u,created)};
 }
 if(path==='family-toggle'){const f=u.family.find(x=>x.id===b.id);if(!f)return fail(404,'Mini user not found.');if(!u.lease)return fail(400,'Create the household temporary profile first.');if(u.lease.incident)return fail(409,'Delete the flagged temporary profile first.');f.active=!f.active;syncLease(u);return {body:{user:view(u,session)}};}
 if(path==='family-remove'){const removed=u.family.find(x=>x.id===b.id);if(!removed)return fail(404,'Mini user not found.');u.family=u.family.filter(x=>x.id!==b.id);s.sessions=s.sessions.filter(x=>!(x.user===u.id&&x.member===b.id));s.backups=s.backups.filter(x=>x.owner!==u.id);s.recovery=s.recovery.filter(x=>x.actorId!==removed.id);if(removed.username)delete s.limits['login:'+digest(removed.username)];delete s.limits['code:'+removed.id];syncLease(u);return {body:{user:view(u,session)}};}
 if(path==='connect'){
  if(process.env.DEMO_MODE!=='true')return fail(503,'Native VPN client and gateway are not connected. No tunnel has been created.');
  if(!['Auto','United States','Germany','Singapore'].includes(b.location))return fail(400,'Choose a supported location.');if(u.lease?.incident)return fail(409,'Delete the flagged temporary profile before starting again.');
  const region=b.location==='Auto'?'United States':b.location;
  if(u.lease?.active&&u.lease.location!==region)return fail(409,'Your family is using this location. Choose the shared location or wait until everyone is off.');
  u.lease??={id:id(),created:now,ip:'192.0.2.42',mode:'simulation'};u.lease.location=region;
  if(member)member.active=!member.active;else u.selfActive=!u.selfActive;syncLease(u);return {body:{user:view(u,session)}};
 }
 if(path==='disconnect'){if(member)member.active=false;else u.selfActive=false;syncLease(u);return {body:{user:view(u,session)}};}
 if(path==='lease-delete'){u.lease=null;u.selfActive=false;u.family.forEach(x=>x.active=false);u.alerts=[];s.backups=s.backups.filter(x=>x.owner!==u.id);return {body:{user:view(u,session)}};}
 if(path==='delete-start'){session.deleteAfter=now+2000;return {body:{readyAt:session.deleteAfter}};}
 if(path==='account-delete'){if(b.confirm!=='Delete my account and information'||!session.deleteAfter||now<session.deleteAfter)return fail(400,'Type the exact phrase and wait two seconds.');s.users=s.users.filter(x=>x.id!==u.id);s.recovery=s.recovery.filter(x=>x.owner!==u.id);s.sessions=s.sessions.filter(x=>x.user!==u.id);s.backups=s.backups.filter(x=>x.owner!==u.id);for(const account of [u,...u.family]){if(account.username)delete s.limits['login:'+digest(account.username)];delete s.limits['code:'+account.id];}return {cookie:'',body:{ok:true}};}
 if(path==='screen'){if(typeof b.url!=='string'||b.url.length>2048)return fail(400,'Enter an address under 2,048 characters.');return {body:screen(b.url)};}
 return fail(404,'Unknown operation.');
}
export default async function handler(req,res) {
 const requestStarted=Date.now();
 res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 const send=(status,body)=>{res.statusCode=status;res.end(JSON.stringify(body));};
 try {
  if(!/^[0-9a-fA-F]{64}$/.test(process.env.ENCRYPTION_KEY||'')||!process.env.CODE_PEPPER)return send(503,{error:'Server secrets are missing. Run node setup.js locally, or set deployment environment variables.'});
  const url=new URL(req.url,'http://local');const path=url.searchParams.get('action')||url.pathname.split('/').pop();
  if(req.method==='POST') {const origin=req.headers.origin;const host=req.headers['x-forwarded-host']||req.headers.host;if(origin&&new URL(origin).host!==host)return send(403,{error:'Request origin is not allowed.'});if(!req.headers['content-type']?.startsWith('application/json'))return send(415,{error:'Send JSON.'});}
  let b=req.body;if(typeof b==='string')b=JSON.parse(b);if(!b){let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>3000000)return send(413,{error:'Request too large.'});}b=raw?JSON.parse(raw):{};}if(!b||typeof b!=='object'||Array.isArray(b))return send(400,{error:'Invalid request.'});
  const token=path==='cron'?req.headers.authorization?.replace(/^Bearer /,''):(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('cyber_session='))?.slice(14);
  const result=await transact(s=>dispatch(s,path,b,token,req.method));
  if(result.mail){try{await sendEmail(result.mail);result.body.emailSent=true;}catch{console.error('Email delivery failed; check provider settings.');result.body.emailSent=false;}if(path==='recovery-request')delete result.body.emailSent;}
  if(path==='recovery-request'&&result.status!==503){const remaining=9000-(Date.now()-requestStarted);if(remaining>0)await new Promise(resolve=>setTimeout(resolve,remaining));}
  if(result.cookie!==undefined)res.setHeader('Set-Cookie',`cyber_session=${result.cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${result.cookie?3600:0}${process.env.VERCEL?'; Secure':''}`);
  send(result.status||200,result.body);
 }catch(e){if(e instanceof SyntaxError)return send(400,{error:'Invalid JSON.'});console.error('Request failed:',e.code||e.name);send(500,{error:'The server could not complete this request. Check server configuration and try again.'});}
}
