import {id,digest,equal,passwordMatches,passwordHash,codes,codeHash} from './security.js';
import {emailBase,emailReady} from './email.js';
export const normalizeEmail=x=>typeof x==='string'?x.trim().toLowerCase():'';
export const validEmail=x=>typeof x==='string'&&x.length<=254&&/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(x);
const actors=s=>s.users.flatMap(owner=>[{owner,actor:owner},...owner.family.filter(f=>f.password).map(actor=>({owner,actor,member:actor.id}))]);
export function pruneRecovery(s){s.recovery=(s.recovery||[]).filter(r=>r.expires>Date.now()&&actors(s).some(x=>x.actor.id===r.actorId));}
export function verificationMail(s,owner,actor){if(!emailReady())return null;const raw=id();s.recovery??=[];s.recovery.push({hash:digest(raw),owner:owner.id,actorId:actor.id,email:actor.email,purpose:'verify',expires:Date.now()+1800000});return {to:actor.email,key:id(),subject:'Verify your Cyber One recovery email',text:`Verify the recovery email for your Cyber One account (${actor.username}).\n\n${emailBase()}/#verify-email=${raw}\n\nThis link expires in 30 minutes. Open it and press Verify email. If you did not request this, ignore it. This mailbox will be able to recover this account after verification.`};}
const fail=(status,message)=>({status,body:{error:message}});
export function recoveryAction(s,path,b,throttle){
 if(path==='verify-email'){
  if(typeof b.token!=='string'||b.token.length>128)return fail(400,'This verification link is invalid or has expired.');const record=s.recovery.find(r=>r.purpose==='verify'&&equal(r.hash,digest(b.token)));const target=record&&actors(s).find(x=>x.actor.id===record.actorId&&x.owner.id===record.owner);
  if(!record||!target||target.actor.email!==record.email)return fail(400,'This verification link is invalid or has expired.');target.actor.emailVerified=true;s.recovery=s.recovery.filter(r=>r.actorId!==target.actor.id);return {body:{ok:true}};
 }
 if(path==='recovery-request'){
  const email=normalizeEmail(b.email),purpose=b.purpose;if(!validEmail(email)||!['username','password','codes','all'].includes(purpose))return fail(400,'Enter your recovery email and choose what you need help with.');
  if(!emailReady())return fail(503,'Email recovery is not configured yet. Ask the operator to configure the email service.');
  const generic={body:{message:'If an eligible account matches, an email will arrive with your next steps. Check your inbox and spam folder.'}};
  if(throttle('recovery:'+digest(email),3)||throttle('recovery-global',100))return generic;
  const username=String(b.username||'').trim().toLowerCase();const matches=actors(s).filter(x=>x.actor.emailVerified&&x.actor.email===email&&(!username||x.actor.username===username));
  if(!matches.length)return generic;
  let text='You requested help with your Cyber One account.\n\n';
  if(purpose==='username')text+='Usernames linked to this verified email:\n'+matches.map(x=>x.actor.username).join('\n');
  else for(const {owner,actor} of matches){const raw=id();s.recovery.push({hash:digest(raw),owner:owner.id,actorId:actor.id,email,purpose,expires:Date.now()+900000});text+=`${actor.username}: ${emailBase()}/#recover=${raw}\n`;}
  text+='\nRecovery links expire in 15 minutes and work once. Ignore this email if you did not request it. Never share recovery links.';
  return {...generic,mail:{to:email,key:id(),subject:purpose==='username'?'Your Cyber One username reminder':'Recover your Cyber One account',text}};
 }
 if(path==='recovery-info'||path==='recovery-complete'){
  if(typeof b.token!=='string'||b.token.length>128)return fail(400,'This recovery link is invalid or has expired.');const r=s.recovery.find(x=>x.purpose!=='verify'&&equal(x.hash,digest(b.token)));const target=r&&actors(s).find(x=>x.actor.id===r.actorId&&x.owner.id===r.owner&&x.actor.email===r.email&&x.actor.emailVerified);
  if(!r||!target)return fail(400,'This recovery link is invalid or has expired. Request a new link.');
  if(path==='recovery-info')return {body:{purpose:r.purpose,username:target.actor.username}};
  const {actor,owner}=target;
  if(r.purpose==='codes'){if(throttle('recovery-code-password:'+actor.id,5))return fail(429,'Too many attempts. Try again later.');if(typeof b.password!=='string'||b.password.length>128||!passwordMatches(b.password,actor.password))return fail(401,'Enter your current password, or request recovery for both password and codes.');}
  if(['password','all'].includes(r.purpose)){if(typeof b.password!=='string'||b.password.length<12||b.password.length>128||b.password!==b.confirm)return fail(400,'Use matching passwords with 12–128 characters.');actor.password=passwordHash(b.password);}
  let replacement;
  if(['codes','all'].includes(r.purpose)){replacement=codes(new Set(actors(s).flatMap(x=>x.actor.codeHashes||[])));actor.codeHashes=replacement.map(codeHash);}
  if(actor.id===owner.id)owner.selfActive=false;else actor.active=false;if(owner.lease)owner.lease.active=!owner.lease.incident&&(!!owner.selfActive||owner.family.some(f=>f.active));
  s.sessions=s.sessions.filter(x=>!(x.user===owner.id&&(actor.id===owner.id?!x.member:x.member===actor.id)));
  s.recovery=s.recovery.filter(x=>x.actorId!==actor.id);s.backups=s.backups.filter(x=>x.owner!==owner.id);delete s.limits['login:'+digest(actor.username)];delete s.limits['code:'+actor.id];delete s.limits['recovery-code-password:'+actor.id];
  return {cookie:'',body:{ok:true,codes:replacement,username:actor.username,message:'Recovery complete. Sign in again with your credentials.'},mail:{to:actor.email,key:id(),subject:'Your Cyber One sign-in details changed',text:`The ${r.purpose==='password'?'password':r.purpose==='codes'?'backup codes':'password and backup codes'} for ${actor.username} were changed. Existing sessions and other recovery links for this account were revoked. If this was not you, secure your email account and contact the operator. No passwords or codes are included in this email.`}};
 }
 return null;
}
