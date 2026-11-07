import { randomBytes } from 'node:crypto';
import type { Config } from '../config.ts';
import type { Database,Query } from '../database.ts';
import { AppError,assert,fail,text } from '../errors.ts';
import { decrypt,encrypt,equal,hash,id,newTotpSecret,passwordHash,passwordValid,token,validTotp } from '../crypto.ts';
import { agreement,disclosure } from './disclosure.ts';

export type Account=Record<string,any>;
export class Accounts {
  db:Database; config:Config; clock:()=>number; dummy:Promise<string>;
  constructor(db:Database,config:Config,clock=Date.now){
    assert(/^[a-f0-9]{64}$/.test(config.masterKey),503,'MASTER_KEY_REQUIRED','Account encryption requires a configured master key. Run npm run setup locally.');
    this.db=db;this.config=config;this.clock=clock;this.dummy=passwordHash(token());
  }
  seal(value:string,aad:string){return JSON.stringify(encrypt(value,Buffer.from(this.config.masterKey,'hex'),aad));}
  open(value:string,aad:string){const box=JSON.parse(value);assert(box.aad===aad,503,'STATE_INVALID','Stored credential context is invalid.');return decrypt(box,Buffer.from(this.config.masterKey,'hex'));}
  async limit(scope:string,max=8,windowMs=60000){
    const now=this.clock();
    const result=await this.db.query(`INSERT INTO rate_windows(key,count,reset_at) VALUES($1,1,$2)
      ON CONFLICT(key) DO UPDATE SET count=CASE WHEN rate_windows.reset_at<=$3 THEN 1 ELSE rate_windows.count+1 END,
      reset_at=CASE WHEN rate_windows.reset_at<=$3 THEN $2 ELSE rate_windows.reset_at END RETURNING count`,[hash(scope),now+windowMs,now]);
    assert(Number(result.rows[0].count)<=max,429,'RATE_LIMIT','Too many attempts. Wait before trying again.');
  }
  async cleanup(){const now=this.clock();await this.db.query('DELETE FROM sessions WHERE expires_at<=$1',[now]);await this.db.query('DELETE FROM invites WHERE expires_at<=$1',[now]);await this.db.query('DELETE FROM rate_windows WHERE reset_at<=$1',[now]);}
  async session(db:Query,accountId:string,scope:'enroll'|'full'|'delete'){
    const credential=token(),expiresIn=scope==='full'?1800:600;
    await db.query('INSERT INTO sessions(hash,account_id,scope,expires_at) VALUES($1,$2,$3,$4)',[hash(credential),accountId,scope,this.clock()+expiresIn*1000]);
    return {accessToken:credential,tokenType:'Bearer',scope,expiresIn};
  }
  async auth(credential:string,full=true,requireCurrentConsent=true,allowDisabled=false):Promise<Account>{
    assert(credential.length>=20 && credential.length<=100,401,'SIGN_IN_REQUIRED','Sign in to continue.');
    const result=await this.db.query('SELECT a.*,s.scope,s.hash AS session_hash FROM accounts a JOIN sessions s ON a.id=s.account_id WHERE s.hash=$1 AND s.expires_at>$2',[hash(credential),this.clock()]);
    const account=result.rows[0];assert(account,401,'SESSION_EXPIRED','Your session expired. Sign in again.');
    assert(!account.disabled || allowDisabled,403,'DELETION_PENDING','This account is pending deletion. Retry deletion to confirm peer revocation.');
    if(full)assert((account.scope==='full' || (allowDisabled && account.scope==='delete')) && account.mfa===1,403,'MFA_REQUIRED','Finish authenticator setup first.');
    if(full && requireCurrentConsent){
      const receipt=(await this.db.query('SELECT version,document_hash FROM consents WHERE account_id=$1',[account.id])).rows[0];
      const current=disclosure(this.config);
      assert(receipt && receipt.version===current.version && receipt.document_hash===current.documentHash,403,'DISCLOSURE_CHANGED','Review and renew the current disclosure.');
    }return account;
  }
  async factor(db:Query,accountId:string,code:string,allowDisabled=false):Promise<boolean>{
    const account=(await db.query('SELECT * FROM accounts WHERE id=$1',[accountId])).rows[0];
    if(!account || (account.disabled && !allowDisabled))return false;
    const step=validTotp(this.open(account.totp_secret,'totp:'+accountId),code,Number(account.last_step),this.clock());
    if(step!==null){const changed=await db.query('UPDATE accounts SET last_step=$1 WHERE id=$2 AND last_step<$1',[step,accountId]);return changed.rowCount===1;}
    return (await db.query('DELETE FROM recovery_codes WHERE account_id=$1 AND hash=$2',[accountId,hash(code)])).rowCount===1;
  }
  async saveAgreement(db:Query,accountId:string,value:ReturnType<typeof agreement>){
    await db.query(`INSERT INTO consents(account_id,version,document_hash,name_attestation,accepted_at,receipt) VALUES($1,$2,$3,$4,$5,$6)
      ON CONFLICT(account_id) DO UPDATE SET version=excluded.version,document_hash=excluded.document_hash,name_attestation=excluded.name_attestation,accepted_at=excluded.accepted_at,receipt=excluded.receipt`,[accountId,value.version,value.documentHash,value.nameAttestation,value.acceptedAt,value.receipt]);
  }
  async register(input:Record<string,unknown>){
    await this.limit('register-global',30);
    const username=text(input.username,3,32);assert(/^[a-z0-9_]+$/.test(username),422,'INVALID_USERNAME','Use lowercase letters, numbers and underscores.');
    const password=text(input.password,12,128),accountId=id();
    const receipt=agreement(input,this.config,accountId,this.clock());
    assert(!this.config.requireIdentity,503,'IDENTITY_NOT_CONFIGURED','Registration is paused until identity verification is integrated.');
    const encoded=await passwordHash(password),secret=this.seal(newTotpSecret(),'totp:'+accountId);
    try {
      const result=await this.db.transaction(async db=>{
        let ownerId:string|null=null;
        if(input.invitation!==undefined && input.invitation!==null && input.invitation!==''){
          const invite=text(input.invitation,20,100);
          const consumed=await db.query('DELETE FROM invites WHERE hash=$1 AND expires_at>$2 RETURNING owner_id',[hash(invite),this.clock()]);
          assert(consumed.rows[0],400,'INVALID_INVITE','This invitation expired or was already used.');ownerId=consumed.rows[0].owner_id;
          // Serialize family reservations in PostgreSQL and SQLite with a write to the owner row.
          const owner=await db.query('UPDATE accounts SET created_at=created_at WHERE id=$1 AND disabled=0 AND owner_id IS NULL RETURNING id',[ownerId]);
          assert(owner.rows[0],400,'INVALID_INVITE','This invitation is unavailable.');
          const count=(await db.query('SELECT count(*) AS count FROM accounts WHERE owner_id=$1',[ownerId])).rows[0].count;
          assert(Number(count)<this.config.familyLimit,409,'FAMILY_FULL','No family slots remain.');
        }
        await db.query('INSERT INTO accounts(id,username,password_hash,owner_id,totp_secret,created_at) VALUES($1,$2,$3,$4,$5,$6)',[accountId,username,encoded,ownerId,secret,this.clock()]);
        await this.saveAgreement(db,accountId,receipt);
        return this.session(db,accountId,'enroll');
      });return {...result,agreement:{...receipt,nameAttestation:undefined},identityVerified:false};
    }catch(error:any){if(error instanceof AppError)throw error;if(error.code==='23505' || String(error.code).includes('SQLITE_CONSTRAINT'))fail(409,'REGISTRATION_UNAVAILABLE','This account could not be created. Choose another username or sign in.');throw error;}
  }
  async login(input:Record<string,unknown>){
    const username=text(input.username,1,32),password=text(input.password,1,128),code=input.code===undefined?'':text(input.code,0,100);
    await this.limit('login-global',120);await this.limit('login:'+username);
    const row=(await this.db.query('SELECT * FROM accounts WHERE username=$1',[username])).rows[0];
    const correct=await passwordValid(password,row?.password_hash??await this.dummy);
    assert(row && correct,401,'INVALID_CREDENTIALS','Sign-in details were not accepted.');
    return this.db.transaction(async db=>{
      if(!row.mfa)return this.session(db,row.id,'enroll');
      assert(await this.factor(db,row.id,code,Boolean(row.disabled)),401,'INVALID_CREDENTIALS','Use a fresh authenticator code or unused recovery code.');
      return this.session(db,row.id,row.disabled?'delete':'full');
    });
  }
  async setup(account:Account){
    assert(account.scope==='enroll' && !account.mfa,403,'ENROLLMENT_ONLY','Authenticator enrollment is unavailable for this session.');
    const secret=this.open(account.totp_secret,'totp:'+account.id);
    return {secret,uri:`otpauth://totp/CyberOne:${encodeURIComponent(account.username)}?secret=${secret}&issuer=CyberOne&digits=6&period=30`};
  }
  async confirm(account:Account,code:string){
    await this.limit('mfa:'+account.id);
    const recoveryCodes=Array.from({length:8},()=>randomBytes(10).toString('hex'));
    const result=await this.db.transaction(async db=>{
      const fresh=(await db.query('SELECT * FROM accounts WHERE id=$1',[account.id])).rows[0];
      assert(account.scope==='enroll' && fresh && !fresh.mfa,409,'ALREADY_ENROLLED','Authenticator setup is already complete.');
      assert(await this.factor(db,account.id,code),400,'INVALID_CODE','That code is invalid or already used. Wait for a fresh code.');
      await db.query('UPDATE accounts SET mfa=1 WHERE id=$1',[account.id]);
      for(const value of recoveryCodes)await db.query('INSERT INTO recovery_codes(hash,account_id) VALUES($1,$2)',[hash(value),account.id]);
      await db.query('DELETE FROM sessions WHERE account_id=$1',[account.id]);
      return this.session(db,account.id,'full');
    });return {...result,recoveryCodes,message:'Save these one-use recovery codes privately. They will not be shown again.'};
  }
  async logout(account:Account){await this.db.query('DELETE FROM sessions WHERE hash=$1',[account.session_hash]);return {signedOut:true,vpnDisconnected:false};}
  async reauthenticate(db:Query,account:Account,input:Record<string,unknown>,allowDisabled=false){
    const fresh=(await db.query('SELECT * FROM accounts WHERE id=$1',[account.id])).rows[0];
    assert(fresh && await passwordValid(text(input.password,1,128),fresh.password_hash) && await this.factor(db,account.id,text(input.code,6,100),allowDisabled),401,'REAUTH_REQUIRED','Confirm with your password and a fresh authenticator or recovery code.');
  }
  async resetMfa(account:Account,input:Record<string,unknown>){
    await this.limit('sensitive:'+account.id);
    return this.db.transaction(async db=>{
      await this.reauthenticate(db,account,input);
      await db.query('UPDATE accounts SET mfa=0,last_step=-1,totp_secret=$1 WHERE id=$2',[this.seal(newTotpSecret(),'totp:'+account.id),account.id]);
      await db.query('DELETE FROM sessions WHERE account_id=$1',[account.id]);await db.query('DELETE FROM recovery_codes WHERE account_id=$1',[account.id]);
      return this.session(db,account.id,'enroll');
    });
  }
  async renew(account:Account,input:Record<string,unknown>){const value=agreement(input,this.config,account.id,this.clock());await this.saveAgreement(this.db,account.id,value);return {...value,nameAttestation:undefined};}
  owner(account:Account){assert(!account.owner_id,403,'OWNER_REQUIRED','Only the main account can manage family membership.');}
  async invite(account:Account){
    this.owner(account);const credential=token();
    await this.db.transaction(async db=>{
      await db.query('UPDATE accounts SET created_at=created_at WHERE id=$1',[account.id]);
      const members=Number((await db.query('SELECT count(*) AS count FROM accounts WHERE owner_id=$1',[account.id])).rows[0].count);
      const invites=Number((await db.query('SELECT count(*) AS count FROM invites WHERE owner_id=$1 AND expires_at>$2',[account.id,this.clock()])).rows[0].count);
      assert(members+invites<this.config.familyLimit,409,'FAMILY_FULL','Family slots are occupied or reserved.');
      await db.query('INSERT INTO invites(hash,owner_id,expires_at) VALUES($1,$2,$3)',[hash(credential),account.id,this.clock()+3600000]);
    });return {invitation:credential,expiresIn:3600,message:'Share this one-use invitation privately. No message was sent.'};
  }
  async family(account:Account){this.owner(account);return {members:(await this.db.query('SELECT id,username FROM accounts WHERE owner_id=$1',[account.id])).rows};}
}
