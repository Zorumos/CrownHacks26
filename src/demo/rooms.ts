import { randomBytes } from 'node:crypto';
import { AppError,assert,fail } from '../errors.ts';
import { decrypt,encrypt,equal,hash,id,token } from '../crypto.ts';
import type { Envelope } from '../crypto.ts';
import { SharedLimiter } from '../store.ts';
import type { AtomicStore } from '../store.ts';

export interface Member { expiresAt:number; connectedUntil:number }
export interface Room {
  id:string; generation:number; version:number; createdAt:number; expiresAt:number;
  presenterHash:string; panic:boolean; panickedAt:number|null; sessions:Record<string,Member>;
  payloadMode:'fixed'|'count'; epoch:number; key:string|null; envelope:Envelope|null;
  payloadHash:string|null; rotatedAt:number|null;
}
export const ROOM_TTL=30*60*1000;
export const HEARTBEAT_TTL=15000;
export const SESSION_TTL=10*60*1000;
export const ROTATION_MS=3000;
const FIXED_PAYLOAD={kind:'synthetic-session-metadata',sampleDeviceCount:3,sampleState:'illustrative'};

export class Rooms {
  store:AtomicStore; clock:()=>number; origin:string; limiter:SharedLimiter;
  constructor(store:AtomicStore,origin:string,clock=Date.now){this.store=store;this.origin=origin;this.clock=clock;this.limiter=new SharedLimiter(store,clock);}
  roomKey(code:string){assert(/^[a-f0-9]{32}$/.test(code),404,'ROOM_NOT_FOUND','That room is not available.');return 'co:demo:room:'+code;}
  parse(raw:string):Room {
    try{
      assert(raw.length<100000,503,'STATE_INVALID','Room state is invalid.');
      const r=JSON.parse(raw);
      assert(r && typeof r.id==='string' && Number.isSafeInteger(r.generation) && Number.isSafeInteger(r.version) && Number.isFinite(r.expiresAt) && typeof r.presenterHash==='string' && typeof r.panic==='boolean' && r.sessions && !Array.isArray(r.sessions) && Object.keys(r.sessions).length<=64 && ['fixed','count'].includes(r.payloadMode),503,'STATE_INVALID','Room state is invalid.');
      assert(/^[a-f0-9]{32}$/.test(r.id) && r.generation>=1 && r.version>=1 && Number.isSafeInteger(r.createdAt) && Number.isSafeInteger(r.expiresAt) && r.expiresAt>r.createdAt && /^[a-f0-9]{64}$/.test(r.presenterHash) && Number.isSafeInteger(r.epoch) && r.epoch>=-1 && (r.key===null || (typeof r.key==='string' && /^[a-f0-9]{64}$/.test(r.key))) && (!r.panic || r.key===null),503,'STATE_INVALID','Room invariants are invalid.');
      if(r.envelope!==null)assert(r.envelope && typeof r.envelope.nonce==='string' && /^[a-f0-9]{24}$/.test(r.envelope.nonce) && typeof r.envelope.tag==='string' && /^[a-f0-9]{32}$/.test(r.envelope.tag) && typeof r.envelope.ciphertext==='string' && /^[a-f0-9]+$/.test(r.envelope.ciphertext) && r.envelope.ciphertext.length%2===0 && r.envelope.ciphertext.length<=4096 && typeof r.envelope.aad==='string',503,'STATE_INVALID','Encrypted room state is malformed.');
      for(const [key,s] of Object.entries(r.sessions) as [string,Member][])assert(/^[a-f0-9]{64}$/.test(key) && Number.isFinite(s.expiresAt) && Number.isFinite(s.connectedUntil),503,'STATE_INVALID','Session state is invalid.');
      return r;
    }catch(error){if(error instanceof AppError)throw error;fail(503,'STATE_INVALID','Room state could not be validated.');}
  }
  clean(room:Room,now:number){for(const [key,s] of Object.entries(room.sessions))if(s.expiresAt<=now)delete room.sessions[key];}
  active(room:Room,now:number){return room.panic?0:Object.values(room.sessions).filter(s=>s.expiresAt>now && s.connectedUntil>now).length;}
  rotation(room:Room,now:number){
    if(room.panic)return;
    const epoch=Math.floor((now-room.createdAt)/ROTATION_MS);
    if(epoch<=room.epoch)return;
    const payload=JSON.stringify(room.payloadMode==='fixed'?FIXED_PAYLOAD:{kind:'synthetic-session-metadata',activeSimulatedConnections:this.active(room,now)});
    const key=randomBytes(32);
    room.envelope=encrypt(payload,key,`${room.id}:${room.generation}:${epoch}`);
    room.key=key.toString('hex'); key.fill(0); // Best effort for this Buffer only; no zeroization guarantee.
    room.epoch=epoch;room.payloadHash=hash(payload);room.rotatedAt=now;
  }
  authorize(room:Room,credential:string,generation:number,role:'any'|'presenter'|'judge',now:number){
    assert(generation===room.generation,409,'GENERATION_CHANGED','The room was reset. Rejoin with the latest invitation.');
    const principal=hash(credential);
    if(equal(principal,room.presenterHash)){
      assert(role!=='judge',403,'JUDGE_REQUIRED','Use your own judge session.');return 'presenter';
    }
    assert(role!=='presenter',403,'PRESENTER_REQUIRED','Only the presenter can do that.');
    const member=room.sessions[principal];
    assert(member && member.expiresAt>now,401,'SESSION_EXPIRED','Your judge session expired. Rejoin the room.');
    return principal;
  }
  async change<T>(code:string,operation:(room:Room,now:number)=>T):Promise<{room:Room;result:T}> {
    const key=this.roomKey(code);
    for(let attempt=0;attempt<20;attempt++){
      const raw=await this.store.read(key);
      assert(raw,404,'ROOM_NOT_FOUND','This room expired or is unavailable.');
      const room=this.parse(raw),now=this.clock();
      assert(room.id===code,503,'STATE_INVALID','Room identity is inconsistent.');
      assert(room.expiresAt>now,410,'ROOM_EXPIRED','This demonstration room expired.');
      this.clean(room,now);
      const result=operation(room,now);
      room.version++;
      const ttl=Math.max(1,Math.ceil((room.expiresAt-this.clock())/1000));
      if(await this.store.compareAndSet(key,raw,JSON.stringify(room),ttl))return {room,result};
    }
    fail(503,'ROOM_BUSY','Several changes arrived together.','Retry shortly; do not assume your change succeeded.');
  }
  public(room:Room,now=this.clock()){
    return {mode:'shared_demo',simulation:true,protected:false,roomCode:room.id,generation:room.generation,version:room.version,
      expiresAt:room.expiresAt,observedAt:now,activeConnections:this.active(room,now),panic:room.panic,panickedAt:room.panickedAt,
      rotation:{epoch:room.epoch,intervalMs:ROTATION_MS,rotatedAt:room.rotatedAt,payloadMode:room.payloadMode,payloadHash:room.payloadHash,envelope:room.envelope,keyPresent:room.key!==null},
      limitations:['This demonstration does not route or protect your device traffic.','Rotation is request-driven, not an independent hourly worker.','Application-level key removal does not prove physical RAM erasure or deletion from backups.']};
  }
  async create(payloadMode:'fixed'|'count'='fixed'){
    await this.limiter.check('room-create',20,3600000);
    const now=this.clock(),code=id(),presenter=token();
    const room:Room={id:code,generation:1,version:1,createdAt:now,expiresAt:now+ROOM_TTL,presenterHash:hash(presenter),panic:false,panickedAt:null,sessions:{},payloadMode,epoch:-1,key:null,envelope:null,payloadHash:null,rotatedAt:null};
    this.rotation(room,now);
    assert(await this.store.create(this.roomKey(code),JSON.stringify(room),ROOM_TTL/1000),503,'CREATE_RETRY','Please create a new room.');
    return {presenterToken:presenter,joinUrl:`${this.origin}/join/${code}?generation=1`,state:this.public(room)};
  }
  async join(code:string,generation:number){
    this.roomKey(code);
    await this.limiter.check('join:'+code,120);
    const credential=token(),principal=hash(credential);
    const {room}=await this.change(code,(r,now)=>{
      assert(r.generation===generation,409,'GENERATION_CHANGED','This invitation is for an older room generation.');
      assert(Object.keys(r.sessions).length<64,409,'ROOM_FULL','This room has reached its session limit.');
      r.sessions[principal]={expiresAt:Math.min(now+SESSION_TTL,r.expiresAt),connectedUntil:0};
      this.rotation(r,now);
    });
    return {sessionToken:credential,state:this.public(room)};
  }
  async snapshot(code:string,credential:string,generation:number){
    await this.limiter.check('session:'+hash(credential),180);
    const {room}=await this.change(code,(r,now)=>{this.authorize(r,credential,generation,'any',now);this.rotation(r,now);});
    return this.public(room);
  }
  async connection(code:string,credential:string,generation:number,connected:boolean){
    await this.limiter.check('connect:'+hash(credential),60);
    const {room}=await this.change(code,(r,now)=>{
      const principal=this.authorize(r,credential,generation,'judge',now);
      assert(!r.panic,409,'PANIC_ACTIVE','This room is stopped. Ask the presenter to reset it.');
      r.sessions[principal].connectedUntil=connected?now+HEARTBEAT_TTL:0;
      r.sessions[principal].expiresAt=Math.min(now+SESSION_TTL,r.expiresAt);
      this.rotation(r,now);
    });return this.public(room);
  }
  async heartbeat(code:string,credential:string,generation:number){
    await this.limiter.check('heartbeat:'+hash(credential),90);
    const {room}=await this.change(code,(r,now)=>{
      const principal=this.authorize(r,credential,generation,'judge',now);
      assert(!r.panic,409,'PANIC_ACTIVE','This room is stopped.');
      // Never reconnect a session whose connection lease has already expired.
      if(r.sessions[principal].connectedUntil>now)r.sessions[principal].connectedUntil=now+HEARTBEAT_TTL;
      r.sessions[principal].expiresAt=Math.min(now+SESSION_TTL,r.expiresAt);
      this.rotation(r,now);
    });return this.public(room);
  }
  async panic(code:string,credential:string,generation:number,confirmed:boolean){
    await this.limiter.check('panic:'+hash(credential),30);
    assert(confirmed,422,'CONFIRM_REQUIRED','Confirm before stopping this demo room.');
    const {room}=await this.change(code,(r,now)=>{
      this.authorize(r,credential,generation,'any',now);
      if(!r.panic){r.panic=true;r.panickedAt=now;r.key=null;for(const s of Object.values(r.sessions))s.connectedUntil=0;}
    });return this.public(room);
  }
  async reset(code:string,credential:string,generation:number){
    await this.limiter.check('reset:'+hash(credential),10);
    const nextToken=token();
    const {room}=await this.change(code,(r,now)=>{
      this.authorize(r,credential,generation,'presenter',now);
      r.generation++;r.presenterHash=hash(nextToken);r.sessions={};r.panic=false;r.panickedAt=null;
      r.createdAt=now;r.epoch=-1;r.key=null;r.envelope=null;this.rotation(r,now);
    });
    return {presenterToken:nextToken,joinUrl:`${this.origin}/join/${code}?generation=${room.generation}`,state:this.public(room)};
  }
  async proof(code:string,credential:string,generation:number){
    const {room}=await this.change(code,(r,now)=>{this.authorize(r,credential,generation,'presenter',now);assert(!r.panic && r.key && r.envelope,410,'KEY_REMOVED','The current application-managed demonstration key is unavailable.');});
    const payload=decrypt(room.envelope!,Buffer.from(room.key!,'hex'));
    return {synthetic:true,payload:JSON.parse(payload),payloadHash:hash(payload),generation:room.generation,epoch:room.epoch};
  }
}
