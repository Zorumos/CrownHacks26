import { AppError, fail } from './errors.ts';
import type { Config } from './config.ts';

export interface AtomicStore {
  read(key: string): Promise<string|null>;
  create(key: string,value: string,ttlSeconds: number): Promise<boolean>;
  compareAndSet(key: string,expected: string,value: string,ttlSeconds: number): Promise<boolean>;
}
export const CAS_LUA = `local old=redis.call('GET',KEYS[1])
if old ~= ARGV[1] then return 0 end
redis.call('SET',KEYS[1],ARGV[2],'EX',ARGV[3])
return 1`;

export class RedisStore implements AtomicStore {
  client: any;
  constructor(client: any){this.client=client;}
  static async open(config: Config): Promise<RedisStore> {
    if(!config.redisUrl || !config.redisToken) fail(503,'SHARED_STORAGE_REQUIRED',config.production?'Shared rooms require configured Redis credentials.':'Local preview: changes are limited to this browser. Cross-device synchronization requires Redis.','Configure Upstash or use the browser-only preview.');
    if(new URL(config.redisUrl).protocol!=='https:')fail(500,'BAD_CONFIG','Redis REST URL must use HTTPS.');
    const { Redis }=await import('@upstash/redis');
    return new RedisStore(new Redis({url:config.redisUrl,token:config.redisToken,automaticDeserialization:false,retry:{retries:0}}));
  }
  async safe<T>(operation:()=>Promise<T>): Promise<T> {
    try{return await operation();}catch(error){
      if(error instanceof AppError)throw error;
      fail(503,'SHARED_STORAGE_UNAVAILABLE','Shared state could not be confirmed.','Wait and retry. Do not assume other screens received this change.');
    }
  }
  async read(key: string){return this.safe(async()=>{const result=await this.client.get(key);return result===null?null:String(result);});}
  async create(key: string,value: string,ttlSeconds: number){return this.safe(async()=>(await this.client.set(key,value,{nx:true,ex:ttlSeconds}))==='OK');}
  async compareAndSet(key: string,expected: string,value: string,ttlSeconds: number){
    return this.safe(async()=>Number(await this.client.eval(CAS_LUA,[key],[expected,value,String(ttlSeconds)]))===1);
  }
}

export class SharedLimiter {
  store: AtomicStore; clock: ()=>number;
  constructor(store: AtomicStore,clock=Date.now){this.store=store;this.clock=clock;}
  async check(scope: string,limit: number,windowMs=60000): Promise<void> {
    const now=this.clock(),bucket=Math.floor(now/windowMs),key=`co:rate:${scope}:${bucket}`;
    for(let attempt=0;attempt<16;attempt++){
      const old=await this.store.read(key);
      const count=old===null?0:Number(old);
      if(!Number.isSafeInteger(count) || count<0)fail(503,'STATE_INVALID','The rate-limit state is invalid.');
      if(count>=limit)fail(429,'RATE_LIMIT','Too many requests.','Wait before trying again.');
      const changed=old===null?await this.store.create(key,'1',Math.ceil(windowMs/1000)+1):await this.store.compareAndSet(key,old,String(count+1),Math.ceil(windowMs/1000)+1);
      if(changed)return;
    }
    fail(503,'STATE_BUSY','The shared state is busy.','Retry with a short delay.');
  }
}
