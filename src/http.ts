import { AppError,assert,bool,fail,integer,object,text } from './errors.ts';
import { equal } from './crypto.ts';
import { loadConfig } from './config.ts';
import { disclosure } from './accounts/disclosure.ts';
import { getAccounts,getRooms,getVPN } from './runtime.ts';

export function bearer(request:Request){const [scheme,credential,...rest]=(request.headers.get('authorization')??'').split(' ');assert(scheme?.toLowerCase()==='bearer' && credential?.length>=20 && credential.length<=100 && rest.length===0,401,'TOKEN_REQUIRED','Provide your private bearer token.');return credential;}
async function json(request:Request){
  if(!request.body)return {};
  const declared=Number(request.headers.get('content-length')??0);assert(!Number.isFinite(declared) || declared<=16384,413,'BODY_TOO_LARGE','The request is too large.');
  const reader=request.body.getReader();const chunks:Uint8Array[]=[];let size=0;
  while(true){const next=await reader.read();if(next.done)break;size+=next.value.length;if(size>16384){await reader.cancel();fail(413,'BODY_TOO_LARGE','The request is too large.');}chunks.push(next.value);}
  if(size===0)return {};
  assert(request.headers.get('content-type')?.split(';')[0]==='application/json',415,'JSON_REQUIRED','Send JSON with the appropriate content type.');
  try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail(422,'INVALID_JSON','The JSON could not be read.');}
}
const consentKeys=['name','signature','agreed','disclosureVersion','documentHash'];
const sensitiveKeys=['password','code'];

export async function handle(request:Request):Promise<Response>{
  const headers=new Headers({'cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'});
  try{
    const config=loadConfig();const url=new URL(request.url),path=url.pathname.replace(/^\/api\/?/,'').split('/').filter(Boolean),method=request.method;
    if(['POST','PUT','PATCH','DELETE'].includes(method)){
      const origin=request.headers.get('origin');assert(!origin || origin===config.origin,403,'ORIGIN_REJECTED','Use the configured app origin.');
    }
    const body=['POST','PUT','PATCH','DELETE'].includes(method)?await json(request):{};
    let result:unknown;
    if(method==='GET' && path.join('/')==='health')result={service:'ok',deviceProtection:'not_verified'};
    else if(method==='GET' && path.join('/')==='config')result={demoMode:config.redisUrl && config.redisToken?'shared':config.production?'setup_required':'local_preview',localPreviewMessage:'Local preview: changes are limited to this browser. Cross-device synchronization requires Redis.',nativeClientRequired:true,identityVerification:false,passkeys:false,emailAliases:false};
    else if(method==='GET' && path.join('/')==='disclosure')result=disclosure(config);
    else if(path[0]==='demo'){
      const rooms=await getRooms();
      if(method==='POST' && path.join('/')==='demo/rooms'){
        assert(config.createSecret.length>=32 && equal(bearer(request),config.createSecret),403,'CREATOR_REQUIRED','Room creation requires the private operator creation credential.');
        const input=object(body,['payloadMode']);const mode=input.payloadMode??'fixed';assert(mode==='fixed' || mode==='count',422,'INVALID_MODE','Use fixed or count payload mode.');result=await rooms.create(mode);
      }else{
        assert(path[1]==='rooms' && path[2],404,'NOT_FOUND','API route not found.');
        const code=path[2],action=path[3]??'state';
        if(method==='POST' && action==='join'){
          const input=object(body,['generation']);result=await rooms.join(code,integer(input.generation));
        }else{
          const credential=bearer(request);
          if(method==='GET' && action==='state')result=await rooms.snapshot(code,credential,integer(Number(url.searchParams.get('generation'))));
          else if(method==='POST' && action==='connection'){const input=object(body,['generation','connected']);result=await rooms.connection(code,credential,integer(input.generation),bool(input.connected));}
          else if(method==='POST' && action==='heartbeat'){const input=object(body,['generation']);result=await rooms.heartbeat(code,credential,integer(input.generation));}
          else if(method==='POST' && action==='panic'){const input=object(body,['generation','confirmed']);result=await rooms.panic(code,credential,integer(input.generation),bool(input.confirmed));}
          else if(method==='POST' && action==='reset'){const input=object(body,['generation']);result=await rooms.reset(code,credential,integer(input.generation));}
          else if(method==='GET' && action==='proof')result=await rooms.proof(code,credential,integer(Number(url.searchParams.get('generation'))));
          else fail(404,'NOT_FOUND','API route not found.');
        }
      }
    }else{
      const accounts=await getAccounts();const route=path.join('/');
      if(method==='POST' && route==='auth/register')result=await accounts.register(object(body,['username','password','invitation',...consentKeys]));
      else if(method==='POST' && route==='auth/login')result=await accounts.login(object(body,['username','password','code']));
      else if(route.startsWith('auth/passkeys'))fail(501,'PASSKEYS_NOT_INTEGRATED','Passkeys are not integrated in this backend. Use the authenticator flow.');
      else{
        const credential=bearer(request);
        if(method==='GET' && route==='auth/mfa/setup')result=await accounts.setup(await accounts.auth(credential,false,false));
        else if(method==='POST' && route==='auth/mfa/confirm'){const input=object(body,['code']);result=await accounts.confirm(await accounts.auth(credential,false,false),text(input.code,6,6));}
        else if(method==='POST' && route==='auth/logout')result=await accounts.logout(await accounts.auth(credential,false,false,true));
        else if(method==='POST' && route==='auth/mfa/reset')result=await accounts.resetMfa(await accounts.auth(credential,true,false),object(body,sensitiveKeys));
        else if(method==='POST' && route==='consent')result=await accounts.renew(await accounts.auth(credential,false,false),object(body,consentKeys));
        else if(method==='GET' && route==='me'){const a=await accounts.auth(credential,false,false);result={id:a.id,username:a.username,mainAccount:!a.owner_id,mfaEnabled:Boolean(a.mfa),identityVerified:false};}
        else if(method==='POST' && route==='family/invites'){object(body,[]);result=await accounts.invite(await accounts.auth(credential));}
        else if(method==='GET' && route==='family')result=await accounts.family(await accounts.auth(credential));
        else if(method==='DELETE' && route==='account')result=await(await getVPN()).deleteAccounts(await accounts.auth(credential,true,false,true),object(body,sensitiveKeys));
        else if(method==='DELETE' && path[0]==='family' && path.length===2)result=await(await getVPN()).deleteAccounts(await accounts.auth(credential,true,false),object(body,sensitiveKeys),path[1]);
        else if(path[0]==='aliases'){await accounts.auth(credential);fail(501,'ALIAS_PROVIDER_NOT_INTEGRATED','Email aliases require a separately configured provider. No external accounts or identities were created.');}
        else if(path[0]==='identity'){await accounts.auth(credential,false,false);fail(501,'IDENTITY_NOT_INTEGRATED','No identity provider is integrated. Do not upload an ID.');}
        else if(method==='GET' && route==='servers'){await accounts.auth(credential);result=(await getVPN()).listServers();}
        else if(method==='GET' && route==='devices')result=await(await getVPN()).listDevices(await accounts.auth(credential));
        else if(method==='POST' && route==='devices')result=await(await getVPN()).addDevice(await accounts.auth(credential),object(body,['label','publicKey']));
        else if(method==='DELETE' && path[0]==='devices' && path.length===2)result=await(await getVPN()).deleteDevice(await accounts.auth(credential,true,false),path[1]);
        else if(method==='POST' && route==='connections'){
          const input=object(body,['deviceId','serverId','adblock']);
          result=await(await getVPN()).connect(await accounts.auth(credential),text(input.deviceId,32,32),input.serverId===undefined?'auto':text(input.serverId,1,40),input.adblock===undefined?true:bool(input.adblock));
        }else if(method==='GET' && path[0]==='connections' && path.length===2)result=await(await getVPN()).status(await accounts.auth(credential),path[1]);
        else if(method==='DELETE' && path[0]==='connections' && path.length===2)result=await(await getVPN()).disconnect(await accounts.auth(credential,true,false),path[1]);
        else fail(404,'NOT_FOUND','API route not found.');
      }
    }
    return Response.json(result,{headers});
  }catch(error){
    if(error instanceof AppError){if(error.status===429)headers.set('retry-after','60');return Response.json({error:{code:error.code,message:error.message,action:error.action,retryable:error.retryable,severity:'warning'}},{status:error.status,headers});}
    return Response.json({error:{code:'INTERNAL_ERROR',message:'The operation could not be completed.',action:'Retry or contact the operator. No successful protection is claimed.',retryable:false}},{status:500,headers});
  }
}
