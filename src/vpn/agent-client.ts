import { createHmac,randomBytes } from 'node:crypto';
import type { ServerConfig } from '../config.ts';
import { AppError,assert,fail,object } from '../errors.ts';
export interface Observation { publicKey:string; peerPresent:boolean; handshake:number|null }
export interface AgentClient { call(server:ServerConfig,operation:'health'|'status'|'provision'|'revoke',payload?:Record<string,unknown>):Promise<Observation> }
export class HTTPSAgent implements AgentClient {
  async call(server:ServerConfig,operation:'health'|'status'|'provision'|'revoke',payload:Record<string,unknown>={}):Promise<Observation>{
    const body=JSON.stringify({operation,...payload}),timestamp=String(Date.now()),nonce=randomBytes(24).toString('hex');
    const signature=createHmac('sha256',server.agentSecret).update(timestamp+'\n'+nonce+'\n'+body).digest('hex');
    try {
      const response=await fetch(server.agentUrl,{method:'POST',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/json','x-co-time':timestamp,'x-co-nonce':nonce,'x-co-signature':signature},body});
      assert(response.ok,503,'AGENT_UNAVAILABLE','The VPN management service did not confirm this operation.');
      const reader=response.body?.getReader();assert(reader,503,'AGENT_INVALID','The VPN service returned no evidence.');
      let size=0;const chunks:Uint8Array[]=[];
      while(true){const item=await reader.read();if(item.done)break;size+=item.value.length;if(size>4096){await reader.cancel();fail(503,'AGENT_INVALID','The VPN evidence exceeded its size limit.');}chunks.push(item.value);}
      const raw=Buffer.concat(chunks).toString('utf8');
      const data=object(JSON.parse(raw),['publicKey','peerPresent','handshake']);
      assert(data.publicKey===server.publicKey && typeof data.peerPresent==='boolean' && (data.handshake===null || (typeof data.handshake==='number' && Number.isSafeInteger(data.handshake) && data.handshake>=0 && data.handshake<=Date.now()+5000)),503,'AGENT_INVALID','The VPN evidence could not be validated.');
      return data as unknown as Observation;
    }catch(error){if(error instanceof AppError && error.status===503)throw error;fail(503,'AGENT_UNAVAILABLE','VPN server state could not be confirmed.','Retry or contact the operator. No protection is claimed.');}
  }
}
