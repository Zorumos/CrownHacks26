// Browser-only adapter. No server store, localStorage, network calls or cross-device claims.
export class LocalPreview {
  generation=1;version=0;panicActive=false;connected=false;epoch=-1;createdAt=Date.now();
  key:CryptoKey|null=null;envelope:Record<string,string>|null=null;clock:()=>number;
  constructor(clock=Date.now){this.clock=clock;this.createdAt=clock();}
  async refresh(){
    const epoch=Math.floor((this.clock()-this.createdAt)/3000);
    if(!this.panicActive && epoch>this.epoch){
      const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
      const nonce=crypto.getRandomValues(new Uint8Array(12)),aad=new TextEncoder().encode('local-preview:'+this.generation+':'+epoch);
      const plaintext=new TextEncoder().encode(JSON.stringify({kind:'synthetic-session-metadata',sampleDeviceCount:3,sampleState:'illustrative'}));
      const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,plaintext));
      // Panic/reset may happen while WebCrypto is pending. Check generation and state again.
      if(!this.panicActive && new TextDecoder().decode(aad).startsWith('local-preview:'+this.generation+':') && epoch>this.epoch){
        const hex=(value:Uint8Array)=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
        this.key=key;this.envelope={nonce:hex(nonce),ciphertext:hex(encrypted.slice(0,-16)),tag:hex(encrypted.slice(-16)),aad:new TextDecoder().decode(aad)};this.epoch=epoch;this.version++;
      }
    }return this.snapshot();
  }
  snapshot(){return {mode:'local_preview',simulation:true,protected:false,generation:this.generation,version:this.version,panic:this.panicActive,activeConnections:this.connected&&!this.panicActive?1:0,rotation:{epoch:this.epoch,envelope:this.envelope,keyPresent:this.key!==null},message:'Local preview: changes are limited to this browser. Cross-device synchronization requires Redis.'};}
  async connection(value:boolean){if(this.panicActive)throw new Error('This local preview is stopped. Reset it first.');this.connected=value;this.version++;return this.refresh();}
  panic(){this.panicActive=true;this.connected=false;this.key=null;this.version++;return this.snapshot();}
  async reset(){this.generation++;this.version++;this.createdAt=this.clock();this.panicActive=false;this.connected=false;this.key=null;this.envelope=null;this.epoch=-1;return this.refresh();}
}
