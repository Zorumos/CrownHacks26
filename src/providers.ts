// Extension contracts, not implemented provider integrations. No IDs are accepted by the current API.
export interface IdentityProvider {
  begin(accountReference:string):Promise<{redirectUrl:string;reference:string}>;
  verifyCallback(rawBody:Uint8Array,headers:Headers):Promise<{reference:string;verified:boolean;expiresAt:number}>;
  removeProviderData(reference:string):Promise<void>;
}
export interface AliasProvider {
  create(input:{ownerReference:string;expiresAt:number}):Promise<{reference:string;address:string}>;
  revoke(reference:string):Promise<void>;
}
export interface NativeProtectionEvidence {
  // These are a contract for a separately authenticated native integration.
  // No route accepts arbitrary browser booleans as proof in this implementation.
  observedAt:number;
  routeCheck:'passed'|'failed'|'unknown';
  dnsCheck:'passed'|'failed'|'unknown';
  ipv6Check:'passed'|'failed'|'unknown';
  killSwitchCheck:'passed'|'failed'|'unknown';
}
