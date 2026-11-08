// Log bounded classifications only. Never log database URLs, query parameters,
// raw provider messages, encrypted records, passwords, or recovery links.
export class StoreFault extends Error {
 constructor(code,stage,cause){super('Storage operation failed');this.name='StoreFault';this.code=code;this.stage=stage;this.detail=safeDetail(cause?.code);}
}
function safeDetail(code){const allowed=new Set(['ENOTFOUND','ECONNREFUSED','ECONNRESET','ETIMEDOUT','ERR_MODULE_NOT_FOUND','ERR_TLS_CERT_ALTNAME_INVALID','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','DEPTH_ZERO_SELF_SIGNED_CERT','CERT_HAS_EXPIRED','ERR_CRYPTO_INVALID_KEYLEN']);return typeof code==='string'&&(/^[0-9A-Z]{5}$/.test(code)||allowed.has(code))?code:undefined;}
const stages=new Set(['configuration','driver','connection','transaction','read','decrypt','write','local-read','local-write']);
export function safeDiagnostic(error){if(error instanceof StoreFault&&stages.has(error.stage))return {code:error.code,stage:error.stage,...(error.detail?{detail:error.detail}:{})};return {code:safeDetail(error?.code)||'INTERNAL_ERROR',stage:'request'};}
export function decryptState(box,open){try{return open(box);}catch(e){throw new StoreFault('STATE_DECRYPT_FAILED','decrypt',e);}}
