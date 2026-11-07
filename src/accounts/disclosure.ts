import { hash,mac,equal } from '../crypto.ts';
import { assert,text } from '../errors.ts';
import type { Config } from '../config.ts';

export function disclosure(config:Config){
  const document={
    version:'2026-11-07.2',title:'Cyber One real-service data disclosure',
    collection:['Username, salted password hash, encrypted authenticator secret, recovery-code hashes, membership and session records.','Typed names are processed to record agreement. Only a keyed per-account name attestation, document version/hash, acceptance time and receipt are retained. A typed name does not verify identity.','Device labels/public keys, assigned tunnel addresses, selected server, DNS preference, request times and operation sequence numbers are retained for provisioning and revocation.'],
    recipients:['Your deployment host/database provider process API and stored account data. The VPN host processes endpoint and traffic metadata when configured. DNS operators receive queries. Publish actual host/operator identities and their retention policy before public launch.','Anonymous demo sessions and synthetic encryption payloads are separate from account data. Upstash Redis holds demo state and its current demo key in shared mode; do not interpret this as proven RAM-only storage.'],
    identity:config.requireIdentity?'Verification is required, but no ID provider is integrated in this build. Registration and new VPN access are blocked. Do not upload an ID.':'No ID documents are accepted or verified in this build.',
    retention:['Accounts, agreement receipts and device records remain until deletion. Peer revocation must be confirmed before associated records are removed.','Account sessions expire after 30 minutes; enrollment sessions after 10 minutes. Invitations expire after one hour. Expired records are cleaned during service use; dormant database copies may retain them until cleanup. Demo rooms expire after 30 minutes.','Application deletion does not erase provider backups or infrastructure logs. Configure and disclose their retention independently.'],
    privacy:'No browsing-history, packet-content, analytics or physical-ID collection is implemented. VPN operators and DNS providers still have metadata visibility. No privacy guarantee, complete anonymity or automatic legal compliance is claimed.',
    local:'Generate VPN private keys on the native device and never submit them. Passwords and typed names reach this API over HTTPS. Local preview stays in browser memory and does not synchronize separate phones.',
    control:'You can sign out, revoke peers, remove devices, replace an authenticator, delete your account and manage family membership. Required terms are separate from optional analytics; this build collects no optional analytics.',
    servers:config.servers.map(s=>({id:s.id,country:s.country,city:s.city,endpoint:s.endpoint,dnsPlain:s.dnsPlain,dnsFiltered:s.dnsFiltered})),
    agreement:'I reviewed this disclosure and agree to the described processing. I understand the integration and privacy limitations.'
  };
  return {...document,documentHash:hash(JSON.stringify(document))};
}
export function normalizeName(value:unknown){
  const name=text(value,2,120).normalize('NFKC').trim().replace(/\s+/gu,' ').toLocaleLowerCase('en-US');
  assert(name.length>=2 && !/\p{C}/u.test(name),422,'INVALID_NAME','Enter a printable name using 2 to 120 characters.');return name;
}
export function agreement(input:Record<string,unknown>,config:Config,accountId:string,now:number){
  const document=disclosure(config);
  assert(input.agreed===true && input.disclosureVersion===document.version && input.documentHash===document.documentHash,409,'REVIEW_DISCLOSURE','Review and agree to the current disclosure.');
  const name=normalizeName(input.name),signature=normalizeName(input.signature);
  assert(equal(name,signature),422,'SIGNATURE_MISMATCH','The typed names do not match.');
  const nameAttestation=mac(config.masterKey,accountId+':'+name);
  return {version:document.version,documentHash:document.documentHash,nameAttestation,acceptedAt:now,receipt:mac(config.masterKey,JSON.stringify([accountId,document.documentHash,now,nameAttestation]))};
}
