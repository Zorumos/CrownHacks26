# Security and privacy review

This is an implementation review, not an independent audit. No claim of production
safety, guaranteed anonymity, physical RAM erasure or zero false data is made.

## Trust boundaries and attack surface

| Boundary | Controls | Remaining risks |
| --- | --- | --- |
| Anonymous judge invitation | 128-bit room code, generation checks, bounded sessions/TTL, separate judge tokens, no account/ID collection | Anyone holding the public invitation can join and confirm room-scoped panic. Do not use it to control real VPN state. |
| Presenter control | Private operator creation secret; separate random presenter token hashed in room; reset rotates it | Presenter token in browser memory can be stolen by XSS. It is not encoded in invitations. No presenter-token recovery endpoint. |
| Shared Redis state | Atomic raw-value CAS, retry bounds, schema/invariant checks, terminal panic per generation, no stale-write resurrection | Redis/operator compromise can reveal the current synthetic demo key or falsify state. Persistence/backups/logs exist outside application erasure claims. |
| Encryption demo | Real AES-256-GCM; random 32-byte keys, 12-byte nonce; authenticated room/generation/epoch; synthetic input only | Language/runtime copies and provider backups cannot be reliably zeroized here. New ciphertext does not imply unlinkability. |
| Browser fallback | Browser memory + WebCrypto; explicit local-only mode; no localStorage; generation/panic recheck after asynchronous encryption | Same browser has access to its local demo key. It is not a multi-device fallback or production encryption service. |
| Auth/account data | Salted scrypt N=32768/r=8/p=3, two concurrent derivations, TOTP, replay counter, one-use recovery, hashed expiring tokens | TOTP is phishable; passkeys are not implemented. Password/recovery loss has no magic bypass. Review phishing-resistant auth before launch. |
| Secret storage | TOTP secret encrypted with AES-GCM and per-account context; master key environment-only; no raw typed-name retention | Master-key compromise exposes authenticator secrets. Key rotation/re-encryption migration and backup-key policy remain operator work. |
| Family data | Separate credentials/devices; owner sees IDs/usernames only; one-use hashed invites; serialized slot reservation | Owner can delete family service accounts after reauthentication. Age/minor/ID policies require a reviewed design. |
| SQL database | Parameterized queries, foreign keys, constraints, explicit transactions, PG pooling/local SQLite, cleanup tool | Live PostgreSQL concurrency/capacity remains unverified. Backups/host logs need retention rules and monitoring. |
| Native device keys | Only public-key field; keys generated locally; no private-key output | Public/private keys share an encoding. An accidentally pasted private key cannot be detected reliably by format. A real native client is still required. |
| VPN operation ordering | Transactional reservation; allocation locks; device operation sequences; preserved uncertain records; disabled devices/accounts before deletion | Deletion can be pending while server is unreachable. UI must explain it. Agent sequence ledger must survive restart. |
| Vercel to VPS | Fixed configured HTTPS endpoint, TLS validation, HMAC body/time/nonce, bounded validated replies | Agent management secret compromise permits scoped peer operations. Firewall/private-management path and secret rotation remain essential. |
| Privileged Linux agent | Fixed interface/executable, no shell, validated key/address pools, reserved DNS, persisted anti-replay/sequence state, root-owned files | CAP_NET_ADMIN/root is powerful. Python/service/dependency/OS compromise can break the boundary. Sequential service needs proxy timeouts and resource limits. |
| Identity/alias/passkey integrations | Explicit unimplemented responses and typed extension contracts; required ID policy blocks access | No documents are accepted, no alias is created, no callback is trusted. Provider security review and callback validation remain before enablement. |
| Network/website safety claims | No arbitrary website scanning, hostname entropy score or payload-upload engine | VPN is not antivirus/phishing proof. TLS/DNS/handshake status does not prove a destination is safe or traffic leak-free. |
| Native updates/client firewall | Documented contract only | OS permission scope, signed updates, token storage, route/DNS/IPv6/kill-switch checks remain separate native implementation. |
| Hosting/logging/supply chain | No body/credential console logs, no analytics, .gitignore for secrets/data, explicit environment scopes | Framework/proxy/provider metadata and logs require disclosure. Next install/build/typecheck and dependency audit were not possible here. Do not publish before validation. |

## Data inventory and deletion

| Data | Where | Purpose/retention |
| --- | --- | --- |
| Demo room code, hashed tokens, session leases | Redis | Synchronization, TTL 30 minutes maximum; sessions ten minutes of activity, contact leases 15 seconds |
| Current demo key/ciphertext/nonce/tag | Redis; only public ciphertext fields sent to browser | Synthetic rotation demo; key removed on panic/overwrite, room TTL. Infrastructure retention is not proven erased |
| Browser preview | Browser memory only | Local demonstration; discarded on page lifecycle/reset, no cross-device persistence |
| Password | Transient API; salted hash in SQL | Authentication until account deletion |
| TOTP secret | Encrypted SQL field | MFA until reset/deletion; master key separate in environment |
| Recovery codes | Shown once; hashes in SQL | One-use recovery until consumption/reset/deletion |
| Account username/family membership/timestamps | SQL | Account operations until deletion |
| Typed name/signature | Transient API; keyed attestation in SQL | Minimal consent acknowledgment; digest is still personal data until account deletion |
| Agreement document version/hash/time/receipt | SQL | Acknowledgment evidence until account deletion; not proof of reading/identity |
| API token | Browser/native memory; hash/scope/expiry in SQL | 10-minute enrollment or deletion-only / 30-minute full session; logical expiry enforced, physical cleanup separately scheduled |
| Family invitations | Hash/owner/expiry in SQL | One-hour expiry; consumed once, physically removed by cleanup if unused |
| Rate-window keys/counts | Redis or hashed SQL keys | Abuse control; shared keys TTL, SQL cleanup tool; raw client IPs are not collected by application limiter |
| Device public key/label/tunnel allocation/preferences | SQL | Provisioning and safe retries until confirmed removal |
| Agent nonce hash/sequence fingerprint | Root-only SQLite on VPS | Replay/order control; nonces pruned after expiry, peer sequence tombstones retained for safe stale-operation rejection |
| WireGuard endpoint/handshake/traffic metadata | OS/WireGuard | Routing/authentication; API fetches key presence/handshake, not packet bodies or browsing history |
| DNS queries | Actual resolver/upstream | Domain resolution/filtering; no application query history; operator must configure/disclose provider retention |
| Infrastructure request metadata/backups | Hosting providers | Separate disclosed retention; not erased by application account deletion or demo panic |

The disclosure is available before real-service data entry and includes configured
server/DNS metadata. Optional analytics are not collected. A typed-name receipt is
keyed acknowledgment, not legal certification. Public deployment must name actual
hosting/database/DNS/verification processors rather than leaving generic provider
language as a substitute for a reviewed policy.

## Known operational limits

No distributed global IP reputation or automated human screening is claimed.
Account throttling is shared via SQL and room throttling via Redis; deployment
edge/proxy limits are still needed for unauthenticated flood resistance. No
permission to scan external systems, execute malware, or erase production disks
is requested. Real VPN panic revocation is deliberately outside the demo panic API.
