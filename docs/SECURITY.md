# Security review and data inventory

This is an implementation review, not a certification or an independent audit.
There is no claim of zero false inputs, zero vulnerabilities, complete anonymity,
or guaranteed blocking of malicious activity. Syntax validation does not establish
truth; a privileged server operator can still fabricate server observations.

## Boundaries and attack surface

| Entry/boundary | Sensitive assets or risk | Implemented protection | Remaining limitation |
| --- | --- | --- | --- |
| Registration/login | Password guessing, database disclosure, enumeration | Strict bounded JSON, scrypt N=2^15/r=8/p=3 with random salt, constant-time hash comparison, MFA, bounded rate limits | Distributed attacks need shared limiter and abuse operations; usernames may be inferred from registration conflicts. No claim that humans/IDs were verified. |
| Authenticator enrollment/reset | Account takeover, replay | Enrollment-only tokens, encrypted TOTP secret, replay counter updated transactionally, fresh factor/password on reset, invalidate old sessions/codes | TOTP is phishable; passkeys not included. Operator encryption key compromise exposes TOTP secrets. |
| Recovery codes | Reusable bypass, accidental disclosure | Random 80-bit one-use codes, SHA256 hashes only, transactional consumption, shown once | A lost password/all factors cannot be recovered in this build. No external recovery process is fabricated. |
| Sessions/browser | Token theft, XSS, CSRF | Random bearer tokens, hashed server records, expiry, memory-only demo token, no cookies, strict CSP, textContent rendering, same-origin writes | XSS can still steal an in-memory token if introduced. No native secure token storage is supplied. Generic server exceptions must not be logged with bodies in a public deployment. |
| Consent input/receipts | Name collection, misleading privacy promises | Explicit agreement, current document hash/version, keyed per-account name digest, server receipt, no name echo | A digest is still personal data. Matching typed names is not signature identity verification. A receipt proves server acknowledgment only under its key, not actual reading or truth. |
| Family membership | Cross-account access, invitation theft | Separate credentials/MFA, owner-only invitations, invitation hashes/one use/expiry, maximum three reservations/members, own-device queries | Owner can see usernames and remove family accounts. Transfer invitation privately. IDs/minors/age verification need a separately reviewed design. |
| Device/public-key submission | Peer theft, key reuse, resource exhaustion | Canonical key format, unique public keys, five-device limit, own-account lookups, no private-key field | Key encoding cannot identify accidental private-key submission. Key ownership is established only by a successful tunnel handshake. |
| Connection orchestration | Duplicate address allocation, partial operations, stale claims | SQLite transactions/unique constraints, operation lock, preserved uncertain allocations, no delete until confirmed revoke | One process only; locks/limits are not distributed. Long broker waits can reduce availability. Reapply peers after interface restart. |
| API to broker | Privilege escalation, arbitrary commands | Private Unix socket, OS group boundary, fixed interface, no shell or network-management URL, strict fields/address pools, blocked infrastructure addresses, subprocess timeouts | Broker has powerful network permissions. A compromised API can manage peers on its assigned interface; the broker is not a full authorization database. Restrict its group to one service. |
| Broker to WireGuard | Secret leakage, false status | Read only public-key/allowed-ips/latest-handshakes; never dump/showconf/private-key, validate expected server key, schema/time validation | Root/OS compromise invalidates evidence. A recent handshake proves contact only. No native IP, DNS, kill-switch verification. |
| DNS filtering | False positives, resolver abuse, disclosure | Locally compiled explicit reviewed domain rules; label-based dnsmasq rules and exceptions; no payload scoring, no query logging by this code | Resolver/upstream privacy and query logging need operator configuration. Rule quality is unmeasured. HTTPS/ad variants/DoH bypass mean false negatives remain. |
| External network/traffic | Metadata observation, malicious destinations | Established WireGuard protocol; no arbitrary-host probe or packet-upload API | VPN is not antivirus. Valid TLS/DNS do not prove a safe website. Server forwarding/firewall/egress privacy are operator duties. |
| Identity-provider callbacks | Document exposure, forged callback | No endpoint or upload exists; policy-required identity checks fail closed | Provider integration, signature validation, minimization and deletion review remain. No IDs should be sent to this prototype. |
| Software/dependencies/updates | Supply-chain compromise | Pinned direct dependencies, originals isolated, no runtime download/update code | Dependency audit, signed native updates, signing-key management, and release process remain. No production hardening claim. |
| Infrastructure/admin/backups | Full database/key/traffic access | Non-root API, root-owned broker config/code, private local config/database; access logging off in run command | Need encryption/ACLs, secret rotation migration, backup expiry, patching, admin MFA and incident response. No admin API is exposed. |

## Data inventory

| Data | Processing/storage | Why and retention |
| --- | --- | --- |
| Password | Transient in API; salted slow hash in SQLite | Authenticate; hash until account deletion. Never log body. |
| Typed name/signature | Transient API; keyed name attestation in SQLite | Consent acknowledgment; digest/version/time/receipt until account deletion. Raw names not stored by this application. |
| Authenticator secret | Encrypted in SQLite under local config key | Verify TOTP; until reset/deletion. Enrollment response shown only during setup. |
| Recovery codes | Returned once; hashes in SQLite | Account recovery; until consumed/reset/deletion. |
| Username/membership | SQLite | Account access and family management; until deletion. |
| Session token | Browser memory; hashed SQLite record | Authenticated API; 10-minute enrollment/30-minute full-session expiry. Expired records removed during authenticated API use; idle database files may retain them until next use/deletion. |
| Invitations | Owner ID/hash/expiry in SQLite | One-use family registration; valid one hour, removed on use/next authenticated cleanup/deletion. |
| API source IP | Brief memory-only hashed rate-limit keys | Throttling. Bounded 10,000-key LRU; timestamps expire logically after throttle windows, stale hashed keys may remain until eviction/restart. No historical IP table. |
| Device label/public key | SQLite | Provision individual devices and isolation; until device/account deletion. |
| Tunnel addresses/server/DNS preference/request timestamp | SQLite | Allocation, provisioning, retry/revocation safety; until confirmed disconnect/deletion. |
| Endpoint/handshake/traffic counters | WireGuard/OS state | Route/authenticate packets; API fetches handshake/key presence only. In-memory until peer/interface removal, subject to OS/host monitoring. |
| DNS queries | Configured resolver/upstream | Domain resolution/filtering; no query logging enabled by project. Actual resolver/host policy needs independent configuration/disclosure. |
| Browsing contents | Not inspected/recorded by this API | No payload-upload/flow-ledger API remains. Transit operators still have visibility according to traffic encryption and infrastructure. |
| Backups/logs | Operator controlled | Must define and disclose actual retention before public launch. Application deletion cannot guarantee erasure of already-created backups. |

No analytics, ad-provider, external QR-service, generative-AI call, or background
website probing is in the execution path. The DNS compiler reads local reviewed
lists only. It never fetches arbitrary lists or executes their text as directives.

## Performance choices

Schema validation and bounded payloads run before business logic. Slow password
hashing uses a two-slot semaphore to limit peak memory. Public key/address
allocation use deterministic parsing and database constraints. Single-process
operation simplifies peer race handling, intentionally trading throughput for
auditable behavior. No continuous scanning or per-flow hash ledger is retained.
There is no invented latency, malware confidence, speed score or blocked-ad count.
