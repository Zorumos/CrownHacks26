# Cyber One — Next.js backend

An implementation of the attached merged requirements focused on **backend code**:
shared judge rooms, atomic synchronization, real AES-256-GCM demo encryption,
room-scoped panic/reset, persistent account security, family isolation, consent,
WireGuard provisioning and a separately deployed Linux management agent.

It includes a small presenter API console and mobile judge page to exercise the
backend. These are integration tools, not a completed consumer VPN interface.
No VPS, Vercel deployment, database or Redis service was purchased/provisioned.

**A browser demo never protects the visitor's device.** A real VPN needs a configured
Linux server and native client. A handshake does not establish device-wide routing,
DNS, IPv6 or kill-switch protection; those results remain unknown here.

## Start on Windows

Use Node.js **24 LTS** (or Node >=22.18). The newer minimum is intentional: local
SQLite and direct TypeScript test execution use Node's built-in capabilities.
Check with `node --version`. Do not use the previous Python project's commands.

Extract this ZIP, open the folder containing `package.json`, then open PowerShell
there. Run each command individually:

```powershell
npm install
npm run setup
npm run migrate
npm run dev
```

Open **http://127.0.0.1:3000** and then **/presenter**. Use this exact hostname to
match the default origin. Development starts with browser-only demo preview when
Redis is absent. It uses real WebCrypto AES-GCM, clearly labeled as a simulation.
Accounts use a local private SQLite file after migration.

`npm run setup` creates a private `.env.local` once and refuses to overwrite keys.
Do not share it. Do not remove an existing encryption key without a migration;
stored authenticator secrets depend on it. Set Windows ACLs appropriately.

## Shared laptop + phone demo

1. Add an Upstash Redis integration and set `UPSTASH_REDIS_REST_URL` and
   `UPSTASH_REDIS_REST_TOKEN` server-side. Both are required.
2. Set `APP_ORIGIN` to the actual HTTPS deployment origin for remote access.
3. Restart/redeploy. The presenter console should show shared mode.
4. Open `.env.local` privately on your own laptop and copy `DEMO_CREATE_SECRET`
   into the console's private room-creation field. On Vercel use your server-side
   configured creation secret. This credential is never placed in client code.
5. Create a room. Share **only the judge URL**, which includes the room code and
   generation. Keep the presenter tab open; its returned credential stays in memory.
6. Open the invitation on a phone, join, then Connect to demo node. The presenter
   count updates through polling. Confirm panic to clear the demo key and count.
7. Only the presenter can reset. Share the new generation's link afterward.

No Redis: **one browser only**. Polling does not make local preview cross-device.
Configured Redis failure returns an outage; it does not silently create isolated
state. Closing/reloading a presenter tab loses its private token; create a new
room if it was not retained securely. Rooms expire after 30 minutes.

This backend delivers invitation URLs. QR layout/generation, traffic graphs and
the polished final product interface remain frontend work; do not call them implemented.

## Tests

```powershell
npm test
npm run typecheck
npm run build
```

Optional Linux-agent unit tests (Python 3.12+):

```powershell
py -3.12 -m unittest discover -s agent -p "test_*.py" -v
```

See `TEST_RESULTS.txt`, `AGENT_TEST_RESULTS.txt`, and [docs/VALIDATION.md](docs/VALIDATION.md).
Core tests run without npm dependencies using `node --experimental-strip-types
--test tests/*.test.ts`. Test stores/agent replies are explicitly synthetic and
cannot be selected as runtime providers.

**Verification limitation:** npm package downloads were rejected by this workspace's
network policy. Core/API-handler tests and Python-agent unit tests ran, but the
full Next.js install/build/typecheck and rendered browser UI could not be verified.
Run the commands above after installation and retain the generated lockfile for a
reviewed reproducible release. Dependencies have supported version ranges, not a
falsely claimed tested lockfile. Production Redis/PostgreSQL and live WireGuard
were not available and remain integration tests to run on owned infrastructure.

## Code map

| Location | Purpose |
| --- | --- |
| `app/api/[...path]/route.ts` | Next.js Node-runtime entry point |
| `src/http.ts` | Bounded JSON, origin checks, API dispatch and sanitized errors |
| `src/demo/rooms.ts` | Atomic room transitions, counting, rotation, panic and reset |
| `src/store.ts` | Official Upstash adapter, Lua CAS, shared throttling |
| `src/demo/local-preview.ts` | Browser-only fallback, never server-global state |
| `src/accounts/` | Disclosure, scrypt/TOTP/recovery, sessions, family invites |
| `src/database.ts` | Local SQLite and production PostgreSQL adapters |
| `migrations/001_initial.sql` | Initial relational schema |
| `src/vpn/` | Own-device provisioning, safe retries, honest evidence |
| `agent/server.py` | Fixed-interface HTTPS WireGuard manager; Linux deployment only |
| `src/providers.ts` | Explicit integration contracts for ID, aliases and native evidence |
| `app/presenter`, `app/join` | Minimal integration clients; keys remain server-side in shared mode |

The request is preserved in `docs/BUILD_REQUIREMENTS.txt`. This is a new Node/Next.js
project; it does not replace or silently import the earlier Python prototype.

## Implemented and remaining

| Feature | Status |
| --- | --- |
| Judge rooms, session leases, unique counting, expiration | Implemented with Redis adapter; tested with atomic test store; live Redis unverified |
| AES-GCM rotation/identical payload/panic/reset | Implemented and tested; not proof of RAM erasure or provider backup destruction |
| Local browser preview | Implemented with WebCrypto; browser rendering unverified |
| Consent/password/TOTP/recovery/session/family backend | Implemented; exercised against real local SQLite |
| PostgreSQL | Adapter and migration included; requires a configured database and integration test |
| Devices, allocation, retries, revocation, evidence | Implemented; tested against synthetic agent observations |
| Linux WireGuard agent | Implemented HMAC/TLS/fixed-interface protocol; unit-tested; no live tunnel test |
| Native Windows activation/kill switch/leak verification | Not included; integration contract and checklist supplied |
| Ad blocking | DNS preference/configuration path; running resolver and reviewed policy required |
| Physical ID / passkeys / temporary email aliases | Explicit unavailable responses and extension contracts; not implemented providers |
| Final account dashboard / QR / charts / complete product UX | Frontend work remains; console/mobile test clients supplied |
| Human user studies / public repository / eligibility | No results or completion claimed |

## Operations

Keep secrets, database files, WireGuard configs/private keys and `.env.local` out
of source control. Use HTTPS outside localhost. Run `npm run cleanup` under your
operator scheduler to remove expired SQL session/invite/rate records. Logical expiry
is enforced on requests even before cleanup; records are not physically erased
merely because a timer passed. Redis keys expire independently.

Read [docs/API.md](docs/API.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md),
[docs/SECURITY.md](docs/SECURITY.md) and [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md).
This is a prototype requiring public-release review, not an audited production VPN.
Follow your hackathon's timing/AI rules; creation on 2026-11-07 does not establish
event eligibility. No repository or public service has been published.
