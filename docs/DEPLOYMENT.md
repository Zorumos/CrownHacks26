# Deployment and live networking

This project is code, not provisioned infrastructure. No live Redis/PostgreSQL/VPN
credentials were supplied. Keep judge simulation isolated from real accounts and
WireGuard state; panic only affects `co:demo:` room records.

## Local Windows

Use Node 24 LTS or >=22.18 and PowerShell inside the folder containing package.json:

```powershell
npm install
npm run setup
npm run migrate
npm run dev
```

No Redis is required for browser-local preview; no database is required for that
preview. Migration enables the real-service account API locally with SQLite.
Use http://127.0.0.1:3000, matching APP_ORIGIN. Do not publish `.env.local` or `data/`.

## Vercel

Prepare a repository yourself after reviewing files, licensing and event rules.
Create a Vercel project for this folder, framework Next.js, Node runtime compatible
with the package's minimum. Set server-side environment variables:

- `APP_ORIGIN`: exact HTTPS origin, with no trailing slash/path.
- `APP_MASTER_KEY`: independent 32 random bytes encoded as 64 hex characters.
- `DEMO_CREATE_SECRET`: strong independent operator bearer for shared-room creation.
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`: from the Upstash integration.
- `DATABASE_URL`: a PostgreSQL provider connection string using its required TLS
  settings. Use the appropriate pooled/serverless endpoint for that provider.
- `REQUIRE_IDENTITY=false` for the current build. True blocks registration/new VPN
  access until a real verification integration exists; it does not enable one.
- `FAMILY_LIMIT=3` initially.
- `VPN_SERVERS_JSON=[]` until actual management infrastructure is ready.

Never prefix these with NEXT_PUBLIC. Vercel filesystem/in-memory variables are not
the account database or authoritative room store. Production accounts require
PostgreSQL. Production shared rooms require Redis. A configured outage returns an
error rather than reverting to fake local server state.

Run `npm run migrate` from a trusted deployment machine/job with the intended
DATABASE_URL. Do not run DDL in public requests. A pool of four connections is
configured; tune pooling/provider limits after capacity tests. Migrations are initial
version 1 only; future schema upgrades need explicit new migrations and backup planning.

`npm install`/`npm run typecheck`/`npm run build` must succeed in your real environment
before publishing. The workspace that produced this code blocked npm package
downloads, so it did not verify that build. Retain and review the installed lockfile,
run a dependency audit, and test actual Redis/PostgreSQL paths. No dependency audit
or production readiness is claimed by a passing core test suite.

Preview deployment origins differ from production: configure each environment's
APP_ORIGIN and avoid leaking production creation/account secrets into untrusted previews.
QR generation is not part of this backend delivery; a frontend should render the
returned joinUrl locally and never put presenter credentials into the QR.

Run `npm run cleanup` through an operator scheduler to remove expired SQL sessions,
invitations and rate windows. Logical expiry is checked immediately on access;
physical deletion is a separate maintenance step. Set actual backup/log retention
and disclose infrastructure processors before accepting public accounts.

## Linux WireGuard host

Use an owned Linux VPS with WireGuard tools, Python 3.12+, a TLS certificate for
the management hostname, and a separately configured WireGuard interface.

The HTTPS management agent does not create interfaces, server private keys,
forwarding, firewall rules, NAT, or resolvers. Configure those explicitly for your
network. Generate server private keys on the host; keep them root-only. The API
inventory includes the **public** server key only.

Use a dedicated interface, private IPv4 /24 and IPv6 ULA /120 pools that do not
overlap existing networks. Reserve network+1 for the host and other infrastructure
addresses, including DNS. Configure IPv4 forwarding/NAT and a correct IPv6 egress
or independently tested native-client blocking policy. Adding ::/0 alone is not
proof of leak protection.

Firewall requirements:

- Allow the chosen VPN UDP listening port.
- Permit authenticated tunnel traffic to required DNS and intended public egress.
- Block access to management ports, other peers, cloud metadata and private
  infrastructure except explicitly intended DNS.
- Restrict the HTTPS management endpoint to your management network/trusted proxy
  wherever possible, and retain HMAC authentication. Do not expose arbitrary admin
  or shell capabilities to browsers.

Disable WireGuard `SaveConfig` on this managed interface. The API manages dynamic
peers; revoked entries must not reappear from stale static peer configuration.

## Management agent configuration

Install `agent/server.py` root-owned in a non-writable code directory. Create a
root-owned 0700 state directory, for example `/var/lib/cyber-one-agent`. Use a
root-owned non-writable configuration file such as `/etc/cyber-one/agent.json`.
The following is a **template**, not a deployed server:

```json
{
  "interface":"wg0",
  "wg_binary":"/usr/bin/wg",
  "subnet4":"10.42.0.0/24",
  "subnet6":"fd42::/120",
  "reserved_addresses":["10.42.0.53"],
  "shared_secret":"REPLACE_WITH_AN_INDEPENDENT_RANDOM_MANAGEMENT_SECRET",
  "state_database":"/var/lib/cyber-one-agent/state.sqlite3",
  "listen_host":"127.0.0.1",
  "listen_port":9443,
  "tls_certificate":"/etc/cyber-one/tls-fullchain.pem",
  "tls_private_key":"/etc/cyber-one/tls-key.pem"
}
```

Make the TLS private key root-owned 0600. The state database holds nonce hashes and
public-peer operation sequence tombstones, not VPN private keys. Do not delete it
casually: its sequences prevent stale operations undoing later revocations.

Start as an appropriately scoped privileged service:

```bash
sudo python3 /YOUR_ROOT_OWNED_INSTALL/agent/server.py /etc/cyber-one/agent.json
```

Keep the default loopback binding and route through a correctly configured trusted
HTTPS reverse proxy/private path, or explicitly configure an interface secured by
your firewall. A remote Vercel function cannot reach a loopback-only VPS listener
without that management network/proxy. TLS hostname/certificate validation remains
enabled in the Node client. Do not work around it by disabling verification.

Harden the service under your Linux service manager: root-owned code/config, least
required CAP_NET_ADMIN scope, NoNewPrivileges, restricted writable paths, private
temporary directory and suitable process/connection limits. The agent is sequential
to serialize operations on one interface. Configure reverse-proxy request and TLS
timeouts to mitigate slow connections. It is not a high-capacity public API.

The service accepts only health/status/provision/revoke at `/v1/peer`. Requests use
HMAC-SHA256 over timestamp, nonce and exact body. The agent persists nonce consumption
and monotonically increasing per-peer operation sequences. It does not execute a
shell or read `wg dump`, `showconf`, private keys or peer endpoint addresses.

## API inventory

Set VPN_SERVERS_JSON to an array with actual operator values:

```json
[
  {
    "id":"your-server",
    "country":"YOUR_ACTUAL_COUNTRY",
    "city":"YOUR_ACTUAL_CITY",
    "publicKey":"COPY_ACTUAL_SERVER_PUBLIC_KEY",
    "endpoint":"YOUR_ACTUAL_VPN_HOSTNAME:51820",
    "agentUrl":"https://YOUR_MANAGEMENT_HOSTNAME/v1/peer",
    "agentSecret":"COPY_THE_MATCHING_INDEPENDENT_AGENT_SECRET",
    "addressPrefix4":"10.42.0.",
    "addressPrefix6":"fd42::",
    "dnsPlain":["10.42.0.1"],
    "dnsFiltered":["10.42.0.53"]
  }
]
```

Replace every placeholder. Subnets/prefixes and reserved addresses must match the
agent/host plan. The backend avoids configured DNS addresses during allocation;
the agent must also reserve them against a compromised or erroneous controller.
Location labels are operator assertions, not independent geolocation evidence.

## Filtered DNS

Deploy a maintained resolver on the reserved filtered address with an operator-reviewed
domain blocklist and exception process. Configure the plain address separately.
Bind/firewall resolvers to authenticated VPN clients, not the public internet.
Do not enable query logging by default. Review/disclose upstream operators and
retention. Test blocked/allowed domains you own over UDP/TCP and IPv4/IPv6.

This Node backend requests resolver settings; it does not claim to install or verify
a filtering engine. Browsers/apps with independent encrypted DNS may bypass the
configured resolver. Same-domain ads cannot generally be removed with DNS rules.

## Native Windows client

Use the official WireGuard client for manual initial verification or implement a
separate narrow native service. Generate private keys locally. Register only the
public key, request server configuration, then assemble and apply it on the device.

Before a green protection claim, independently verify routes, DNS, IPv6, public
egress and a functioning kill switch. Native attestation and these checks are not
implemented by this backend. Do not accept browser booleans or a server handshake
as substitute evidence. Keep local Disconnect working even when the API is offline.

After agent/interface restart, dynamic peers may need an authenticated repeated
connect request. Preserve API allocations and agent sequence ledger. Do not restore
revoked peers from an old WireGuard static config. Re-adding a deleted device should
use a new local key pair, not reset a remembered public key's sequence.

## Primary references

- https://nextjs.org/docs/app/api-reference/file-conventions/route
- https://upstash.com/docs/redis/sdks/ts/commands/scripts/eval
- https://vercel.com/docs/redis
- https://nodejs.org/api/crypto.html
- https://www.wireguard.com/quickstart/
- https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8
