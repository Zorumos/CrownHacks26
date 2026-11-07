# Live server deployment and native integration

No deployment, public service, or paid resource has been created. This document
describes setup on **your own Linux host**. The localhost Windows demo needs no
administrator access; the following server operations do.

## 1. Prepare owned infrastructure

Install Python 3.12+, WireGuard tools and a firewall using your distribution's
supported packages. Create a dedicated non-root account for the API and a dedicated
group for broker access. Install this project's code root-owned under an operator
chosen directory, and give the API account write access only to its settings/data
directory. Never let it rewrite broker code, the `wg` executable or broker config.

Generate the server private key locally with WireGuard. Keep it in a root-only
file; never put it into the API inventory or a repository. Configure a dedicated
interface, such as `wg0`, with non-overlapping private IPv4 and IPv6 subnets and a
UDP listening port. Use network+1 as the interface address and reserve any DNS
addresses before allocating devices. Disable `SaveConfig` for this managed
interface: dynamically provisioned peers must not silently become static peers
that return after revocation and a restart.

The broker manages **only peer keys and allowed tunnel addresses**. It does not
create interfaces, enable forwarding, configure NAT, or manage firewalls.

Configure IPv4 forwarding and NAT/routing for the chosen tunnel subnet. Configure
IPv6 forwarding and a correct routable IPv6 design or explicitly tested IPv6
blocking in the native client. A ULA-only IPv6 subnet needs suitable egress
routing/NAT to reach the public IPv6 internet; do not assume adding `::/0` alone
solves leaks. Configure the firewall to:

- Permit the chosen VPN UDP port from clients.
- Permit necessary DNS from authenticated tunnel addresses only.
- Permit intended public internet forwarding and established return traffic.
- Block tunnel clients from the host's API management ports, metadata services,
  other clients, and private infrastructure except explicitly needed DNS.
- Keep the broker completely inaccessible from the public network.

These policies depend on your existing interfaces and firewall. Review rules for
your host rather than applying a generic command that can lock out administration.
No universal forwarding configuration is automatically executed by this project.

## 2. Root-owned broker configuration

Create `/etc/cyber-one/broker.json`. **The values below illustrate an address plan;
they are not a real deployed server.** Adapt the subnets/interface and numeric
group ID to your environment:

```json
{
  "interface": "wg0",
  "socket": "/run/cyber-one/wg0.sock",
  "wg_binary": "/usr/bin/wg",
  "subnet4": "10.42.0.0/24",
  "subnet6": "fd42::/120",
  "reserved_addresses": ["10.42.0.53"],
  "api_group_id": 1234
}
```

Create `/run/cyber-one` root-owned, group-readable/traversable by the dedicated
API group, mode 0750. Make the broker config root-owned and mode 0640 or stricter.
Start the broker with the server's system Python:

```bash
sudo python3 /YOUR_ROOT_OWNED_INSTALL/agent/broker.py /etc/cyber-one/broker.json
```

The broker binds one Unix socket mode 0660 with the configured group. It uses only
fixed-interface `wg show public-key`, `allowed-ips`, `latest-handshakes`, and
validated `wg set peer ...` operations. It never reads private keys through
`dump`/`showconf`, invokes a shell, accepts executable paths from API requests, or
forwards user-supplied URLs.

Run it under your service manager for persistence. Harden its service with a
dedicated root-owned config/code path, restrictive filesystem access,
`NoNewPrivileges`, `PrivateTmp`, and an appropriate `CAP_NET_ADMIN` capability
boundary, tested on your distribution. The API stays non-root and receives no
network-administration capability. Root/CAP_NET_ADMIN remains powerful: a broker
code compromise is an explicit trust boundary, not magically risk-free.

## 3. Configure real API inventory

On the Linux API host, install dependencies in a virtual environment and run
`python setup_local.py` as the dedicated API account from its working directory.
Edit its private `config.local.json`; retain the generated encryption key. Set
the `origin` to the exact HTTPS origin serving the API/demo behind your reverse
proxy, and add an inventory entry:

```json
{
  "id": "YOUR_SERVER_ID",
  "country": "YOUR_ACTUAL_COUNTRY",
  "city": "YOUR_ACTUAL_CITY",
  "public_key": "COPY_ACTUAL_SERVER_PUBLIC_KEY",
  "endpoint": "YOUR_ACTUAL_HOSTNAME:51820",
  "socket": "/run/cyber-one/wg0.sock",
  "subnet4": "10.42.0.0/24",
  "subnet6": "fd42::/120",
  "dns_plain": ["10.42.0.1"],
  "dns_filtered": ["10.42.0.53"]
}
```

This example deliberately does not pass validation until placeholders are
replaced. Server IDs must use lowercase letters/numbers/hyphens. The inventory
public key must match the broker's real `wg show wg0 public-key` result. DNS
addresses must point to functioning resolvers; the API cannot infer their status.
API and broker subnet plans must match. Each inventory socket represents a local
managed interface; multiple geographic hosts need a separately designed,
authenticated regional management deployment. This prototype is not a remote
orchestration system.

Start one API worker with the README command, under the unprivileged API account.
Bind the reverse proxy to HTTPS and keep the API's private listener local. Leave
access logging off unless you disclose and retain it deliberately. Configure
proxy request-size limits, connection timeouts and aggregate request throttling.
Do not trust arbitrary forwarded-IP headers; the example uses no proxy headers.
With this setting, per-IP throttling behind a proxy sees the proxy address; shared
limiting/trusted proxy configuration must be designed before public load.

## 4. Filtered DNS that actually enforces rules

Use a maintained DNS resolver such as dnsmasq on your VPN host. Bind a plain
instance to the reserved plain address and a filtered instance to its reserved
address. Add those addresses to the interface and firewall. Do not run an open
public resolver. Set explicit trusted upstreams and review their privacy policies.

For the filtered instance, prepare an operator-reviewed file containing one domain
per line. No default list is shipped, and no live accuracy claim is invented.
Record its source/license, review date and version. Compile locally:

```bash
python3 agent/compile_blocklist.py reviewed-domains.txt reviewed-rules.conf --allow reviewed-exceptions.txt
```

The output file must not already exist. Review the output, run dnsmasq's config
test, then install it in the filtered instance's dedicated configuration directory
and restart/reload as appropriate. Use `no-hosts` and no DHCP/hosts sources in this
dedicated filtered resolver, plus `no-resolv` and explicit upstreams. `local=/domain/`
prevents forwarding for a listed domain and its subdomains; a more-specific
`server=/allowed.domain/#` rule permits an explicit exception through the normal
upstreams. The compiler does not alter DNS services automatically.

Do not enable query logging by default. Test a domain you own: it should resolve
through the plain instance, fail through the filtered instance when listed, and
resolve through the filtered instance when explicitly allowed. Test IPv4, IPv6,
TCP and UDP DNS. These are operator tests, not fake blocked-ad counters in the UI.
Filtering can break legitimate services; maintain a reviewed exception process.
Apps using independent DNS-over-HTTPS may bypass configured DNS. DNS filtering
cannot remove same-domain ads or read encrypted pages. No browser-wide domain
history is sent to the API.

## 5. Native client activation

The Windows client must generate a WireGuard key pair locally and keep the private
key in OS-protected storage. Authenticate to the API and register only the public
key. Request a connection, construct native configuration from the returned fields,
and start the OS VPN tunnel through a narrowly scoped native service.

Before reporting device protection, check actual IPv4/IPv6 routing, DNS routing,
public egress behavior, and kill-switch enforcement on that device. Use your own
controlled probe endpoint if you need to observe public IP; disclose it and do not
accept an arbitrary URL from a browser. Server contact alone is insufficient.
Native activation/verification is **not implemented in this backend bundle**.

On disconnect, stop the native tunnel and call server revocation. If the server is
unreachable, report unconfirmed server revocation, keep retrying deliberately, and
do not discard the tracked peer allocation. If the API is unreachable, the client
must still be able to stop its local tunnel. Never disable a kill switch silently.

## 6. Restart, revocation and public-release gates

Dynamic peers are not persisted into WireGuard static config by the broker. After
an interface/host restart, an authenticated repeated connection request re-applies
the allocated peer. Before restoring old static config, ensure revoked peers are
absent. Back up the API database and encryption key consistently and privately;
publish an actual backup expiry schedule before public use.

Complete live end-to-end tests, human accessibility testing, secret/dependency
review, infrastructure retention configuration, account-abuse capacity planning,
and incident-response/recovery procedures before exposing this to real users.
If physical-ID checks are required, implement a reviewed provider flow with signed
callbacks and minimized retention first; `require_identity=true` currently blocks
registration and VPN access rather than skipping checks.

Primary references used for implementation decisions:

- https://www.wireguard.com/quickstart/
- https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8
- https://git.zx2c4.com/wireguard-tools/tree/src/show.c
- https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
