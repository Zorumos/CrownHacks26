# Changes from supplied prototype

## 2026-11-07

- Preserve all four original files separately, with their unsafe protection claims
  excluded from runtime imports.
- Replace fabricated carrier IPs and cipher-list claims with explicit server
  observations and unknown device-protection status.
- Remove unvalidated entropy/payload threat scores and arbitrary destination probes.
- Add strict, bounded JSON API, persistent accounts, encrypted TOTP secrets,
  replay-safe factors, recovery codes, short-lived hashed sessions and account deletion.
- Add versioned disclosure acknowledgment without plaintext typed-name retention.
- Add isolated family accounts, limited one-use invitations and per-account devices.
- Add local, fixed-interface WireGuard broker with validated public keys/address pools.
- Serialize address allocation and provision/revoke operations. Preserve ambiguous
  operations until revocation is confirmed rather than forgetting possible live peers.
- Add real filtered-DNS configuration path and operator-reviewed dnsmasq policy compiler.
- Add per-device warning transitions with persistent status, cooldowns and accessible metadata.
- Include a minimal browser integration demo and complete setup, API, deployment,
  threat model, rubric, original prompt and honest validation documentation.

Not included: a native VPN client, real server inventory, public deployment,
physical-ID provider, passkeys, email-alias provider, independent audit, human user
tests, live leak checks or a measured sub-minute protection claim.
