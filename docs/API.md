# API and client contract

All request bodies are strict JSON: unknown fields and coerced types are rejected.
Use `Content-Type: application/json`. Protected routes require
`Authorization: Bearer YOUR_TOKEN`. Never put tokens in URLs or browser storage.
Normal sessions last 30 minutes; enrollment sessions 10 minutes. Reloading the
demo loses its in-memory token, requiring sign-in. HTTPS is mandatory beyond
localhost. No browser cookies are used, and there is no permissive CORS policy.

## Core flow

1. `GET /api/disclosure`: render all disclosure sections using text content.
2. `POST /api/auth/register`:

```json
{
  "username": "your_username",
  "password": "a password you choose with at least 12 characters",
  "name": "Your Name",
  "signature": "Your Name",
  "agreed": true,
  "disclosure_version": "COPY_FROM_DISCLOSURE",
  "document_hash": "COPY_THE_64_CHARACTER_DOCUMENT_HASH_FROM_DISCLOSURE",
  "invitation": null
}
```

These are placeholders, not working credentials or a valid copied disclosure.
Agreement must precede sending names/passwords. The server can check the version,
hash, names and agreement flag, but cannot prove that somebody read the text.

3. Store the returned enrollment token in memory.
4. `GET /api/auth/mfa/setup`: the secret and `otpauth` URI are enrollment-only.
   Render locally. Never send them to an external QR-generation website.
5. `POST /api/auth/mfa/confirm` with `{"code":"YOUR_CURRENT_SIX_DIGIT_CODE"}`.
   Replace the token with the full-session token. Save the recovery codes once.
6. `POST /api/devices` with `{"label":"My laptop","public_key":"YOUR_LOCAL_PUBLIC_KEY"}`.
7. `GET /api/servers`: show country/city from operator inventory; labels are not
   independently geolocated. No servers are invented.
8. `POST /api/connections`:

```json
{"device_id":"COPY_DEVICE_ID","server_id":"auto","adblock":true}
```

The backend reserves addresses transactionally and provisions the public peer.
It returns public configuration and `waiting_for_client`, never fake protection.
Native software must add its own private key and apply the configuration locally.
WireGuard cannot distinguish public and private keys by length/encoding alone;
never paste a private key. No API schema accepts a `private_key` field.

9. `GET /api/connections/{device_id}`: retrieve server-side handshake evidence.
   Poll no faster than once per five seconds and stop on expired sessions.
10. `DELETE /api/connections/{device_id}` revokes server peer access. The native
    client must stop its own tunnel. This is not equivalent to signing out.

Repeated connect requests with the same device, selected server and DNS settings
reuse the allocation. An ambiguous timeout keeps the allocation until a confirmed
revocation. Changing server/DNS preferences requires an explicit disconnect first;
there is no unsafe promise of seamless switching in this backend.

## Authentication and account controls

| Method | Route | Behavior |
| --- | --- | --- |
| POST | `/api/auth/login` | Username, password, fresh TOTP or one unused recovery code. Password-only login returns enrollment scope only for incomplete enrollment. |
| POST | `/api/auth/logout` | Revoke this API token; active VPN service is unaffected. |
| POST | `/api/auth/mfa/reset` | Password plus fresh TOTP/recovery code; invalidate all sessions and old recovery codes; restart enrollment. |
| GET | `/api/me` | Basic account identity and role, no authenticator secret. |
| POST | `/api/consent` | Renew acknowledgment when document changes; same name/signature/agreed/version/hash fields as registration, no password/username. |
| POST | `/api/family/invites` | Owner creates a private one-use code valid one hour. Nothing is emailed or messaged. |
| GET | `/api/family` | Owner sees member IDs and usernames only. |
| DELETE | `/api/family/{id}` | Owner password + fresh code; revoke member's peers and delete their service account. UI must explicitly explain account deletion. |
| GET | `/api/devices` | Only this account's devices. |
| DELETE | `/api/devices/{id}` | Remove only this account's device after confirmed peer revocation. |
| DELETE | `/api/account` | Password + fresh code; revoke all affected peers, delete account and owned family accounts. Show the full consequence before confirmation. |
| GET | `/api/capabilities` | Explicitly expose unimplemented integrations. |

DELETE account/family endpoints accept JSON `{"password":"...","code":"..."}`.
Recovery codes are consumed once. A TOTP code already used for enrollment/login
cannot be reused; wait for a new code. Lost passwords or loss of all factors
cannot be bypassed through a pretend support/identity flow. External password
recovery and passkeys require additional design/integration.

## Honest evidence semantics

`protected: null` means protection cannot be verified, **not protected=true**.
`protected: false` on absent/revoked provisioning refers to this service, not other
VPNs or security tools a user may run. A fresh server handshake only indicates
recent authenticated peer contact; idle tunnels can have old handshakes without
being broken. The 180-second freshness cutoff is conservative, not malware logic.
Backend restarts lose in-memory warning transition history; persistent status is
always available by querying again.

`request_to_handshake_seconds` is server-observed timing, with integer-second
WireGuard timestamps. It is not total connection/protection time. Protection's
under-one-minute result stays null until a separately implemented trusted native
measurement checks routing, DNS, IPv6, and kill-switch behavior. Client-reported
booleans from arbitrary browsers are not accepted as proof.

The native client should track elapsed time with a monotonic clock, select servers
using actual local latency measurements if desired, manage OS permissions narrowly,
and announce status transitions through accessible controls. Never infer location
from a hash, IP routing from local hostname resolution, or VPN encryption from a
list of supported TLS ciphers. There is no generative AI in the decision path.

Errors have stable codes and plain-language messages/actions. Validation errors
name fields but do not echo submitted secrets. Inspect HTTP status; never treat
an error response as a successful tunnel. The backend has no arbitrary-host probe,
payload-upload, offensive scanning, or packet-inspection API.
