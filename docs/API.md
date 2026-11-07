# API contract

Base: `/api`. Route handlers use the Node runtime. Bodies are JSON objects, max
16 KiB, with strict field/type checks. Errors have `code`, `message`, `action`,
`retryable`, and severity; submitted secrets are not echoed. Responses are no-store.

Pass credentials as `Authorization: Bearer VALUE`, not query parameters. Same-origin
browser mutations are enforced when Origin is present. No permissive CORS or
cookie-based authentication is configured. Native/CLI clients may omit Origin.

## Public configuration

| Method/path | Description |
| --- | --- |
| GET `/health` | Service availability, never a protection claim |
| GET `/config` | shared/local-preview/setup-required and integration capabilities |
| GET `/disclosure` | Current document/version/hash before real-service data collection |

## Shared judge rooms

| Method/path | Credential/body |
| --- | --- |
| POST `/demo/rooms` | Private operator creation bearer; `{ "payloadMode": "fixed" }` or `count` |
| POST `/demo/rooms/{code}/join` | Public invitation possession; `{ "generation": 1 }` |
| GET `/demo/rooms/{code}/state?generation=1` | Presenter or own judge bearer |
| POST `/demo/rooms/{code}/connection` | Judge bearer; `{ "generation":1, "connected":true }` |
| POST `/demo/rooms/{code}/heartbeat` | Judge bearer; `{ "generation":1 }` |
| POST `/demo/rooms/{code}/panic` | Presenter or judge bearer; `{ "generation":1, "confirmed":true }` |
| POST `/demo/rooms/{code}/reset` | Presenter bearer only; `{ "generation":1 }` |
| GET `/demo/rooms/{code}/proof?generation=1` | Presenter only; synthetic plaintext proof while key exists |

Creation/reset returns `presenterToken`, `joinUrl`, `state`. Join returns
`sessionToken` and `state`. Keep tokens in memory; judge links contain only public
room invitation code/generation, never presenter credentials. Reset rotates the
presenter token; old tokens/generations fail. Losing a reset response may require
creating a new room; this is safer than exposing recoverable presenter credentials.

Poll state approximately once per second while visible. Send heartbeat about every
five seconds for an active judge; connected leases last 15 seconds. An already
expired lease is not revived by a heartbeat; reconnect explicitly. Judge sessions
last up to ten minutes of activity and never outlive the 30-minute room lifetime.
Count drops immediately on disconnect/panic and logically on lease expiry when next read.

Rotation advances on authorized polling/requests every three-second epoch. If nobody
makes requests, there is no independent worker. No historical rotations are fabricated
to fill gaps. Fixed mode encrypts the same canonical synthetic payload; count mode
includes only a synthetic connection count. Every new epoch uses a random 256-bit
key and 96-bit nonce, with room/generation/epoch authenticated as context.

Panic is an atomic terminal state for that generation: key=null, active leases=0,
envelope unchanged. All later writes recheck the panic flag/generation. Reset is
presenter-only and invalidates previous sessions while retaining the original room
absolute expiry. Public responses use selected fields, not serialized internal state.

## Real-service accounts

Registration example, using actual values returned by `/disclosure`:

```json
{
  "username":"your_username",
  "password":"your own password of at least 12 characters",
  "name":"Your Name",
  "signature":"Your Name",
  "agreed":true,
  "disclosureVersion":"COPY_CURRENT_VERSION",
  "documentHash":"COPY_CURRENT_DOCUMENT_HASH",
  "invitation":null
}
```

Placeholders above are not working credentials. The name is processed transiently;
the database retains a keyed per-account attestation/version/time/receipt. Matching
typed names is acknowledgment, not identity proof or proof of reading.

| Method/path | Behavior |
| --- | --- |
| POST `/auth/register` | Fields above; returns enrollment token; blocks if ID required but unavailable |
| GET `/auth/mfa/setup` | Enrollment bearer only; secret/otpauth URI, never external QR generation |
| POST `/auth/mfa/confirm` | Enrollment bearer; `{ "code":"CURRENT_SIX_DIGIT_CODE" }`; full token + one-time display of recovery codes |
| POST `/auth/login` | `{ "username":"...", "password":"...", "code":"..." }`; fresh TOTP or unused recovery code |
| POST `/auth/logout` | Revoke this website token; does not stop a native tunnel |
| POST `/auth/mfa/reset` | Full bearer + password/fresh code; revoke sessions/recovery codes, restart enrollment |
| GET `/me` | Basic role/MFA status, no authenticator secret |
| POST `/consent` | Authenticated; name/signature/agreed/disclosureVersion/documentHash |
| POST `/family/invites` | Owner bearer; `{}`; one-use code expires in one hour |
| GET `/family` | Owner sees member IDs/usernames only |
| DELETE `/family/{id}` | Owner password/fresh code; deletes the member service account after revocation |
| DELETE `/account` | Password/fresh code; deletes own account and any owned family accounts after revocation |

Username: 3–32 lowercase letters/digits/underscores. Password: 12–128 characters;
no arbitrary composition requirements. Sessions: 10-minute enrollment, 30-minute full.
Repeated use of an accepted TOTP time step is rejected. Save eight one-use recovery
codes privately. Losing password/all factors has no pretend recovery bypass.

Pending-deletion accounts cannot do ordinary work. If revocation fails, sign in with
password/fresh factor to obtain a deletion-only token and retry DELETE `/account`.
Each authentication consumes its code; use a new TOTP time step or another unused
recovery code for the subsequent deletion confirmation.
Do not expose that token to other endpoints. Changed disclosure/ID policy does not
block authenticated revocation or deletion.

## Real device/VPN control

| Method/path | Behavior |
| --- | --- |
| GET `/servers` | Public inventory labels for authenticated user; no management credentials |
| POST `/devices` | `{ "label":"Laptop", "publicKey":"DEVICE_PUBLIC_KEY" }`; five-device limit |
| GET `/devices` | Only own devices |
| DELETE `/devices/{id}` | Disable new use, revoke peer, delete after confirmed removal |
| POST `/connections` | `{ "deviceId":"ID", "serverId":"auto", "adblock":true }` |
| GET `/connections/{id}` | Sanitized server-side contact evidence |
| DELETE `/connections/{id}` | Revoke peer; native client still stops its own interface |

Public/private WireGuard keys share an encoding format; the backend cannot reliably
detect a private key pasted into `publicKey`. Generate locally and check before
submission. No API accepts a `privateKey` field. Configurations contain only public
server settings, tunnel addresses, DNS choices and native-client obligations.

Auto selects the first responding management service in configured order, not the
measured fastest network path. No live load/throughput/region/IP values are invented.

Retries reuse allocation and operation sequence. Disconnect increments a persistent
sequence; the agent rejects older operations, so a late provision cannot undo revoke.
Uncertain operations retain records. Changing server/DNS preferences requires an
explicit disconnect. After deleting and re-adding a device, generate a new key pair;
the management ledger intentionally remembers old-key sequence tombstones.

`protected:null` means unknown, not true. A recent handshake (180-second cutoff)
means authenticated server contact only; idle tunnels can be stale while still usable.
Native route, DNS, IPv6, public egress and kill-switch checks are not supplied here.
The under-one-minute **protection** outcome therefore remains null. Request-to-handshake
timing is distinct and uses coarse server timestamps. Warning codes are persistent
and include announcement hints; the client must keep banners visible and deduplicate.

## Explicit unavailable integrations

Passkey, identity and alias paths return an unavailable/not-integrated error. No ID
upload, verification success, alias creation or third-party account is fabricated.
`src/providers.ts` documents extension interfaces. Implement and test provider callback
authentication, minimization, expiry and deletion before enabling them.
