# Shared frontend/backend contract

All browser calls: `POST /api/index?action=ACTION`, JSON body, same-origin credentials.
Response: JSON object; failures use HTTP 400/401/403/404/409/429/503 and `{ "error": "Plain-language next step" }`. Never return sensitive database errors.
GET `/api/index?action=cron` accepts `Authorization: Bearer CRON_SECRET` from the external scheduler, not a customer cookie.

| Action | Input | Response / effect |
|---|---|---|
| config | {} | demo, storage |
| register | username, email, password, confirm, sampleVerified:true, sampleImage:base64 PNG/JPG (max 2 MB decoded) | codes[10], stage:codes; disclosure-stage session cookie |
| codes-saved | {} | stage:disclosure; rejects requests before ten-second initial hold elapses |
| login | username, password | stage:code; new session cookie |
| code | code | stage:disclosure |
| consent | privacy:true, terms:true, signature | user; session becomes ready |
| me | {} | stage; user only after ready |
| logout | {} | ok; session revoked, cookie cleared |
| profile | name, notify:boolean | user |
| family-add | name, username, email, password, confirm; optional id to upgrade an existing label | user, codes[10], familyCreated:true; max eight linked logins; creator session remains signed in |
| family-codes-saved | {} | ok after ten-second family-code hold |
| family-toggle | id | user; shares owner lease |
| family-remove | id | user |
| connect | location: Auto / United States / Germany / Singapore | user; toggles simulated profile, stable lease ID |
| disconnect | {} | user; profile paused, retained |
| lease-delete | {} | user; profile, alerts and owner snapshots removed |
| delete-start | {} | readyAt: epoch milliseconds |
| account-delete | confirm: exact phrase | ok; permanent application cascade |
| screen | url | decision: blocked / invalid / unknown, reason |
| admin-login | secret | ok; separate operator session |
| admin-state | {} | counts, pseudonymous household references, snapshot ciphertext/IV/times |
| admin-backup | {} | ok; fresh encrypted snapshots |
| admin-incident | reference | ok; incident-marked profile paused |
| admin-purge | before:ISO date, confirm:Delete selected backups | deleted:count |

`user`: username, name, email, emailVerified, notify, role:owner/mini, householdUsername, family[], lease|null, alerts[].
`family`: id, name, username, hasLogin, active. Only the owner sees family entries. Password and code hashes never leave the server. Mini sessions have their own actor and link back to the household.
`lease`: id, created, ip (documentation address), mode:simulation, location, active (requesting actor), sharedActive (any household actor), incident?.
`alert`: at, text, demo:true.

The frontend cannot grant consent, verify a code, create a lease, act as administrator, or delete data without successful backend responses. All relevant operations enforce the server session stage. The server owns timestamps, deletion delay, identifiers and code creation.

## Email verification and recovery

| Action | Input | Effect |
|---|---|---|
| email-add | email, password | Fully signed-in actor adds/replaces an unverified address; password required. Sends verification if configured. |
| email-send-verification | {} | Fully signed-in actor resends own pending verification email. |
| verify-email | token | Confirms mailbox ownership with a single-use 30-minute token; no auto-login. |
| recovery-request | email, purpose:username/password/codes/all, optional username | Generic response regardless of matching accounts; emails only verified addresses. |
| recovery-info | token | Reveals the bound username and purpose only to token holder. |
| recovery-complete | token, password, confirm for password/all | Resets credentials, revokes affected actor sessions and links, pauses actor's profile, purges household snapshots; returns new codes only for codes/all. |

For purpose `codes`, `password` means the current password and no confirmation is needed. For `all`, verified mailbox possession authorizes a new password plus new codes. Recovery tokens expire in 15 minutes, are single-use, and never appear in unauthenticated request responses. Email dispatch is awaited after database commit. Link URLs use server-configured APP_URL.
