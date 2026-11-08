# Email verification and recovery on Vercel

The website now requires a recovery email for new main and family accounts. Existing signed-in users can add an address in Account after entering their current password. Recovery can use an address only after its verification link is confirmed.

Vercel runs the API. PostgreSQL stores encrypted account records and hashed tokens. Resend delivers the emails; Vercel does not supply a mailbox or send account messages automatically.

## Configure real delivery

1. Sign in to Resend: https://resend.com . Review current service terms, quotas and costs.
2. Add a sending domain/subdomain you own, such as `auth.yourdomain.com`, and add the DNS records shown by Resend. Wait for verification. Your website can remain on a `vercel.app` address; the sending domain is separate. Do not attempt to verify `vercel.app`, which you do not own.
3. Create a sending API key scoped to the sending domain where supported. Keep it private. Disable click/open tracking for transactional recovery messages.
4. In your Vercel project, open Settings → Environment Variables and add these for the Production environment:

   | Variable | Example / purpose |
   |---|---|
   | `APP_URL` | `https://your-project.vercel.app` — exact origin, no path/query/fragment |
   | `RESEND_API_KEY` | Your private sending key |
   | `EMAIL_FROM` | `Cyber One <accounts@auth.yourdomain.com>` — must use your verified sending domain |

5. Keep the existing `DATABASE_URL`, `ENCRYPTION_KEY`, `CODE_PEPPER`, `ADMIN_SECRET`, `CRON_SECRET` and `DEMO_MODE=true`. Do not change existing encryption keys when updating.
6. Push this updated project to the GitHub repository connected to Vercel and deploy/redeploy. Environment changes require a new deployment. Never commit `.env` or `.data`.
7. The package sets a 30-second API function duration; check that your selected Vercel plan supports it. Recovery requests use an approximately nine-second response floor, with a bounded eight-second email-API request, to reduce account-existence timing differences. This is mitigation, not a guarantee against timing analysis under load or slow database responses.

## Test the actual deployment

1. Create an account with an email address you control. Record its ten codes; the initial ten-second hold still applies.
2. Open the verification email. The link opens a confirmation screen; press Verify email. Visiting a link alone does not consume it, which reduces accidental consumption by email scanners.
3. Sign in and open Account. Confirm the recovery email is marked Verified.
4. On the login page choose “Forgot username, password or codes?” and request a username reminder. The username is emailed, never displayed to an unauthenticated requester.
5. Request password recovery, open its email link, and choose a new matching password. Existing codes still work; old sessions for that account are revoked.
6. Request backup-code recovery. The link requires the current password before replacing all ten codes. If both password and codes are lost, select the combined recovery option, which uses verified-mailbox possession to reset both.
7. Save replacement codes before leaving. The ten-second countdown and saved-code acknowledgement also apply to replacement codes. Sign in again normally and complete the disclosure.
8. Try a used link and an expired link. Both must fail. Then test a family account and confirm its recovery does not change the main account's password or revoke sibling sessions.

Password/code recovery links expire after 15 minutes; email-verification links after 30 minutes. Credentials are not reset on merely requesting or opening a link. Recovery completion requires an explicit form submission. Successful recovery invalidates all other outstanding links for that account, revokes its sessions, pauses its own simulated profile, and removes household application snapshots containing its old credentials. Another active household member can keep the shared profile active.

## Existing accounts and family accounts

Existing accounts remain usable without email, but cannot use email recovery until an address is added and verified from a fully signed-in session. Adding or changing an unverified address requires the current password. A verified address cannot be changed in this version; a safe old-and-new-address change process is future work.

Family mini accounts have their own email fields and verification status. Multiple accounts may share a mailbox; recovery emails then include separate account-bound links, and the requester can optionally specify a username. A shared mailbox controls recovery for every account that verified that mailbox. The family creator remains signed in when creating a mini user; verification goes to the mini user's entered address. The main account cannot silently change an already-verified mini-user email via these endpoints.

The application does not implement manual owner/admin password resets for family users in this release. Recovery uses the member's verified email. Main-account deletion removes every linked account's recovery records; mini-user removal removes that member's records.

## Missing configuration, failed delivery and privacy

Without email-service settings, accounts can still be created and their entered email is saved as unverified. The UI says delivery is not configured. No recovery link is printed in a console, displayed by the administrator, or returned to the browser as a debug shortcut. Recovery requests fail closed while delivery is unconfigured.

If a provider call fails after registration, the account and displayed backup codes still exist. Sign in and resend verification from Account after correcting the settings. If a recovery email fails or never arrives, request a new link after checking inbox/spam and provider status. Only a generic response is shown to unauthenticated requesters, whether or not an eligible account exists. Provider acceptance does not guarantee inbox delivery. There is no durable delivery queue or bounce-webhook integration in this prototype; production should add delivery monitoring and a durable outbox/worker.

Provider API requests use an idempotency key and are awaited before the function completes. Tokens are generated cryptographically, stored as SHA-256 hashes, expire and work once. Email links use the configured `APP_URL` rather than a client-supplied host header. Tokens travel in the URL fragment, are removed from the address bar when the app loads, and are sent to the API only in JSON bodies. Do not enable analytics or request-body logging on these endpoints. The email provider necessarily processes the recipient address, username and message/link contents; review its retention policy separately. Never email passwords or backup codes themselves.

Reset requests are limited by email address and a global budget. Code-reset password attempts, email additions and verification resends have separate limits. These are a small-demo defense; use a shared external rate limiter and delivery/abuse monitoring before scaling. Anyone who controls a verified mailbox can use combined recovery to gain account access: email recovery is not phishing-resistant MFA. There is no recovery route for a person who lost access to both their credentials and their verified mailbox.

Recovery and verification do not require a Vercel cron job. The ten-minute snapshot job remains separate. Locally you can configure the same provider variables in `.env` and set `APP_URL=http://localhost:3000`; for links opened from another device, use a deployed HTTPS website.

## References

- https://resend.com/docs/api-reference/emails/send-email
- https://resend.com/docs/dashboard/domains/introduction
- https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
