# Cyber One

A working hackathon website and API for privacy-focused household accounts, temporary-profile management, encrypted snapshots and an operator console. **This release is a VPN control-plane prototype. It does not implement a VPN tunnel.** It does not change public IPs, bypass network restrictions, encrypt device traffic, block system-wide ads, verify government IDs, or autonomously detect breaches.

## Start on Windows

1. Extract the entire ZIP first. Open the extracted `cyber-one` folder.
2. Install Node.js 22 or newer if needed. Run `node --version` to check.
3. Double-click `START-WEBSITE.cmd`. Keep its console open. Or open a terminal **inside that folder** and run:

   ```sh
   node setup.js
   npm start
   ```

4. Open http://localhost:3000. The operator console is http://localhost:3000/admin.
5. Open the newly created `.env` file locally and use the value after `ADMIN_SECRET=` for administrator sign-in. Never upload `.env` or share it with customers.

Local account storage uses Node built-ins; Gmail email delivery requires Nodemailer. The Windows launcher installs dependencies if needed; for manual startup run `npm install` once before `npm start`. Local records persist encrypted in `.data/state.json`. Keep `.env`: losing its encryption key makes stored records unreadable. Do not include `.data` or `.env` when sharing code. The browser may open before the server is ready; refresh if needed.

## What works

Unique normalized usernames; salted scrypt password hashing; ten cryptographically generated globally collision-checked case-sensitive reusable codes; staged authentication and per-login signed disclosure; one-hour server sessions; profile preferences; up to eight linked family logins; at most one temporary profile per household; deletion with a server-side two-second delay; encrypted snapshots and cutoff deletion; authenticated operator incident rehearsal with in-app notices; controlled URL rule checks; PostgreSQL persistence for a shared Vercel deployment.

The sample identity step requires a PNG or JPG image up to 2 MB. It sends sample image bytes to the backend for a basic file-format check, then discards them; images are never stored and this does not verify identity. Never use real identity documents. New accounts must wait ten seconds on the backup-code screen and confirm their codes are saved before continuing. The server also enforces this initial ten-second delay. Mini users have their own unique username, password and ten backup codes, and complete code verification and disclosure on each login. The main account creates these accounts from Account → Create family account; the branded signup page keeps the creator signed in and links the new login server-side. A mini user can change their own profile preferences and simulated VPN On/Off state but cannot create family users or delete shared data. Simulated profiles use documentation IP 192.0.2.42. Codes are shown once: record them before leaving. Email verification and username/password/backup-code recovery are now implemented. Real delivery sends from Cyber0neNorthCarolinaUSA@gmail.com and requires that Google account’s App Password; see `docs/05-EMAIL-RECOVERY-SETUP.md`.

## Family accounts and live status

1. Sign in to the main account and open **Account → Create family account**.
2. On the family signup page enter the member's name, a unique username, and matching passwords. The server links the new login to the main account automatically; it does not trust a browser-supplied parent ID.
3. Save that member's ten backup codes. Wait ten seconds and acknowledge they are saved, then return to the household.
4. The family member opens the website in another browser profile, private window, or device, and logs in with their own username, password and one of their own codes. They then complete the disclosure.
5. When they turn their simulated VPN profile On or Off, the main account's family list updates within five seconds. These are profile states, not proof of real VPN traffic or whether someone is online. Logout does not automatically disconnect a profile.

One household owns exactly one temporary profile. Each family login has its own active flag; the shared profile stays active while any member or the owner remains On. An active household's region cannot be changed underneath other users. The owner can turn individual mini users On/Off and remove their logins. Removing a mini user revokes its sessions and removes household application snapshots to prevent its credentials reappearing in backups. Deleting the main account cascades to all linked family logins. An incident turns everyone Off and locks the profile until owner deletion.

Existing mini-user labels remain intact after upgrading. Select **Set up login** next to an existing label to give it credentials without creating another member. Family logins can recover through their own verified email. Shared mailboxes are allowed and receive separate account-bound links.

## GitHub → Vercel → two laptops

1. Create an empty GitHub repository. Upload the contents of this folder, including `api`, `lib`, `public`, `package.json`, `vercel.json` and docs. Include `.gitignore`. Never upload `.env`, `.data` or `node_modules`.
2. Create a PostgreSQL database, such as a managed Neon database. Run `schema.sql` in the provider's SQL editor with a migration role. Create a separate runtime database role and grant only SELECT, INSERT and UPDATE on `cyber_state`.
3. In Vercel choose Add New Project → import your GitHub repository. Framework: Other. Root directory: the folder containing `package.json`. Output directory: `public`. Do not select static-only GitHub Pages; this application needs its API.
4. Add private Vercel environment variables: `DATABASE_URL` (TLS-enabled PostgreSQL connection string), `ENCRYPTION_KEY` (64 hex characters), `CODE_PEPPER`, `ADMIN_SECRET`, `CRON_SECRET`, and `DEMO_MODE=true`. Run `node setup.js` to create unique random values for your deployment. Do not prefix them with PUBLIC or expose them in client code. Use different secrets for different deployments.
5. Deploy. Vercel installs `pg` for PostgreSQL; local file mode does not load it. If you changed env variables after deploying, redeploy.
6. Configure account-recovery emails using `docs/05-EMAIL-RECOVERY-SETUP.md`: add `APP_URL` and `GMAIL_APP_PASSWORD` from the Google account Cyber0neNorthCarolinaUSA@gmail.com, then redeploy. Resend and EMAIL_FROM are no longer used. Without them, recovery remains unavailable.
7. Laptop B opens `https://YOUR-PROJECT.vercel.app/`. Laptop A opens `https://YOUR-PROJECT.vercel.app/admin`. Use separate browser sessions. Both see the same database. The admin console requires ADMIN_SECRET.
8. Verify registration, logout/login with a code, consent, temporary-profile creation, manual snapshot, incident delivery and deletion on the hosted deployment before presenting.

This package has not been pushed to your GitHub account or deployed to Vercel. Connected account credentials were not provided. PostgreSQL driver installation and hosted execution have not been verified in the build environment.

## Every-ten-minute backups

Local: the running server takes encrypted snapshots every ten minutes. Vercel: function processes do not run reliable background intervals. Configure an external scheduler to call the following every ten minutes with a bearer secret:

```text
GET https://YOUR-PROJECT.vercel.app/api/index?action=cron
Authorization: Bearer YOUR_CRON_SECRET
```

Alternatively, use Vercel Cron on a plan supporting that frequency, with this additional `vercel.json` property:

```json
"crons": [{"path":"/api/index?action=cron","schedule":"*/10 * * * *"}]
```

Check current plan limits before enabling. The default package intentionally omits a cron declaration so importing on a restricted plan does not fail. Manual “Back up & re-encrypt now” works without a scheduler. Requests are idempotent within a ten-minute window. Snapshot expiry (24 hours) is applied on the next backup job; scheduled execution is necessary for timely expiry. Monitor job failures. These snapshots are stored in the same application database and are not protection against complete database loss.

## Security design and limitations

- AES-256-GCM with fresh random 96-bit nonces for persisted state and household snapshots. Ciphertext changes while plaintext is preserved. This is not master-key rotation, and changing ciphertext does not stop a thief who has the encryption key. Keep key material in a proper secret store; production should use a managed key service and documented rotation.
- Passwords are salted scrypt hashes; backup codes are peppered HMAC-SHA256 hashes. Requested reusable codes are replayable and not phishing-resistant. Replace with passkeys or TOTP and one-time recovery codes for production.
- Runtime DB writes use parameterized SQL and a database advisory lock to enforce invariants across Vercel instances. A single encrypted state row is intentionally simple for small demos; it serializes work and cannot scale without redesign. Scrypt runs synchronously and adds latency under load. Replace with async/worker password hashing and proper relational per-user tables for production.
- Encrypted state includes session hashes and temporary rate limits. Brute-force attempts are rate-limited by username, plus global admin/registration budgets. This protects the small demonstration, but global throttles can cause denial of service. Production needs an external rate limiter, connection/IP policies, quotas and anti-automation defenses.
- Same-origin JSON requests, SameSite Strict HttpOnly session cookies and explicit Origin checks protect write operations. Secure cookies are enabled on Vercel. Local trusted-network HTTP is sample-only. CSP and no-referrer headers are set in Vercel config; no third-party analytics or assets.
- Per-login disclosure is enforced on the server. Typed signatures record acknowledgement only. Scrolling cannot establish comprehension. This is product disclosure, not a reviewed legal policy.
- Removing a temporary profile purges all household application snapshots because old snapshots might contain it. Account removal deletes account data, family credentials, consent, sessions and snapshots. It cannot erase copies already stolen, hosting-provider access logs, managed database backups or forensic disk remnants. Provider retention requires separate review.
- The application necessarily decrypts data to serve requests. Compromised server code, keys or administrator credentials are outside the protection of encryption-at-rest. Operator access can send simulated incidents and delete snapshots; protect the secret and never reuse a customer password.
- Incident reporting is simulated and operator initiated. Notices poll every five seconds while the connection page is open. There is no detection agent, incident email/push service or native VPN client integration. Account verification and recovery emails use the separately configured Gmail SMTP transport.
- The URL lab never fetches an entered URL. It blocks only the controlled `.test` rule, embedded credentials and unsupported protocols. Unknown does not mean safe. There is no network interception or browser-wide enforcement.

## Connecting a real VPN later

Keep this website as the control plane. Add separately hosted Linux WireGuard gateways, unique peer keys per device, a native desktop client/service with explicit OS consent, DNS filtering, IPv4/IPv6 routes and leak protection. One household temporary profile can own multiple device peers; never share a single private key across family devices. Gateways need real region/exit-IP inventory, peer revocation and health reporting. A cryptographic handshake and verified egress must determine Connected status. Tunnel disconnect, family controls, logout policy and deletion must revoke actual peers through an authenticated service adapter. Fail closed when health is unknown. A database lease alone provides no VPN protection.

Integrate an actual identity-verification provider with signed verified callbacks, deduplication tokens, deletion/retention controls and minimal data collection before changing DEMO_MODE. This prototype deliberately blocks new production registrations and VPN activation when DEMO_MODE is false. Do not advertise production protection until native client/gateway tests pass.

## Tests and prompts

```sh
npm test
npm run check
```

See `docs/01-FRONTEND-PROMPT.md`, `02-BACKEND-PROMPT.md`, `03-API-CONTRACT.md` and `04-DEMO-AND-RUBRIC.md`. These prompts describe the same implemented contract, honest demo boundaries and production path. Tests cover authorization stages, isolation, deletion, code behavior, household invariant, incidents, cryptographic tampering, backup cutoff and URL screening.

Recovery tests use mocked email delivery; no real emails were sent and no live provider delivery or Vercel deployment was verified.

No browser visual or screen-reader validation has been performed in the build environment. Perform keyboard, mobile and assistive-technology checks with your team before the demo. No real-user testing is claimed.

## Hackathon eligibility

Use only work permitted by your event rules. Record when this code was created and disclose AI assistance as required. Do not claim work was done during the event unless that is true. No offensive testing or live malware is included.

## References

- https://www.wireguard.com/quickstart/
- https://vercel.com/docs/functions/runtimes
- https://vercel.com/docs/cron-jobs/usage-and-pricing
- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

## License

MIT; see LICENSE. Review before publishing and do not publish secrets or sample accounts.

For generic server errors or admin-login failures, see `docs/06-SERVER-TROUBLESHOOTING.md`. This version logs safe storage-stage classifications without exposing connection strings or account contents.
