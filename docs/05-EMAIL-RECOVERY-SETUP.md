# Gmail verification and recovery on Vercel

The sender for this version is fixed in `lib/email.js`:

**Cyber0neNorthCarolinaUSA@gmail.com**

The character after Cyber is the digit zero. The authenticated Gmail account and From address both use that exact address. Resend is no longer used. Gmail can deliver to other users' email addresses; no custom sending domain is required. Google still applies sending limits, abuse checks and spam filtering, and may block cloud-server sign-ins. This is a small hackathon/demo setup, not a guaranteed production mail service.

## Get the Google App Password

1. Sign into the Google account **Cyber0neNorthCarolinaUSA@gmail.com**. Confirm the account avatar shows that exact account if multiple Google accounts are open.
2. Open https://myaccount.google.com/security and enable **2-Step Verification**.
3. Open https://myaccount.google.com/apppasswords . Google may ask you to sign in again.
4. Create an App Password named `Cyber One Vercel`.
5. Copy the generated 16-character App Password privately. This is NOT your ordinary Gmail password. Google may display it in four groups; this code strips display spaces automatically.
6. If App Passwords are unavailable, check Google's account restrictions: https://support.google.com/mail/answer/185833 . This implementation does not yet include Google OAuth setup. Do not turn off account security or use your normal password as a workaround.

Never send the App Password through chat, commit it to GitHub, add it to browser JavaScript, or show it in screenshots. It is a credential for the dedicated sender account. Revoke it in Google if exposed. Merely typing the email address in the code does not authorize sending.

## Configure Vercel

In the Vercel project → Settings → Environment Variables, add:

| Key | Value |
|---|---|
| `GMAIL_APP_PASSWORD` | The private Google App Password created on the account above |
| `APP_URL` | Your actual production origin, such as `https://your-project.vercel.app`; no path/query/fragment |

Keep existing database, encryption, administrator and cron secrets unchanged. This Gmail version does not read `RESEND_API_KEY` or `EMAIL_FROM`; old entries may be removed to avoid confusion. The sender is already set in code, so you do not need to create a `GMAIL_USER` variable.

Push this updated project's contents to the repository connected to Vercel, then deploy/redeploy. Vercel installs `nodemailer` from `package.json`. The API remains a Node function with a 30-second maximum duration. SMTP uses Gmail port 465 with verified TLS, bounded connection timers and an eight-second overall send deadline. Delivery requests are awaited after account/token state is committed.

## Test

1. Create a Cyber One account using a real recipient email address that you control. The recipient can differ from the sender Gmail account and can use another email provider.
2. Save the ten backup codes, then complete disclosure.
3. Find the verification message sent by Cyber One. Check spam if necessary. Open its link and press **Verify email**.
4. Under Account confirm the recovery email is Verified. Existing accounts can add an email from Account by supplying their current password.
5. Log out and choose **Forgot username, password or codes?** Request a username reminder or recovery link.
6. Verify password-only reset preserves codes, code-only reset requires the current password and replaces codes, and combined recovery resets both after proof of mailbox access.
7. Replacement codes appear only once, with the existing ten-second hold and saved-code acknowledgement. Old codes and old sessions for the recovered actor stop working.

A successful SMTP acceptance means Gmail accepted the message, not that it reached the inbox. Check the sender's Google account security notices and sending limits if messages fail. Requests show generic results to avoid revealing whether an account exists; the operator can check generic server errors without logging message contents or credentials. There is no durable retry queue or bounce integration. Do not repeatedly resend blindly: SMTP does not guarantee exactly-once delivery after a timeout.

## Local use

The Windows launcher installs packages if Nodemailer is missing. For a manual launch:

```sh
npm install
node setup.js
npm start
```

Add `GMAIL_APP_PASSWORD` to your existing private `.env`; setup preserves existing files and does not overwrite keys. Use `APP_URL=http://localhost:3000` only when opening links on the same laptop running the server. Use the deployed HTTPS origin for other devices.

## Security and lifecycle

Required email fields, verified-address gating, single-use hashed tokens, rate limits, family isolation, per-login disclosure and snapshot deletion behavior are retained. Verification links expire after 30 minutes; recovery links after 15 minutes. Link tokens use URL fragments and are removed from the address bar when the app loads. Messages contain recovery links, never passwords or backup codes. Google processes recipient addresses and message contents under its own policies.

Shared family mailboxes are allowed, but that mailbox can recover every linked account that verified it. Family recovery revokes only that member's sessions and pauses their profile; other active members can keep the shared profile active. The owner cannot silently replace a mini user's verified email. Verified address changes and manual operator password resets are not implemented.

Successful recovery removes the household's application snapshots containing old credentials and invalidates outstanding links for the actor. Main-account deletion removes all family recovery records; mini-user removal removes that member's records. There is no recovery if someone loses credentials and access to the verified mailbox.

The request endpoint retains an approximately nine-second response floor to reduce timing differences, not a guarantee against timing analysis under load. No cron is required for email recovery; the snapshot scheduler is separate.

## Validation limits

Automated tests use a fake SMTP transport; no live emails were sent. Package installation was blocked by registry access restrictions in the build environment, so the installed Nodemailer runtime, actual Google authentication, SMTP egress from Vercel, inbox delivery and live PostgreSQL remain unverified. Install dependencies and run the real deployment checks before presenting.

## References

- https://support.google.com/mail/answer/185833
- https://developers.google.com/workspace/gmail/imap/imap-smtp
- https://nodemailer.com/guides/using-gmail
- https://nodemailer.com/smtp
