# What was actually verified

See the final actual Node run in `TEST_RESULTS.txt` and Linux-agent unit run in
`AGENT_TEST_RESULTS.txt`. These are execution results, not benchmark or real-user data.

Node tests execute TypeScript directly under Node 24.22.1 without third-party test
packages. They cover real SQLite transactions, application crypto, auth and route
handler Request/Response code. Shared demo tests inject an explicit atomic test
store; real WireGuard tests inject synthetic observations. Runtime providers never
select either test implementation.

Final result: **60 Node tests and 8 Python-agent unit tests passed**. The local
`npm run setup`, `npm run migrate`, and `npm run cleanup` commands also completed
successfully against a newly generated private development configuration/database.
Those runtime files are excluded from the delivered archive.

## Verified in automated tests

- AES-256-GCM round-trip and tamper rejection; salted scrypt validation; RFC TOTP
  vector and time-step replay rejection.
- Disclosure agreement/version validation and name minimization; enrollment scopes,
  session expiry/logout, one-use recovery and authenticator replacement.
- Family invitation limits/consumption and owner/member device isolation.
- Real local SQLite persistence/query/transaction behavior and API-handler flow.
- Repeat/concurrent allocation, partial provisioning, uncertain revocation,
  disabled-device deletion and retryable account deletion.
- Shared room counting, session/contact expiry, atomic rotation races, panic/reset
  races, invalid credentials/generations and stale operation rejection.
- Redis-adapter CAS invocation/error mapping; provider failures never silently
  produce a separate local fallback.
- Browser-local WebCrypto adapter behavior in Node's WebCrypto implementation;
  this is not a browser rendering or accessibility test.
- Bounded JSON, foreign-origin rejection, capability labels and secret-free errors.
- Python agent's fixed-interface commands, allowed-IP parser, allocation rejection,
  persisted sequence ordering and HMAC nonce/time/body checks using mocked wg output.

## Not verified here

The workspace network rejected package downloads from npm with HTTP 403. Therefore
`npm install`, Next.js build, TypeScript typecheck, dependency audit and browser
rendering were not completed. The supplied app code must pass those checks in your
development/deployment environment before release. No lockfile is invented.

No live Upstash Redis, PostgreSQL, Linux WireGuard interface, native Windows client,
TLS management endpoint, production load, leak tests or two-device network deployment
was available. Read the acceptance checklist and run those integrations on owned
infrastructure. No measured under-one-minute protection or one-to-two-second
cross-device result is claimed.

There are no real-user testing results, feedback-driven design changes, accessibility
certification, public source repository or hackathon eligibility claims. The code
was created on 2026-11-07; actual event timing/AI permission must be assessed honestly.

## Detection scope

There is no validated malware/phishing classifier. The backend reports server peer
presence and freshness only, with unknown device routing/DNS/IPv6/firewall status.
The 180-second contact threshold is a heuristic status boundary and can flag idle
tunnels; it is not evidence of a malicious destination or a real-world classifier
accuracy estimate. DNS policy quality likewise needs representative labeled cases
and controlled resolver tests. Never derive advertised false-positive/negative
percentages from tiny unit fixtures.
