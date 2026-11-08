# Two-laptop demo: 3 minutes

Use the same hosted URL on both laptops. Laptop A opens `/admin`; Laptop B opens `/`. They must share the Vercel deployment and PostgreSQL database. Laptop A is an operator console, not the physical database center; Vercel/Postgres providers host the data. To physically store data on Laptop A instead, run the local server there and have Laptop B use `http://LAPTOP-A-LAN-IP:3000` on the same trusted network. This local HTTP option is for sample-only rehearsal, not real accounts.

0:00–0:20 Problem: families need understandable controls and deletion they can verify. Explain this is a working account/privacy control plane with simulated VPN data, not an active tunnel.
0:20–1:00 Laptop B: sign up with a sample ID acknowledgement, save codes, sign disclosure, activate the temporary profile. Returning-user activation after sign-in is one button. The full required onboarding may exceed a minute; time it honestly.
1:00–1:25 Create a family login from Account, save its codes, and sign in on another browser/device. Turn its profile On; the main account shows On within five seconds. Show the same temporary-profile ID. Submit `https://credential-check.test/signin` in the lab. It is blocked without a network request. Submit `https://example.com` and show Unknown, not Safe.
1:25–1:50 Laptop A: sign in with ADMIN_SECRET, create a snapshot twice and show ciphertext changes. Explain that data remains equivalent, nonces change, and the master key does not rotate.
1:50–2:20 Send a simulated incident for the active household. Laptop B sees the notice within five seconds and the profile pauses. It cannot reactivate while flagged. Delete the temporary profile and refresh Laptop A to verify snapshots disappeared.
2:20–3:00 Summarize what was implemented, what is simulated, the application's own attack surface, and the production gateway path. Do not claim a real public IP change, full phishing detection, ID verification or autonomous breach detection.

## Rubric evidence and honest limits

| Criterion | Implemented evidence | Limit / next step |
|---|---|---|
| Usability/accessibility 25 | One large toggle, plain errors, labels, focus, text statuses, responsive layout | Mandatory identity/code/disclosure process adds friction; time real users |
| Protective impact 25 | Enforced staged authentication, at-rest encryption, tenant authorization, deletion, controlled link rejection | Link lab is opt-in and tiny; VPN remains simulated |
| Technical execution 20 | Real HTTP API, persisted encrypted state, shared deployed DB, automated tests | Hosted DB and browser QA need validation in your environment |
| Tool security 15 | No real IDs, no analytics, server-only secrets, scoped DB role, sessions, CSRF origin checks | Global-state storage/lock is a small-event architecture, not large-scale production |
| Innovation 10 | Shared household ephemeral identity with visible snapshot deletion | Judges determine novelty; do not claim invention of VPN or encryption |
| Presentation 5 | Realistic harmless sign-in fixture, incident rehearsal, deletion story | Distinguish database actions from native network protection |

Bonus checklist: keyboard/screen-reader testing by your team; test with two people during the event, record their feedback and the actual change; open-source only work eligible under event rules with README/install steps. Never fabricate user testing or an event start time. No live malware or offensive actions are included.

## Suggested real-user feedback log
Person / task / time to activate / confusion observed / change made / retest outcome.
