# Acceptance and event checklist

## Before public sharing

1. Check event start/end and AI-assistance rules. Record actual work timestamps.
2. Install dependencies and retain the generated lockfile after review.
3. Run tests, `npm run typecheck`, `npm run build` and dependency/security review.
4. Verify APP_ORIGIN, HTTPS, master key, private room-creation credential and provider
   environment scopes. Ensure no secrets/data/private keys are committed.
5. Apply schema migration to a dedicated test PostgreSQL database, configure Redis,
   test actual adapters, expiry, concurrency and outage behavior before real users.
6. Review host/database/Redis/DNS metadata logging and publish actual processor/
   retention information. An app-level no-log statement does not control providers.

## Laptop presenter and phone judge

1. Create a room, share only judge URL (or frontend-generated QR), join on two phones.
2. Connect both; verify unique count=2. Repeated connect does not increase it.
3. Disconnect one; close/background the other and verify lease expiry excludes it.
4. Observe new ciphertext while fixed-mode payload hash stays identical. Use presenter
   proof to verify actual synthetic plaintext before panic.
5. Confirm panic on a judge device. Verify every visible screen receives panic, key
   indicator becomes absent, count=0 and ciphertext freezes. Time actual propagation.
6. Try connecting/heartbeat/rotation/reset as a judge after panic. State must not revive;
   reset must remain presenter-only.
7. Presenter resets; all old tokens/generation links are rejected. New invitation works.
8. Disconnect Redis/network. Show stale/unavailable status, never isolated false shared state.
9. Test missing Redis locally: banner says one-browser preview. Separate phones must
   not appear synchronized through a React-only fallback.

## Real service on owned infrastructure

1. Read disclosure, agree, enroll TOTP and save recovery codes privately.
2. Verify family members have separate auth and cannot access each other's devices.
3. Configure an actual WireGuard host/agent and filtered/plain resolvers. Register
   a native-generated public key, request config, keep private key on-device.
4. Activate native tunnel. Verify device routing, public egress, DNS, IPv6 and kill
   switch independently; a server handshake alone must never show protected=true.
5. Measure Connect-to-required-checks time after onboarding, including failures and
   timeouts; report observed results rather than assuming the 60-second target.
6. Test controlled blocked and allowed domains; disclose limitations/false blocks.
7. Interrupt provision/revoke responses. Retry safely without losing allocations.
8. Race a delayed provision with revoke; the persistent agent sequence rejects stale
   operations. Restart agent/interface and verify no revoked peer is restored.
9. Delete a device/account while management is unavailable; pending state remains
   explicit and deletions can be retried. Verify peers and SQL data afterward.

## Accessibility

- Keyboard-only completion, logical focus and visible focus ring.
- Screen-reader labels/errors, one panic transition announcement, quiet ciphertext updates.
- Meaningful text/icons without color dependence, contrast, reduced motion.
- Mobile reflow and enlarged text. No flashing crisis animation.
- Confirm destructive real-account actions clearly explain family-account effects.

## Real-user study (blank template)

Use pseudonyms; do not collect IDs, passwords or browsing data. Ask nontechnical
participants/busy developers to join, connect, interpret a warning, panic/reset
according to their role, and explain which behavior is simulated.

| Participant pseudonym | Task | Completed? | Time | Confusion/assistance | Warning understood? |
| --- | --- | --- | --- | --- | --- |
| Not yet tested | — | — | — | — | — |

| Event time | Observation | Change implemented | Retest | Remaining issue |
| --- | --- | --- | --- | --- |
| Not yet tested | — | — | — | — |

## Rubric mapping, not awarded scores

| Criterion | Backend evidence | Remaining evidence |
| --- | --- | --- |
| Usability/accessibility 25 | Simple API defaults, warnings, explicit modes, minimal console/mobile clients | Polished final UI, measured native one-button protection, human accessibility tests |
| Technical execution | Atomic rooms, encryption, account/SQLite integration, safe agent operation sequences | Next build, real Redis/PG, live WireGuard/native client and load tests |
| Tool security 15 | Scope boundaries, minimization, protected secrets, replay controls, threat model | Independent audit, deployed permissions/log retention, provider review |
| Innovation 10 | Inspectable crypto/panic demonstration and conservative evidence semantics | Judging assessment; no novelty or complete-protection claim |
| User tests/design feedback +2 | Script and blank logs | Actual eligible-event participants/change/retest |
| Accessibility +2 | Semantic controls, focus styles, quiet updates, confirmation | Keyboard/screen-reader/contrast/reflow validation |
| Open-source/README +1 | Source, MIT license, install/API/deployment docs | User-authorized publication and working verified install |

Avoid overbroad permissions (−3), undisclosed data transmission (−5), pre-event core
work or unauthorized offensive/malware actions (disqualification). No such eligibility
decision is made by this project, and no public deployment/repository was created.
