# Validation and event evidence

Automated checks run in this workspace using Python 3.12.14, FastAPI 0.141.1,
Uvicorn 0.52.1, httpx 0.28.1 and cryptography 50.0.0. See `TEST_RESULTS.txt` for
the final actual test run. The environment emits a deprecation notice for httpx
in Starlette's test client; tests currently execute successfully. It is not a
failed security or connection check. Upgrade the test-client dependency path
deliberately when migrating to a newer test transport.

## What was checked

- Registration, actual TOTP algorithm and replay prevention, one-use recovery.
- Agreement version/hash/name matching and no plaintext-name consent storage.
- Restricted enrollment tokens, logout/expiry, authenticator replacement.
- Family invitation limits and cross-family device isolation.
- Realistic server-observation decision logic, without conflating it with protection.
- Repeat connection/address allocation, parallel allocation, failed setup tracking.
- Failed revocation preserves allocation and permits deliberate retry.
- Unknown server, malformed requests/keys, bad origin, oversized request handling.
- A broker parser fixture matching the actual WireGuard allowed-ips output format.
- DNS rule syntax/allow exceptions, reserved DNS addresses, no arbitrary URLs.
- Python compilation, JavaScript syntax, HTTP static assets and generated OpenAPI.

All broker replies in automated integration tests are synthetic and injected into
the test app. They are never offered as live evidence in the running demo. Default
runtime connects only to configured local Unix brokers; there is no simulation
mode that reports users as protected.

A Chromium interaction test was attempted, but this environment blocked the
browser's process socket. Therefore rendered browser behavior, responsive visual
layout, keyboard operation and screen-reader output were **not verified** here.
Semantic labels, focus styles, text-based warnings, live-region attributes and
minimum control sizes are implemented in the demo, but human checks remain.

No real VPN host/native client or identity provider was available. Live WireGuard
provisioning, real routing/NAT, ad blocking, external-IP change, kill-switch
behavior, production capacity and under-one-minute device protection are untested.
The application does not label those results successful.

## Detection assessment

There is no validated malware/phishing classifier in this build. The original
entropy/port/byte-pattern scores were removed because they cannot support the
claimed calibration. A DNS miss or an idle handshake does not prove an attack.

Eight explicitly labeled synthetic cases test the **recent-contact** predicate:
two recent-present cases and six stale/future/absent cases. The test expects zero
misclassifications on that tiny fixture set. This is a boundary-condition test,
not a real-world false-positive/negative estimate or proof of VPN protection.
The DNS compiler is tested for syntax/explicit rule generation; ad-list recall
and false-block rates require a representative labeled dataset and live resolver.

## Real end-to-end checklist on owned infrastructure

1. Finish the deployment guide. Verify actual server key, endpoint, tunnel
   addresses, firewall isolation, plain/filtered DNS and IPv6 behavior.
2. Register a test user, agree, enroll an authenticator and keep recovery codes.
3. Register a native-generated public key, request a connection, import public
   settings plus local private key and activate the native tunnel.
4. Observe handshake evidence; independently check device routing/public egress,
   DNS/IPv6 behavior and an enforced kill switch. Do not turn a server handshake
   into a blanket green “Protected” badge.
5. Block the controlled endpoint/network, verify warning timing and local traffic
   blocking. Check that idle traffic alone does not produce a misleading attack claim.
6. Lose connectivity during provision/revoke. Confirm retries reuse allocation and
   no orphaned peer is silently forgotten. Restart interface/API and reconcile.
7. Verify two family accounts cannot read or change each other's devices. Verify
   removing a member deletes that service account only after peer revocation.
8. Delete accounts. Inspect application records and live peers; apply the separate
   disclosed backup/log policy. Confirm no packet/domain histories in app logs.

## Under-one-minute usability measurement

Start timing after onboarding when the participant presses the native Connect
button. Stop only after actual required protection checks pass. Record failures
and timeouts rather than omitting them. Backend request-to-handshake timing alone
is not the target metric.

| Participant pseudonym | Nontechnical/busy developer | Task completed? | Time to verified protection | Confusion/assistance | Warning understood? |
| --- | --- | --- | --- | --- | --- |
| Not yet tested | — | — | — | — | — |

Ask participants to connect, switch server, respond to lost contact, revoke a
device, and explain the disclosure in their own words. Do not collect real IDs,
passwords, browsing activity, or unneeded identifying notes in research logs.

## Accessibility checks to conduct

- Complete each task using keyboard only; ensure focus stays visible and logical.
- With a screen reader, verify every field name, error and connection transition.
- Confirm warnings remain understandable in grayscale/colorblind modes.
- Check zoom/reflow at 200–400% and on a narrow viewport.
- Ensure critical loss is announced once on transition while its banner persists.
- Confirm account deletion explains the effect on family accounts before submit.

## Feedback and event log (blank by design)

| Event time | Participant pseudonym | Observed issue | Change made | Retest outcome |
| --- | --- | --- | --- | --- |
| Not yet tested | — | — | — | — |

Record event start/end, AI-use rules, work timestamps and team contributions. Do
not claim this code was written during an event unless that is true. Nothing in
this bundle establishes hackathon eligibility, user-test bonus points or judging
scores. The generated code's creation date is 2026-11-07; event timing was not provided.
