# Consolidated development prompt and supplied criteria

This preserves the requested product direction and rubric as project input. It is
not a claim that every requirement is complete. Consult README.md and VALIDATION.md
for actual implementation status. Original supplied code is in `originals/`.

## Prompt

Build the backend for my privacy-focused VPN app, following the product requirements
and judging criteria below. Explain decisions in beginner-friendly language and
provide complete code, setup instructions, and meaningful tests.

Target a Windows desktop client with Linux VPN servers. Clearly separate backend
responsibilities from desktop-client responsibilities. Use an established VPN
protocol such as WireGuard instead of inventing encryption.

### 1. Usability and accessibility — 25 points

After completing identity screening, account creation, and authentication setup,
a nontechnical user should activate protection in under one minute, without a
manual. A busy developer should have the same low-friction experience.

Provide a one-button connection flow that automatically chooses a healthy suitable
server by default, establishes an encrypted tunnel, routes supported traffic through
the server, changes public IP as seen by services, requests optional ad/tracker
blocking by default, shows actual connection state and country/city, and supports
manual server selection and Off. All controls must reflect actual connection state.
Handle failure with a clear next step rather than a false successful result.

Measure the one-minute target from the onboarded user's Connect press until required
checks succeed. Report measurements, not assumptions. Encryption protects the
device-to-server tunnel; do not promise anonymity, GPS changes, complete data-theft
prevention or bypass of every local restriction. If a network blocks VPNs, report
that honestly. Use familiar terms, secure defaults, minimal choices and advanced
settings only when needed.

### 2. Plain-language, actionable warnings

Return stable error codes, severity, explanations, actions and retryability.
Disclose/obtain agreement before collection. During connection show progress without
needless popups. On failure explain recovery. If protection drops, state what is
known and whether traffic is blocked. Explain consequences before disabling a kill
switch. Missing/stale evidence means unknown, not protected. Distinguish unavailable
ad blocking from unavailable VPN service. Deduplicate repeated warnings, retain
persistent status, and interrupt only when action is immediately needed.

### 3. Disclosure and agreement

Explain data items, purposes, local/external processing, recipients, retention,
deletion, operational logs and user controls before collecting personal information.
Require the user to type their name and explicitly agree. Treat that name as
personal data; retain minimal agreement evidence including version and time. A
typed name does not prove reading, identity, legal compliance or guaranteed privacy.
Keep optional analytics consent separate. Never silently collect/transmit data.

### 4. Accounts, family profiles, verification

One free main account plus three additional family profiles initially, with a
configurable design direction for future limits. Each member has separate
authentication, devices and private settings. Main account manages invitations and
membership without automatically accessing credentials or browsing activity.
Support authenticator verification or passkeys, secure recovery, session expiry and
device revocation.

Original proposed onboarding: open app, disclosure/explicit agreement before
collection, physical-ID screening, account username/password, authenticator/passkey,
then account home. Evaluate whether ID checks are necessary, keep verification
results instead of raw ID documents wherever possible, use a replaceable reviewed
provider integration, and clearly label development mocks. Explain how family
verification and failed/interrupted onboarding work. Do not claim ID checks eliminate
bots, fake accounts, scams or cyberattacks. The user originally proposed saving ID
with the account; minimization and privacy must be reconciled before implementing
that proposal.

### 5. VPN screen and region selection

Central connect/disconnect button with Server, Auto and Off controls. Connect uses
selected server; pressing while on disconnects; Auto selects a suitable available
server based on actual evidence when measurements exist. Show server country/city.
Make server switches controlled and disclose interruptions. Explain changing public
IP versus GPS, cookies and service availability. The backend must not treat issued
configuration as proof of a working native tunnel.

### 6. Temporary identities

Help users avoid exposing actual personal data to external services. Clarify temporary
VPN access versus email aliases versus external accounts. A feasible interpretation
is revocable email aliases with expiration and proportionate abuse controls. Do not
pretend a VPN can automatically replace personal data with “the VPN's data” or create
third-party accounts. The user's goal includes reducing credential theft, secret
leakage, abuse through fake accounts, scams, and negative outcomes while retaining
strong privacy.

### 7. Technical execution

Deliver a working core demo: disclosure, agreement, account/authentication, ready
screen, Connect, verified connection status, Disconnect. Identify development mocks
and external infrastructure. Handle malformed input, expiry, unauthorized profile
access, unavailable servers/providers, timeouts, duplicate requests and interrupted
operations.

Use actual system observations for claims: tunnel status, handshake freshness,
routing and public IP only where verifiable. Never fabricate addresses, availability,
ID results, successful blocking or protection. Validate external responses; missing,
inconsistent or malformed evidence stays unknown/unavailable. No AI-generated
security verdicts or invented certainty. No system can guarantee all received data
is truthful just because it has valid syntax.

Detection logic must identify the target, explain decisions, use labeled evaluation
cases, and report measured false positives/negatives and limitations. Do not invent
accuracy rates or claim arbitrary hostname entropy is a calibrated malware detector.

### 8. Security of the tool itself — 15 points

Least privilege, no unnecessary collection, correct secret handling, local processing
where practical, and an attack surface the team can explain. Generate private VPN
keys on-device and keep them there. Hash passwords; exclude secrets from code/logs.
Separate account management, identity verification and traffic handling. Scope
privileged operations narrowly. Authorize every account/profile/device/admin action.
Document operational data, retention, deletion and operator visibility. Avoid
browsing history/traffic-content storage by default. Explain DNS/IPv6 and native
kill-switch responsibilities, key rotation, revocation and deletion.

Threat model: login/recovery/passkeys, ID uploads/callbacks, invitations/permissions,
temporary identities, devices/configuration, APIs/database/servers, admin tools,
privileged native components and updates. For each explain assets, entry points,
trust boundaries, threats, protections and remaining limitations.

### 9. Innovation — 10 points

Propose a feasible differentiator beyond a wrapper for an existing API. One option
is an evidence-based protection status showing exactly which checks passed, failed
or remain unknown and what to do next, without unnecessary traffic collection.
Do not claim novelty or that it has never been done without evidence.

### 10. Accessibility and event bonuses

Accessibility built in: screen-reader labels/announcements, logical keyboard
navigation, visible focus, text/icons beyond color, understandable instructions,
and status changes that do not overwhelm assistive technology.

- Tested with real users during the event and changed design from feedback: +2.
- Accessibility built in (screen reader, colorblind-safe alerts, keyboard): +2.
- Open-source with clear README/install steps: +1.

Supply a usability script, timing/completion/warning-comprehension measurements,
feedback log and changes/retest log. Do not invent participants/results. Prepare
clear README/config examples and a proposed license; do not publish automatically.

### 11. Penalties and eligibility

- Unjustified over-scoped permissions: −3.
- User data collected/transmitted without disclosure: −5.
- Core work completed before hackathon started: disqualified.
- Offensive actions on unowned/unauthorized systems or live malware samples:
  disqualified.

Record event start/end, AI-use permission and timestamps. Before generating
event-submission implementation, establish eligibility; otherwise limit event work
to planning. Actual event timing was not provided in this conversation, so do not
claim compliance or bonus points. This document records the requested constraint;
the supplied implementation has its own creation date and must be assessed under
the real event rules.

### 12. Deliverables

Concise justified architecture; complete files; schema/migrations; API examples;
environment/settings without real secrets; local/Linux setup; explicit Windows
integration requirements; meaningful tests; live-demo checklist; privacy inventory;
attack-surface explanation; rubric mapping. Prioritize a small working core and
clearly label implemented, untested, mocked and future features. Never call a mock
VPN or server configuration alone real protection.

## Supplied source data

- `originals/vpn.py`: OS/DNS/TLS probes, payload/hostname risk scoring and hash ledger.
- `originals/shield_manager.py`: onboarding wrapper and claimed one-click features.
- `originals/warnings_engine.py`: warning templates and cooldowns.
- `originals/privacy_disclosure.py`: disclosure and typed-name hash receipt.

Their original claims are **input to review**, not trusted descriptions of actual
protection. The replacement removes unsupported claims while preserving the
intended privacy, simplicity and accessible-warning goals.
