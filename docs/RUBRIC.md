# Rubric mapping — implementation evidence, not awarded scores

| Criterion | Evidence in this bundle | Remaining evidence/work |
| --- | --- | --- |
| Usability/accessibility, 25 | Structured plain-language errors, warning transition cooldowns, consent flow, clear unknown states, semantic accessible demo | Native one-button Connect and measured device protection under 60 seconds; real keyboard/screen-reader/visual testing. Backend demo is an integration tool, not final consumer UX. |
| Technical execution, weight not supplied | Runnable API, SQLite schema, MFA/family/device core, broker integration, tested input/error/race handling | Real Linux/Windows end-to-end tunnel, DNS/IPv6/kill switch and production reliability. |
| Sound detection | Explicit deterministic evidence model, tiny labeled freshness fixture, no fabricated malware score | Representative false-positive/negative evaluation for any actual security classifier; reviewed DNS-list performance. |
| Tool security, 15 | Least-privilege broker boundary, no raw ID collection, encrypted TOTP secret, password hashes, name minimization, authorization tests, documented attack surface | Independent audit, deployment hardening, secret rotation, infrastructure retention, dependency/supply-chain review and capacity testing. |
| Innovation, 10 | Conservative evidence/status model with unknown results, timed actionable warnings, no invented safety | Judge assessment and real user outcome validation; no claim of unprecedented novelty. |
| Real users and design change, +2 | Research script and blank evidence log | Conduct during eligible event, record actual feedback/change/retest. |
| Accessibility built in, +2 | Labels, keyboard-native controls, focus styles, text-based warnings/live regions | Human screen-reader/keyboard/color-vision checks; no bonus assumed. |
| Open source/README, +1 | Source, MIT license, README, commands and privacy/deployment docs | Choose a public repository and publish if authorized; not published by this task. |

Permission justification: API uses ordinary files and a group-scoped local socket;
broker can administer one configured WireGuard interface. The website requests
no browser extension, all-sites access, camera, microphone, GPS, ID upload or OS
administrator privileges. Native Windows permission design remains a separate
required integration.

No public deployment, messages to others, paid services, real-ID collection,
offensive network actions or live malware execution were performed. Work timestamp
and event eligibility must be reviewed honestly; do not claim this was created
after an unknown event start time.
