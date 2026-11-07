# Cyber One — VPN website backend

A runnable FastAPI control plane integrating the four supplied modules and the
product brief. It includes accounts, required TOTP enrollment, recovery codes,
family invitations, consent receipts, device isolation, a WireGuard peer broker,
timed warnings, and a small accessible browser integration demo.

**This is not a complete VPN product.** The website cannot redirect a visitor's
device traffic. A native client, a real Linux VPN host, forwarding/firewall rules,
and a configured DNS resolver are required for actual VPN service. No server
credentials, private keys, real server inventory, or identity-verification provider
were provided. The demo starts with **no servers** and makes no protection claim.

## Run on your Windows laptop

Use a supported Python 3.12+ installation. Open PowerShell in this extracted folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe setup_local.py
.\.venv\Scripts\python.exe -m uvicorn backend.app:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log --no-proxy-headers
```

Open http://127.0.0.1:8000. If your installed Python is a different supported
version, change the first command's version selector. There is no need to activate
the virtual environment or change PowerShell execution policy.

On Linux/macOS, use `python3 -m venv .venv`, then `.venv/bin/python` in place of
the Windows interpreter path. Windows supports the account/API demo; the
privileged provisioning broker runs on Linux alongside the API for live operation.
The broker uses a Unix socket, not a publicly exposed management endpoint.

1. Read the disclosure before entering personal data.
2. Create an account; type the same name twice and explicitly agree.
3. Show the authenticator secret and add it to an authenticator app.
4. Confirm a six-digit code. Save the eight one-use recovery codes privately.
5. Generate device keys in your local native client. Register **only its public key**.
6. With no live server configured, expect a clear setup warning or HTTP 503.
   This is deliberate; there is no simulated successful VPN connection.

API specification: http://127.0.0.1:8000/api/openapi.json.
Full endpoint examples and integration flow: [docs/API.md](docs/API.md).
Live server setup: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Run checks

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use explicitly synthetic broker fixtures. They do **not** prove a live
tunnel, DNS filtering, leak protection, real user feedback, or a sub-minute
protection result. See [docs/VALIDATION.md](docs/VALIDATION.md).

## What changed from your files

| Supplied file | Integrated replacement | Reason |
| --- | --- | --- |
| `vpn.py` | `backend/vpn.py`, `agent/broker.py` | Replace arbitrary DNS/TCP probes and unvalidated malware scores with configured-server peer provisioning and bounded broker replies. |
| `shield_manager.py` | `backend/shield_manager.py` | Remove hash-derived fake IPs, TLS cipher inventory as tunnel proof, fictional stealth transport, and unconditional protected status. |
| `warnings_engine.py` | `backend/warnings_engine.py` | Stable codes, actionable messages, per-device transition alerts, bounded memory, and cooldowns even for repeated critical states. |
| `privacy_disclosure.py` | `backend/privacy_disclosure.py` | Disclose actual behavior, version agreements, avoid storing typed names, and remove impossible privacy promises. |

Unmodified originals are preserved under `originals/` for review and are **not**
imported by the application. Do not use them as an alternative production engine.
Their old Python interfaces are intentionally not drop-in compatible; integrate
through the new API. The complete consolidated build prompt and acceptance
criteria are in [docs/BUILD_PROMPT.md](docs/BUILD_PROMPT.md).

## Implemented versus remaining

| Area | Status |
| --- | --- |
| Disclosure, typed-name agreement, encrypted TOTP secrets, recovery codes | Implemented; typed name is acknowledgment, not identity proof. |
| Family accounts | Main account plus three invitations/members; members authenticate separately. Owner sees usernames/membership, not device data. |
| Accounts/devices/deletion | Implemented with authorization and revocation confirmation; deletion remains available when disclosure policy changes. |
| WireGuard peer management | Implemented broker adapter; requires operator-configured Linux host. No live WireGuard test was possible here. |
| Ad blocking | Filtered DNS selection plus reviewed-domain compiler for dnsmasq. Requires a running resolver; not verified by the API. |
| Auto selection | First responding broker in configured priority order. No invented latency/load scores or fastest-server claims. |
| Native one-button activation, Windows kill switch, IP/DNS/IPv6 checks | Client integration work remains; contract documented. |
| Physical ID | No collection/provider. Enabling `require_identity` blocks new registration and VPN access instead of pretending verification succeeded. |
| Passkeys and temporary email aliases | Not integrated; explicitly reported unavailable. |
| Feedback bonus and under-one-minute outcome | Not claimed. Test and timing templates included. |

## Operational constraints

Run one API process and one broker per interface. SQLite transactions serialize
address allocation; a process lock serializes provisioning/revocation; password
hashing has bounded concurrency. Rate limits and warning histories are in-memory,
bounded, and reset on process restart. Scaling needs a shared limiter, distributed
operation coordination, a managed database and operational capacity testing.

Keep `config.local.json` and `data/` private and out of source control. The config
contains the encryption/receipt key; losing it prevents TOTP decryption. Protect
backups and configure Windows ACLs or Linux ownership. Public deployment needs
HTTPS, infrastructure logging/retention review, dependency scanning and a security
review. Secret rotation is an operator migration, not an automatic process here.

Do not publish test data as user research or claim event eligibility. The supplied
rubric disqualifies core work before the event starts. Record event timing and
AI-assistance permission before submitting; no hackathon start time was provided.
The MIT license is included for release; nothing has been published externally.
