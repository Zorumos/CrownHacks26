import base64
import hmac
import ipaddress
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .privacy_disclosure import PrivacyDisclosureGate
from .security import Limiter, Secrets, digest, password_hash, password_valid, valid_step
from .settings import Settings
from .shield_manager import OneClickShieldManager
from .storage import Store
from .vpn import BrokerUnavailable, UnixBroker, allocate, configuration, public_key
from .warnings_engine import PlainLanguageWarningEngine


class APIError(Exception):
    def __init__(self, status, code, message, action="Try again."):
        self.status, self.code, self.message, self.action = status, code, message, action


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=False)


class Signup(Input):
    username: str = Field(pattern=r"^[a-z0-9_]{3,32}$")
    password: str = Field(min_length=12, max_length=128)
    name: str = Field(min_length=2, max_length=120)
    signature: str = Field(min_length=2, max_length=120)
    agreed: bool
    disclosure_version: str = Field(max_length=80)
    document_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    invitation: str | None = Field(default=None, max_length=100)


class Login(Input):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(default="", max_length=100)


class Code(Input):
    code: str = Field(pattern=r"^\d{6}$", max_length=6)


class Device(Input):
    label: str = Field(min_length=1, max_length=60)
    public_key: str = Field(min_length=44, max_length=44)

    @field_validator("public_key")
    @classmethod
    def valid_key(cls, value):
        return public_key(value)

    @field_validator("label")
    @classmethod
    def valid_label(cls, value):
        if not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Use a printable device name")
        return value.strip()


class Connect(Input):
    device_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    server_id: str = Field(default="auto", pattern=r"^[a-z0-9-]{1,40}$")
    adblock: bool = True


class Confirm(Input):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=100)


def create_app(settings=None, broker=None):
    cfg = settings or Settings.load()
    cfg.validate()
    store = Store(cfg.database)
    box = Secrets(cfg.secret)
    limiter = Limiter()
    warnings = PlainLanguageWarningEngine()
    shield = OneClickShieldManager(warnings)
    broker = broker or UnixBroker()
    lock = threading.RLock()
    servers = {s["id"]: s for s in cfg.servers}
    dummy_password = password_hash(secrets.token_urlsafe(32))
    app = FastAPI(title="Cyber One VPN control plane", version="1.0.0", docs_url=None, redoc_url=None, openapi_url="/api/openapi.json",
                  description="Server provisioning is not proof of device-wide VPN protection.")
    app.state.store, app.state.shield = store, shield
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[urlsplit(cfg.origin).hostname, "testserver"] if cfg.origin.startswith("http://") else [urlsplit(cfg.origin).hostname])

    @app.exception_handler(APIError)
    async def error_handler(request, error):
        headers = {"Retry-After": "60"} if error.status == 429 else {}
        return JSONResponse(status_code=error.status, headers=headers, content={"error": {
            "code": error.code, "message": error.message, "action": error.action,
            "retryable": error.status in {429, 503}, "severity": "warning"}})

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request, error):
        # Pydantic's default errors can echo passwords and signatures. Do not return input.
        return JSONResponse(status_code=422, content={"error": {"code": "INVALID_INPUT",
            "message": "Some fields are missing or invalid.", "action": "Check the indicated fields.",
            "fields": [".".join(str(x) for x in e["loc"]) for e in error.errors()], "retryable": False}})

    @app.exception_handler(Exception)
    async def unexpected_handler(request, error):
        return JSONResponse(status_code=500, content={"error": {"code": "INTERNAL_ERROR",
            "message": "We could not complete that request.", "action": "Try again or contact the operator.", "retryable": False}})

    @app.middleware("http")
    async def safeguards(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.headers.get("origin") not in (None, cfg.origin):
                return JSONResponse(status_code=403, content={"error": {"code": "ORIGIN_REJECTED", "message": "Use the app's own page."}})
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 16384:
                    return JSONResponse(status_code=413, content={"error": {"code": "BODY_TOO_LARGE", "message": "This request is too large."}})
            # Request.body caches bytes for the downstream route after the stream is consumed.
            request._body = bytes(data)
            if data and request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse(status_code=415, content={"error": {"code": "JSON_REQUIRED", "message": "Send a JSON request."}})
        peer = request.client.host if request.client else "unknown"
        if request.url.path.startswith("/api/") and not limiter.allow("request:"+digest(peer), 120, 60):
            return JSONResponse(status_code=429, headers={"Retry-After": "60"}, content={"error": {"code": "RATE_LIMIT", "message": "Too many requests. Wait one minute."}})
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                                 "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
        if cfg.origin.startswith("https://"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def throttle(request, category, subject="", limit=8):
        peer = request.client.host if request.client else "unknown"
        if not limiter.allow(category+":"+digest(peer), limit, 60):
            raise APIError(429, "RATE_LIMIT", "Too many attempts.", "Wait one minute before trying again.")
        if subject and not limiter.allow(category+":subject:"+digest(subject), limit, 60):
            raise APIError(429, "RATE_LIMIT", "Too many attempts for this account.", "Wait one minute.")

    def session(db, account, scope):
        token = secrets.token_urlsafe(32)
        lifetime = 1800 if scope == "full" else 600
        db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (digest(token), account, scope, time.time()+lifetime))
        return {"access_token": token, "token_type": "Bearer", "expires_in": lifetime, "scope": scope}

    def auth(request: Request):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not 20 <= len(token) <= 100:
            raise APIError(401, "SIGN_IN_REQUIRED", "Please sign in.", "Open the sign-in screen.")
        with store.tx() as db:
            db.execute("DELETE FROM sessions WHERE expires<=?", (time.time(),))
            db.execute("DELETE FROM invites WHERE expires<=?", (time.time(),))
            row = db.execute("SELECT a.*, s.scope, s.hash AS session_hash FROM accounts a JOIN sessions s ON a.id=s.account_id WHERE s.hash=? AND s.expires>?", (digest(token), time.time())).fetchone()
        if row is None:
            raise APIError(401, "SESSION_EXPIRED", "Your session ended.", "Sign in again.")
        return dict(row)

    def verified(account=Depends(auth)):
        if account["scope"] != "full" or not account["mfa"]:
            raise APIError(403, "MFA_REQUIRED", "Finish authenticator setup first.", "Save the authenticator secret and enter its six-digit code.")
        return account

    def full(account=Depends(verified)):
        if cfg.require_identity:
            raise APIError(503, "IDENTITY_NOT_CONFIGURED", "VPN access is paused until the required identity-verification integration is available.", "Contact the operator. Do not upload an ID here.")
        with store.tx() as db:
            consent = db.execute("SELECT version,document_hash FROM consents WHERE account_id=?", (account["id"],)).fetchone()
        disclosure = PrivacyDisclosureGate.get_plain_language_disclosure(cfg.require_identity)
        if not consent or consent["version"] != disclosure["version"] or consent["document_hash"] != disclosure["document_hash"]:
            raise APIError(403, "DISCLOSURE_CHANGED", "Review the current disclosure before continuing.", "Submit a new agreement through /api/consent.")
        return account

    def owner(account):
        if account["owner_id"]:
            raise APIError(403, "OWNER_REQUIRED", "Only the main account can manage family membership.")

    def verify_factor(db, account, code):
        fresh = db.execute("SELECT * FROM accounts WHERE id=?", (account["id"],)).fetchone()
        step = valid_step(box.open(fresh["totp_secret"]), code, fresh["last_step"])
        if step is not None:
            db.execute("UPDATE accounts SET last_step=? WHERE id=?", (step, fresh["id"]))
            return True
        recovery = db.execute("DELETE FROM recovery_codes WHERE account_id=? AND hash=?", (fresh["id"], digest(code)))
        return recovery.rowcount == 1

    def consent_check(data):
        disclosure = PrivacyDisclosureGate.get_plain_language_disclosure(cfg.require_identity)
        if not data.agreed or data.disclosure_version != disclosure["version"] or data.document_hash != disclosure["document_hash"]:
            raise APIError(409, "REVIEW_DISCLOSURE", "Please review and agree to the current disclosure.", "Reload the disclosure and confirm your agreement.")
        try:
            name = PrivacyDisclosureGate.normalize_name(data.name)
            signature = PrivacyDisclosureGate.normalize_name(data.signature)
        except ValueError as exc:
            raise APIError(422, "INVALID_NAME", str(exc)) from exc
        if not hmac.compare_digest(name.encode(), signature.encode()):
            raise APIError(422, "SIGNATURE_MISMATCH", "The typed names do not match.", "Use the same name in both fields.")
        return disclosure, name

    def record_consent(db, account_id, disclosure, name):
        accepted = time.time()
        name_digest = box.attest(account_id+":"+name)
        receipt = box.attest(json.dumps([account_id, disclosure["document_hash"], accepted, name_digest]))
        db.execute("INSERT OR REPLACE INTO consents VALUES(?,?,?,?,?,?)", (account_id, disclosure["version"], disclosure["document_hash"], accepted, name_digest, receipt))
        return dict(version=disclosure["version"], document_hash=disclosure["document_hash"], accepted_at=accepted, receipt=receipt)

    def own_device(db, device_id, account):
        row = db.execute("SELECT * FROM devices WHERE id=? AND account_id=?", (device_id, account["id"])).fetchone()
        if row is None:
            raise APIError(404, "DEVICE_NOT_FOUND", "That device is not available in your profile.")
        return dict(row)

    def revoke_device(device):
        with store.tx() as db:
            row = db.execute("SELECT * FROM connections WHERE device_id=?", (device["id"],)).fetchone()
            if row:
                db.execute("UPDATE connections SET state='revocation_pending' WHERE device_id=?", (device["id"],))
        if not row:
            return
        server = servers.get(row["server_id"])
        try:
            if server is None:
                raise BrokerUnavailable()
            reply = broker.call(server, "revoke", key=device["public_key"])
            if reply["peer_present"]:
                raise BrokerUnavailable()
        except BrokerUnavailable as exc:
            raise APIError(503, "REVOCATION_UNCONFIRMED", "We could not confirm that server access was removed.", "Turn off the native client and retry. Do not assume revocation succeeded.") from exc
        with store.tx() as db:
            db.execute("DELETE FROM connections WHERE device_id=?", (device["id"],))

    @app.get("/api/health")
    def health():
        return {"service": "ok", "vpn_protection": "not_verified", "identity_verification": "not_integrated"}

    @app.get("/api/disclosure")
    def disclosure():
        return PrivacyDisclosureGate.get_plain_language_disclosure(cfg.require_identity)

    @app.post("/api/auth/register", status_code=201)
    def register(data: Signup, request: Request):
        throttle(request, "register", limit=5)
        document, name = consent_check(data)
        if cfg.require_identity:
            raise APIError(503, "IDENTITY_NOT_CONFIGURED", "Registration is paused until identity verification is available.", "Contact the operator. Do not upload an ID here.")
        account_id = secrets.token_hex(16)
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        encoded_password = password_hash(data.password)
        try:
            with store.tx() as db:
                owner_id = None
                if data.invitation:
                    invitation = db.execute("SELECT * FROM invites WHERE hash=? AND expires>?", (digest(data.invitation), time.time())).fetchone()
                    if invitation is None:
                        raise APIError(400, "INVALID_INVITE", "This family invitation expired or was already used.")
                    owner_id = invitation["owner_id"]
                    count = db.execute("SELECT count(*) FROM accounts WHERE owner_id=?", (owner_id,)).fetchone()[0]
                    if count >= 3:
                        raise APIError(409, "FAMILY_FULL", "This account already has three family profiles.")
                    db.execute("DELETE FROM invites WHERE hash=?", (digest(data.invitation),))
                db.execute("INSERT INTO accounts(id,username,password,owner_id,totp_secret,created) VALUES(?,?,?,?,?,?)", (account_id, data.username, encoded_password, owner_id, box.seal(secret), time.time()))
                receipt = record_consent(db, account_id, document, name)
                result = session(db, account_id, "enroll")
        except sqlite3.IntegrityError as exc:
            raise APIError(409, "REGISTRATION_UNAVAILABLE", "We could not create this account.", "Choose a different username or sign in if you already registered.") from exc
        return {**result, "agreement": receipt, "next": "mfa_enrollment", "identity_verified": False}

    class Agreement(Input):
        name: str = Field(min_length=2, max_length=120)
        signature: str = Field(min_length=2, max_length=120)
        agreed: bool
        disclosure_version: str = Field(max_length=80)
        document_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @app.post("/api/consent")
    def renew_consent(data: Agreement, account=Depends(auth)):
        document, name = consent_check(data)
        with store.tx() as db:
            return record_consent(db, account["id"], document, name)

    @app.get("/api/auth/mfa/setup")
    def setup_mfa(account=Depends(auth)):
        if account["scope"] != "enroll" or account["mfa"]:
            raise APIError(403, "ENROLLMENT_ONLY", "Authenticator setup is only available during enrollment.")
        secret = box.open(account["totp_secret"])
        return {"secret": secret, "uri": "otpauth://totp/CyberOne:"+quote(account["username"])+"?secret="+secret+"&issuer=CyberOne&digits=6&period=30", "action": "Add this secret to your authenticator app, then enter its six-digit code."}

    @app.post("/api/auth/mfa/confirm")
    def confirm_mfa(data: Code, request: Request, account=Depends(auth)):
        throttle(request, "mfa", account["id"])
        codes = [secrets.token_hex(10) for _ in range(8)]
        with store.tx() as db:
            fresh = db.execute("SELECT * FROM accounts WHERE id=?", (account["id"],)).fetchone()
            if account["scope"] != "enroll" or fresh["mfa"]:
                raise APIError(409, "ALREADY_ENROLLED", "Authenticator setup is already complete.")
            if not verify_factor(db, account, data.code):
                raise APIError(400, "INVALID_CODE", "That code is invalid or already used.", "Wait for a new authenticator code and try again.")
            db.execute("UPDATE accounts SET mfa=1 WHERE id=?", (account["id"],))
            db.executemany("INSERT INTO recovery_codes VALUES(?,?)", [(digest(c), account["id"]) for c in codes])
            db.execute("DELETE FROM sessions WHERE account_id=?", (account["id"],))
            result = session(db, account["id"], "full")
        return {**result, "recovery_codes": codes, "action": "Save these one-use recovery codes somewhere private. They will not be shown again."}

    @app.post("/api/auth/login")
    def login(data: Login, request: Request):
        throttle(request, "login", data.username.casefold())
        with store.tx() as db:
            row = db.execute("SELECT * FROM accounts WHERE username=?", (data.username,)).fetchone()
            correct = password_valid(data.password, row["password"] if row else dummy_password)
            if not correct or row is None:
                raise APIError(401, "INVALID_CREDENTIALS", "Sign-in details were not accepted.", "Check your username, password, and authenticator or recovery code.")
            account = dict(row)
            if not account["mfa"]:
                return {**session(db, account["id"], "enroll"), "next": "mfa_enrollment"}
            if not verify_factor(db, account, data.code):
                raise APIError(401, "INVALID_CREDENTIALS", "Sign-in details were not accepted.", "Use a fresh authenticator code or an unused recovery code.")
            return session(db, account["id"], "full")

    @app.post("/api/auth/logout")
    def logout(account=Depends(auth)):
        with store.tx() as db:
            db.execute("DELETE FROM sessions WHERE hash=?", (account["session_hash"],))
        return {"signed_out": True, "vpn_disconnected": False, "message": "Signed out of the website. An active VPN tunnel stays on until you disconnect it."}

    @app.post("/api/auth/mfa/reset")
    def reset_mfa(data: Confirm, request: Request, account=Depends(auth)):
        throttle(request, "sensitive", account["id"])
        with store.tx() as db:
            if not account["mfa"] or account["scope"] != "full" or not password_valid(data.password, account["password"]) or not verify_factor(db, account, data.code):
                raise APIError(401, "REAUTH_REQUIRED", "Confirm with your password and a fresh authenticator or recovery code.")
            secret = base64.b32encode(secrets.token_bytes(20)).decode()
            db.execute("UPDATE accounts SET mfa=0,totp_secret=?,last_step=-1 WHERE id=?", (box.seal(secret), account["id"]))
            db.execute("DELETE FROM sessions WHERE account_id=?", (account["id"],))
            db.execute("DELETE FROM recovery_codes WHERE account_id=?", (account["id"],))
            result = session(db, account["id"], "enroll")
        return {**result, "next": "mfa_enrollment", "message": "Old authenticator and sessions removed. Enroll your replacement authenticator. Existing VPN tunnels are not revoked."}

    @app.get("/api/me")
    def me(account=Depends(auth)):
        return {"id": account["id"], "username": account["username"], "main_account": not bool(account["owner_id"]), "mfa_enabled": bool(account["mfa"]), "identity_verified": False}

    @app.post("/api/family/invites", status_code=201)
    def invite(account=Depends(full)):
        owner(account)
        token = secrets.token_urlsafe(24)
        with store.tx() as db:
            count = db.execute("SELECT (SELECT count(*) FROM accounts WHERE owner_id=?) + (SELECT count(*) FROM invites WHERE owner_id=? AND expires>?)", (account["id"], account["id"], time.time())).fetchone()[0]
            if count >= 3:
                raise APIError(409, "FAMILY_FULL", "All three family slots are occupied or reserved.")
            db.execute("INSERT INTO invites VALUES(?,?,?)", (digest(token), account["id"], time.time()+3600))
        return {"invitation": token, "expires_in": 3600, "message": "Give this one-use code to your family member privately. No message has been sent."}

    @app.get("/api/family")
    def family(account=Depends(full)):
        owner(account)
        with store.tx() as db:
            return {"members": [dict(r) for r in db.execute("SELECT id,username FROM accounts WHERE owner_id=?", (account["id"],))]}

    @app.delete("/api/family/{member_id}")
    def remove_family(member_id: str, data: Confirm, request: Request, account=Depends(verified)):
        owner(account)
        throttle(request, "sensitive", account["id"])
        with lock:
            with store.tx() as db:
                if not password_valid(data.password, account["password"]) or not verify_factor(db, account, data.code):
                    raise APIError(401, "REAUTH_REQUIRED", "Confirm with your password and a fresh code.")
                member = db.execute("SELECT id FROM accounts WHERE id=? AND owner_id=?", (member_id, account["id"])).fetchone()
                if not member:
                    raise APIError(404, "MEMBER_NOT_FOUND", "That family member is not available.")
                devices = [dict(r) for r in db.execute("SELECT * FROM devices WHERE account_id=?", (member_id,))]
            for device in devices:
                revoke_device(device)
            with store.tx() as db:
                db.execute("DELETE FROM accounts WHERE id=?", (member_id,))
        return {"removed": True, "message": "Membership and this service account were removed; server peers were revoked."}

    @app.post("/api/devices", status_code=201)
    def add_device(data: Device, account=Depends(full)):
        device_id = secrets.token_hex(16)
        try:
            with store.tx() as db:
                if db.execute("SELECT count(*) FROM devices WHERE account_id=?", (account["id"],)).fetchone()[0] >= 5:
                    raise APIError(409, "DEVICE_LIMIT", "Remove an old device before adding another.")
                db.execute("INSERT INTO devices VALUES(?,?,?,?,?)", (device_id, account["id"], data.label, data.public_key, time.time()))
        except sqlite3.IntegrityError as exc:
            raise APIError(409, "KEY_ALREADY_REGISTERED", "That public key is already registered.", "Use the existing device or generate a new key pair on your device.") from exc
        return {"id": device_id, "label": data.label}

    @app.get("/api/devices")
    def list_devices(account=Depends(full)):
        with store.tx() as db:
            return {"devices": [dict(r) for r in db.execute("SELECT id,label,public_key,created FROM devices WHERE account_id=?", (account["id"],))]}

    @app.delete("/api/devices/{device_id}")
    def remove_device(device_id: str, account=Depends(verified)):
        with lock:
            with store.tx() as db:
                device = own_device(db, device_id, account)
            revoke_device(device)
            with store.tx() as db:
                db.execute("DELETE FROM devices WHERE id=?", (device_id,))
        return {"removed": True}

    @app.get("/api/servers")
    def list_servers(account=Depends(full)):
        return {"servers": [{"id": s["id"], "country": s["country"], "city": s["city"], "location_source": "operator_configured_not_geolocation_verified"} for s in cfg.servers],
                "auto_policy": "First broker-responsive server in operator priority order; client latency and server load are not measured."}

    @app.post("/api/connections")
    def connect(data: Connect, request: Request, account=Depends(full)):
        throttle(request, "connect", account["id"], 12)
        if data.server_id != "auto" and data.server_id not in servers:
            raise APIError(404, "UNKNOWN_SERVER", "That server is not available.", "Refresh the server list.")
        with lock:
            with store.tx() as db:
                device = own_device(db, data.device_id, account)
                old = db.execute("SELECT * FROM connections WHERE device_id=?", (data.device_id,)).fetchone()
            if old:
                if old["state"] == "revocation_pending":
                    raise APIError(409, "REVOCATION_PENDING", "A previous disconnect still needs confirmation.", "Retry disconnect first.")
                if (data.server_id != "auto" and old["server_id"] != data.server_id) or old["adblock"] != data.adblock:
                    raise APIError(409, "DISCONNECT_FIRST", "Disconnect before changing servers or DNS settings.", "Disconnect, change your selection, then connect again.")
                server = servers.get(old["server_id"])
                if not server:
                    raise APIError(503, "SERVER_REMOVED", "The server inventory changed.", "Restore its configuration and revoke this device before reconnecting.")
                connection = dict(old)
            else:
                choices = cfg.servers if data.server_id == "auto" else [servers[data.server_id]]
                server = None
                for candidate in choices:
                    try:
                        broker.call(candidate, "health")
                        server = candidate
                        break
                    except BrokerUnavailable:
                        continue
                if server is None:
                    raise APIError(503, "NO_USABLE_SERVER", "No VPN server could be verified.", "Ask the operator to configure the broker, or try again later.")
                with store.tx() as db:
                    used = {r[0] for r in db.execute("SELECT address4 FROM connections WHERE server_id=?", (server["id"],))}
                    try:
                        a4, a6 = allocate(server, used)
                    except ValueError as exc:
                        raise APIError(409, "SERVER_FULL", str(exc), "Choose another server.") from exc
                    db.execute("INSERT INTO connections VALUES(?,?,?,?,?,?,?)", (device["id"], server["id"], a4, a6, "provisioning", int(data.adblock), time.time()))
                    connection = dict(db.execute("SELECT * FROM connections WHERE device_id=?", (device["id"],)).fetchone())
            try:
                reply = broker.call(server, "provision", key=device["public_key"], address4=connection["address4"], address6=connection["address6"])
                if not reply["peer_present"]:
                    raise BrokerUnavailable()
            except BrokerUnavailable as exc:
                # Preserve allocation: a timed-out broker might already have provisioned the peer.
                raise APIError(503, "PROVISION_UNCONFIRMED", "We could not confirm server setup.", "Retry this same request, or disconnect to revoke any partial setup.") from exc
            with store.tx() as db:
                db.execute("UPDATE connections SET state='provisioned' WHERE device_id=?", (device["id"],))
            return {"device_id": device["id"], "server_id": server["id"],
                    "configuration": configuration(server, connection),
                    **shield.evaluate(account["id"], device["id"], connection, reply)}

    @app.get("/api/connections/{device_id}")
    def connection_status(device_id: str, account=Depends(full)):
        with store.tx() as db:
            device = own_device(db, device_id, account)
            row = db.execute("SELECT * FROM connections WHERE device_id=?", (device_id,)).fetchone()
        if row is None:
            return {"state": "not_provisioned", "protected": False, "message": "No server access is provisioned for this device by this service."}
        connection = dict(row)
        if connection["state"] == "revocation_pending":
            return {"state": "revocation_pending", "protected": None, "message": "Server revocation is unconfirmed. Turn off your native client and retry disconnect."}
        reply = None
        try:
            server = servers.get(connection["server_id"])
            if not server:
                raise BrokerUnavailable()
            reply = broker.call(server, "status", key=device["public_key"])
        except BrokerUnavailable:
            pass
        return {"device_id": device_id, "server_id": connection["server_id"],
                **shield.evaluate(account["id"], device_id, connection, reply, unavailable=reply is None)}

    @app.delete("/api/connections/{device_id}")
    def disconnect(device_id: str, account=Depends(verified)):
        with lock:
            with store.tx() as db:
                device = own_device(db, device_id, account)
            revoke_device(device)
        return {"state": "server_access_revoked", "protected": False,
                "warnings": warnings.build(account["id"], device_id, ["ACCESS_REVOKED"])}

    @app.delete("/api/account")
    def delete_account(data: Confirm, request: Request, account=Depends(verified)):
        throttle(request, "sensitive", account["id"])
        with lock:
            with store.tx() as db:
                if not password_valid(data.password, account["password"]) or not verify_factor(db, account, data.code):
                    raise APIError(401, "REAUTH_REQUIRED", "Confirm with your password and a fresh code or recovery code.")
                members = [r[0] for r in db.execute("SELECT id FROM accounts WHERE owner_id=?", (account["id"],))]
                ids = members+[account["id"]]
                devices = []
                for account_id in ids:
                    devices.extend(dict(r) for r in db.execute("SELECT * FROM devices WHERE account_id=?", (account_id,)))
            for device in devices:
                revoke_device(device)
            with store.tx() as db:
                for account_id in ids:
                    db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        return {"deleted": True, "message": "Account records and server peers removed. Operator backups require separate retention controls."}

    @app.get("/api/capabilities")
    def capabilities():
        return {"native_client_required": True, "device_protection_verification": False,
                "identity_verification": False, "passkeys": False, "temporary_email_aliases": False,
                "adblock": "DNS configuration only; resolver deployment and verification required",
                "automatic_server_selection": "first responsive broker, not measured fastest",
                "hackathon": "Record event start, AI rules, and work timestamps; do not claim eligibility or user testing without evidence."}

    web = Path(__file__).resolve().parent.parent/"web"
    app.mount("/assets", StaticFiles(directory=web), name="assets")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(web/"index.html")

    return app
