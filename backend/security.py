"""Bounded local throttling, scrypt passwords, hashed sessions, RFC 6238 TOTP."""
import base64
from collections import OrderedDict, deque
import hashlib
import hmac
import secrets
import struct
import threading
import time
from cryptography.fernet import Fernet

_HASH_SLOTS = threading.BoundedSemaphore(2)


def _scrypt(password, salt):
    # OWASP's lower-memory scrypt option: N=2^15, r=8, p=3.
    # Bound concurrency so login floods cannot multiply memory usage without limit.
    with _HASH_SLOTS:
        return hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=3, maxmem=64*1024*1024)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    value = _scrypt(password, salt)
    return salt.hex() + ":" + value.hex()


def password_valid(password: str, encoded: str) -> bool:
    salt, expected = encoded.split(":")
    value = _scrypt(password, bytes.fromhex(salt))
    return hmac.compare_digest(value.hex(), expected)


def totp(secret: str, step: int) -> str:
    key = base64.b32decode(secret, casefold=True)
    raw = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = raw[-1] & 15
    return str((struct.unpack(">I", raw[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)


def valid_step(secret: str, code: str, last: int, now=None):
    step = int((time.time() if now is None else now) // 30)
    for candidate in (step, step-1, step+1):
        if candidate > last and hmac.compare_digest(totp(secret, candidate), code):
            return candidate
    return None


class Secrets:
    def __init__(self, key):
        self.key = key.encode()
        self.box = Fernet(self.key)

    def seal(self, value):
        return self.box.encrypt(value.encode()).decode()

    def open(self, value):
        return self.box.decrypt(value.encode()).decode()

    def attest(self, value):
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()


class Limiter:
    """Single-process only. Shared throttling is a deployment requirement for replicas."""
    def __init__(self):
        self.items = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, key, count=10, seconds=60):
        with self.lock:
            now = time.monotonic()
            history = self.items.pop(key, deque())
            while history and history[0] <= now-seconds:
                history.popleft()
            allowed = len(history) < count
            if allowed:
                history.append(now)
            self.items[key] = history
            while len(self.items) > 10000:
                self.items.popitem(last=False)
            return allowed
