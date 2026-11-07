from contextlib import contextmanager
from pathlib import Path
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES(1);
CREATE TABLE IF NOT EXISTS accounts(
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
 owner_id TEXT REFERENCES accounts(id), totp_secret TEXT NOT NULL,
 mfa INTEGER NOT NULL DEFAULT 0, last_step INTEGER NOT NULL DEFAULT -1,
 created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS consents(
 account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 version TEXT NOT NULL, document_hash TEXT NOT NULL, accepted REAL NOT NULL,
 name_attestation TEXT NOT NULL, receipt TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
 hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 scope TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_codes(
 hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS invites(
 hash TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS devices(
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 label TEXT NOT NULL, public_key TEXT UNIQUE NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS connections(
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 server_id TEXT NOT NULL, address4 TEXT NOT NULL, address6 TEXT NOT NULL,
 state TEXT NOT NULL, adblock INTEGER NOT NULL, requested REAL NOT NULL,
 UNIQUE(server_id,address4), UNIQUE(server_id,address6));
"""


class Store:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.tx() as db:
            db.executescript(SCHEMA)
        if os.name != "nt":
            os.chmod(path, 0o600)

    @contextmanager
    def tx(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
