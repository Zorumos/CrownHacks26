"""Generate development secrets locally. Never commit config.local.json or data/."""
import json
import os
from pathlib import Path
from cryptography.fernet import Fernet


def main():
    path = Path("config.local.json")
    if path.exists():
        raise SystemExit("config.local.json already exists; refusing to replace its encryption key.")
    value = {"database": "data/cyber-one.sqlite3", "secret": Fernet.generate_key().decode(),
             "origin": "http://127.0.0.1:8000", "require_identity": False, "servers": []}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, indent=2)
    print("Created private local settings. No VPN server is configured yet.")


if __name__ == "__main__":
    main()
