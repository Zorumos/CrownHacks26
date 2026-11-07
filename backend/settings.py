from dataclasses import dataclass, field
from pathlib import Path
import base64
import ipaddress
import json
import os
import re


@dataclass
class Settings:
    database: str = "data/cyber-one.sqlite3"
    secret: str = ""
    origin: str = "http://127.0.0.1:8000"
    require_identity: bool = False
    servers: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls):
        path = Path(os.getenv("CYBER_CONFIG", "config.local.json"))
        if not path.is_file():
            raise RuntimeError("Run python setup_local.py first. No default secrets are provided.")
        obj = cls(**json.loads(path.read_text()))
        obj.validate()
        return obj

    def validate(self):
        if len(base64.urlsafe_b64decode(self.secret)) != 32:
            raise ValueError("secret must be a generated 32-byte Fernet key")
        if not re.fullmatch(r"https?://[a-zA-Z0-9.:-]+", self.origin):
            raise ValueError("origin must be an exact origin without a path")
        if not self.origin.startswith("https://") and self.origin not in (
            "http://127.0.0.1:8000", "http://localhost:8000"
        ):
            raise ValueError("HTTP is allowed only on the documented local development origins")
        ids = set()
        if len(self.servers) > 8:
            raise ValueError("This single-process prototype supports at most eight servers")
        for s in self.servers:
            if not re.fullmatch(r"[a-z0-9-]{1,40}", s["id"]) or s["id"] in ids:
                raise ValueError("server IDs must be unique")
            ids.add(s["id"])
            if len(base64.b64decode(s["public_key"], validate=True)) != 32:
                raise ValueError("invalid server public key")
            if not Path(s["socket"]).is_absolute():
                raise ValueError("broker socket must be an absolute local path")
            # Endpoint is inventory, not user-supplied; prevent config-line injection anyway.
            if not re.fullmatch(r"(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}", s["endpoint"]):
                raise ValueError("invalid endpoint")
            if not 1 <= int(s["endpoint"].rsplit(":", 1)[1]) <= 65535:
                raise ValueError("invalid endpoint port")
            for version, key in [(4, "subnet4"), (6, "subnet6")]:
                net = ipaddress.ip_network(s[key])
                if net.version != version or net.num_addresses < 8 or not net.is_private:
                    raise ValueError("use private tunnel subnets with at least eight addresses")
            if ipaddress.ip_network(s["subnet4"]).num_addresses > 65536:
                raise ValueError("IPv4 allocation pool too large; use /16 or smaller")
            for kind in ("dns_plain", "dns_filtered"):
                if not s.get(kind):
                    raise ValueError("configure explicit plain and filtered DNS addresses")
                for address in s[kind]:
                    ipaddress.ip_address(address)
            for key in ("country", "city"):
                if not isinstance(s[key], str) or not 1 <= len(s[key]) <= 80:
                    raise ValueError("invalid location label")
