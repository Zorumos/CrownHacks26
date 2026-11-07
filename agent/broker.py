#!/usr/bin/env python3
"""Linux privileged broker. No public listener, shell, private-key read, or arbitrary interface."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import socketserver
import stat
import subprocess


def validate_key(key):
    raw = base64.b64decode(key, validate=True)
    if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != key:
        raise ValueError("Invalid public key")
    return key


class Agent:
    def __init__(self, config):
        self.config = config
        self.interface = config["interface"]
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", self.interface):
            raise ValueError("Invalid fixed interface")
        self.net4 = ipaddress.ip_network(config["subnet4"])
        self.net6 = ipaddress.ip_network(config["subnet6"])
        self.wg = config.get("wg_binary", "/usr/bin/wg")
        if not Path(self.wg).is_absolute():
            raise ValueError("wg path must be absolute")

    def run(self, *args):
        return subprocess.run([self.wg, *args], check=True, timeout=2, capture_output=True,
                              text=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).stdout.strip()

    def execute(self, req):
        if not isinstance(req, dict) or set(req)-{"operation", "key", "address4", "address6"}:
            raise ValueError("Unknown fields")
        op = req.get("operation")
        if op not in {"health", "status", "provision", "revoke"}:
            raise ValueError("Unsupported operation")
        server_key = validate_key(self.run("show", self.interface, "public-key"))
        if op == "health":
            if set(req) != {"operation"}:
                raise ValueError("Unexpected fields")
            return dict(ok=True, public_key=server_key, peer_present=False, handshake=None)
        key = validate_key(req["key"])
        if op == "provision":
            a4, a6 = ipaddress.ip_address(req["address4"]), ipaddress.ip_address(req["address6"])
            for address, network in ((a4, self.net4), (a6, self.net6)):
                if address not in network or int(address)-int(network.network_address) < 2 or address == network.broadcast_address:
                    raise ValueError("Address outside assigned client pool")
                if str(address) in self.config.get("reserved_addresses", []):
                    raise ValueError("Address reserved for infrastructure")
            expected = {str(a4)+"/32", str(a6)+"/128"}
            for line in self.run("show", self.interface, "allowed-ips").splitlines():
                other, ranges = line.split("\t", 1)
                # `wg show IFACE allowed-ips` separates networks with spaces (dump uses commas).
                networks = [ipaddress.ip_network(x) for x in ranges.split() if x != "(none)"]
                if other != key and any(address.version == net.version and address in net for address in (a4, a6) for net in networks):
                    raise ValueError("Address already assigned to another peer")
                if other == key and {str(n) for n in networks} != expected:
                    raise ValueError("Existing peer has a different allocation")
            self.run("set", self.interface, "peer", key, "allowed-ips", ",".join(sorted(expected)))
        elif set(req) != {"operation", "key"}:
            raise ValueError("Unexpected fields")
        if op == "revoke":
            self.run("set", self.interface, "peer", key, "remove")
        stamps = {}
        for line in self.run("show", self.interface, "latest-handshakes").splitlines():
            peer, stamp = line.split("\t")
            stamps[peer] = int(stamp)
        return dict(ok=True, public_key=server_key, peer_present=key in stamps,
                    handshake=(stamps.get(key) or None))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    info = args.config.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise SystemExit("Broker config must be root-owned and not group/world writable")
    agent = Agent(json.loads(args.config.read_text()))

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                raw = self.rfile.readline(4097)
                if len(raw) > 4096 or not raw.endswith(b"\n"):
                    raise ValueError("Request too large")
                reply = agent.execute(json.loads(raw))
            except Exception:
                # Never expose command stderr, endpoint data, or keys through error responses.
                reply = {"ok": False, "public_key": "", "peer_present": False, "handshake": None}
            self.wfile.write(json.dumps(reply).encode()+b"\n")

    path = Path(agent.config["socket"])
    if not path.is_absolute() or not path.parent.is_dir():
        raise SystemExit("Create a dedicated root-owned socket directory first")
    parent = path.parent.stat()
    if parent.st_uid != 0 or parent.st_mode & 0o022:
        raise SystemExit("Socket directory must be root-owned and not group/world writable")
    if path.exists():
        if not path.is_socket():
            raise SystemExit("Refusing to replace non-socket file")
        path.unlink()
    os.umask(0o117)
    with socketserver.UnixStreamServer(str(path), Handler) as server:
        os.chown(path, 0, int(agent.config["api_group_id"]))
        os.chmod(path, 0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()
