"""Real server peer operations through a fixed local Unix socket, never user URLs."""
import base64
import ipaddress
import json
import socket
import time
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt


def public_key(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Use a base64-encoded WireGuard public key.") from exc
    if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
        raise ValueError("Use a canonical 32-byte WireGuard public key; never submit a private key.")
    return value


class BrokerReply(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ok: StrictBool
    public_key: str
    peer_present: StrictBool
    handshake: StrictInt | None = None


class BrokerUnavailable(Exception):
    pass


class UnixBroker:
    def call(self, server, operation, **payload):
        if not hasattr(socket, "AF_UNIX"):
            raise BrokerUnavailable("Linux broker required")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect(server["socket"])
                sock.sendall(json.dumps(dict(operation=operation, **payload)).encode()+b"\n")
                data = bytearray()
                while b"\n" not in data:
                    chunk = sock.recv(1024)
                    if not chunk:
                        raise BrokerUnavailable("Incomplete broker reply")
                    data.extend(chunk)
                    if len(data) > 4096:
                        raise BrokerUnavailable("Oversized broker reply")
            reply = BrokerReply.model_validate_json(bytes(data).split(b"\n", 1)[0])
            public_key(reply.public_key)
            if not reply.ok or reply.public_key != server["public_key"]:
                raise BrokerUnavailable("Broker did not verify configured server")
            if reply.handshake is not None and (reply.handshake < 0 or reply.handshake > time.time()+5):
                raise BrokerUnavailable("Invalid handshake time")
            return reply.model_dump()
        except BrokerUnavailable:
            raise
        except (OSError, ValueError) as exc:
            raise BrokerUnavailable("Cannot verify VPN server") from exc


def allocate(server, used):
    """The database transaction serializes allocation; .1 is reserved for the server."""
    net4, net6 = ipaddress.ip_network(server["subnet4"]), ipaddress.ip_network(server["subnet6"])
    reserved = set(server["dns_plain"]+server["dns_filtered"])
    for i in range(2, min(net4.num_addresses-1, net6.num_addresses-1)):
        address4, address6 = str(net4.network_address+i), str(net6.network_address+i)
        if address4 not in used and address4 not in reserved and address6 not in reserved:
            return address4, address6
    raise ValueError("The server's device address pool is full.")


def configuration(server, connection):
    dns = server["dns_filtered"] if connection["adblock"] else server["dns_plain"]
    return {
        "private_key_source": "native_client_only",
        "interface": {"address": [connection["address4"]+"/32", connection["address6"]+"/128"], "dns": dns},
        "peer": {"public_key": server["public_key"], "endpoint": server["endpoint"],
                 "allowed_ips": ["0.0.0.0/0", "::/0"], "persistent_keepalive": 25},
        "adblock_requested": bool(connection["adblock"]),
        "adblock_verified": None,
        "kill_switch_required": True,
        "client_steps": ["Insert the private key held on this device.", "Apply routes, DNS, IPv6 policy and kill switch in the native client.", "Activate the WireGuard tunnel and perform client-side leak checks."],
    }
