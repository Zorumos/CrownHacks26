"""Conservative evidence evaluation. A server handshake is not device protection."""
import time
from collections import OrderedDict
import threading


class OneClickShieldManager:
    def __init__(self, warnings):
        self.warnings = warnings
        self.seen = OrderedDict()
        self.lock = threading.Lock()

    def evaluate(self, account, device, connection, reply=None, unavailable=False, now=None):
        now = time.time() if now is None else now
        stamp = reply.get("handshake") if reply else None
        fresh = bool(reply and reply["peer_present"] and stamp is not None and 0 <= now-stamp <= 180)
        # A new connect request must see contact after its own start; old activity is not activation evidence.
        after_request = fresh and stamp >= connection["requested"]
        with self.lock:
            observation_key = (device, connection["requested"])
            before = self.seen.pop(observation_key, False)
            self.seen[observation_key] = before or fresh
            while len(self.seen) > 10000:
                self.seen.popitem(last=False)
        codes = ["BROKER_UNAVAILABLE"] if unavailable else (["TUNNEL_LOST"] if before and not fresh else [])
        if not fresh and not unavailable:
            codes.append("CLIENT_REQUIRED")
        if fresh:
            codes.append("PROTECTION_UNKNOWN")
        if connection["adblock"]:
            codes.append("ADBLOCK_UNVERIFIED")
        elapsed = round(stamp-connection["requested"], 3) if after_request else None
        return {
            "state": "unknown" if unavailable else ("tunnel_contact_observed" if fresh else "waiting_for_client"),
            "protected": None,
            "protection_status": "not_verified",
            "headline": "Tunnel contact observed; device protection unverified" if fresh else "Device protection is not verified",
            "evidence": {"source": "wireguard_server" if reply else "unavailable", "observed_at": now,
                         "peer_present": reply["peer_present"] if reply else None,
                         "last_handshake": stamp, "recent_handshake": fresh,
                         "device_routes_verified": None, "dns_verified": None,
                         "ipv6_verified": None, "kill_switch_verified": None,
                         "public_ip": None},
            "timing": {"request_to_handshake_seconds": elapsed,
                       "handshake_within_60_seconds": (elapsed < 60) if elapsed is not None else None,
                       "protection_under_60_seconds": None},
            "warnings": self.warnings.build(account, device, codes),
        }
