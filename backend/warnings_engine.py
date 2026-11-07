"""Deterministic, bounded warning deduplication, per account and device."""
from collections import OrderedDict
import threading
import time

CATALOG = {
    "NO_SERVERS": ("warning", "VPN is not set up yet", "No usable server is configured.", "Ask the operator to configure a VPN server.", True),
    "BROKER_UNAVAILABLE": ("warning", "Cannot reach the VPN server", "We could not confirm the server state.", "Try again. If this continues, contact the operator.", True),
    "CLIENT_REQUIRED": ("info", "Finish connecting on your device", "The server is ready; your device has not established a recent tunnel.", "Open your native VPN client and activate the connection.", True),
    "PROTECTION_UNKNOWN": ("warning", "Device protection is not verified", "A server handshake cannot confirm your device's routing, DNS, IPv6, or kill switch.", "Use the native client's connection and leak checks before relying on protection.", False),
    "TUNNEL_LOST": ("critical", "VPN contact was lost", "The server no longer sees a recent handshake. We cannot tell whether ordinary traffic is blocked.", "Check your native client's kill switch and reconnect before sending sensitive information.", True),
    "ADBLOCK_UNVERIFIED": ("info", "Ad blocking has not been verified", "Filtered DNS was requested; the client and resolver still need checking.", "Check DNS settings in the native client. Some ads cannot be blocked with DNS.", False),
    "ACCESS_REVOKED": ("info", "Server access removed", "The server peer was removed. Your device may still show a local interface.", "Turn off the tunnel in your native client.", False),
}


class PlainLanguageWarningEngine:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.states = OrderedDict()
        self.lock = threading.Lock()

    def build(self, account_id, device_id, codes):
        now = self.clock()
        key = (account_id, device_id)
        current = frozenset(codes)
        with self.lock:
            previous, shown = self.states.pop(key, (frozenset(), {}))
            result = []
            for code in codes:
                severity, title, message, action, retryable = CATALOG[code]
                changed = code not in previous
                interrupt = severity == "critical" and changed
                announce = changed or now-shown.get(code, float("-inf")) >= 60
                if announce:
                    shown[code] = now
                result.append(dict(code=code, severity=severity, title=title, message=message,
                                   action=action, retryable=retryable, interrupt=interrupt,
                                   announce=announce, delivery="persistent_banner",
                                   aria_live="assertive" if interrupt else "polite"))
            self.states[key] = (current, {c: shown[c] for c in current if c in shown})
            while len(self.states) > 10000:
                self.states.popitem(last=False)
        return result
