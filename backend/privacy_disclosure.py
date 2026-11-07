"""Versioned actual behavior, not a blanket anonymity or safety promise."""
import hashlib
import json
import unicodedata


class PrivacyDisclosureGate:
    DISCLOSURE_VERSION = "2026-11-07.1"

    @classmethod
    def get_plain_language_disclosure(cls, require_identity=False):
        document = {
            "version": cls.DISCLOSURE_VERSION,
            "title": "Before you create an account",
            "collection": [
                "We store a username, a password hash, encrypted authenticator secret, recovery-code hashes, and account/family membership.",
                "We use your typed name to record agreement. We retain a keyed digest rather than the name itself. This is personal data and does not verify your identity.",
                "We store agreement version, document hash, acceptance time, and a keyed receipt.",
                "We store your device label, public VPN key, tunnel addresses, selected server, DNS preference, and connection-request time.",
                "The API briefly processes your network address for rate limiting in memory. Sessions expire after 30 minutes; setup sessions after 10 minutes.",
            ],
            "traffic": [
                "WireGuard servers see peer network endpoints, handshake times and byte counters in memory. The API retrieves only peer presence and handshake time.",
                "The configured DNS resolver receives DNS queries. Filtered DNS may block listed domains; it cannot block every ad or inspect encrypted page content.",
                "Traffic routing exposes destination metadata to network operators. HTTPS content remains encrypted between your device and the website.",
            ],
            "providers": "No identity, analytics, advertising, or AI provider is integrated in this build. Your VPN host and DNS operator process traffic when you use their services. Review their policies before enabling a deployment.",
            "retention": "Account, agreement, device, and membership records remain until you delete them. Expired sessions and invitations are removed during API use. Server peer revocation must succeed before device/account deletion completes. Operator backups and infrastructure logs need a published retention policy before public launch.",
            "local_processing": "Generate VPN private keys on your device; never send them here. The browser keeps its API token only in memory. Passwords and typed names necessarily reach this API; use HTTPS outside localhost.",
            "identity": ("Identity verification is required by operator policy, but no provider is installed: registration is disabled." if require_identity else "This prototype does not collect IDs or verify identity. It does not claim to prevent bots or abuse through ID screening."),
            "controls": "You can revoke VPN access, remove devices, change filtered DNS when requesting a new connection, log out, or delete your account. No optional analytics are collected.",
            "limitations": "Agreement is an acknowledgment, not proof that you read this or a guarantee of privacy. This prototype has no independent security audit. A website alone cannot establish a device-wide VPN.",
            "agreement": "I have reviewed this disclosure and agree to the described processing. I understand that the VPN requires a native client and that protection is not guaranteed.",
        }
        document["document_hash"] = hashlib.sha256(json.dumps(document, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        return document

    @staticmethod
    def normalize_name(value):
        value = " ".join(unicodedata.normalize("NFKC", value).split()).casefold()
        if not 2 <= len(value) <= 120 or any(unicodedata.category(c).startswith("C") for c in value):
            raise ValueError("Enter your name using 2 to 120 printable characters.")
        return value
