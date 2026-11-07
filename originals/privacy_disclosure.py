"""
privacy_disclosure.py - Plain-English Disclosure & Mandatory Digital Signature Module
- Implements reading-time optimized plain-language privacy disclosures.
- Enforces mandatory full-name digital signature verification before shield activation.
- Generates SHA-256 cryptographic consent receipts.
"""

import hashlib
import time
from typing import Any, Dict, Tuple


class PrivacyDisclosureGate:
    DISCLOSURE_VERSION = "1.0-PLAIN-ENGLISH"

    @classmethod
    def get_plain_language_disclosure(cls) -> Dict[str, Any]:
        return {
            "version": cls.DISCLOSURE_VERSION,
            "title": "Cyber One Plain-English Privacy & Safety Promise",
            "reading_time_seconds": 15,
            "what_we_use_temporarily_in_memory": [
                "Your device's network connection address (only while connected, to route your encrypted tunnel).",
                "The website domain you are visiting (checked in milliseconds against live DNS to block fake sites, ads, and hackers).",
            ],
            "what_we_never_collect_or_sell": [
                "We NEVER record your browsing history, private messages, passwords, or form inputs.",
                "We NEVER sell, rent, or share your identity or network activity with advertisers or third parties.",
                "We NEVER use generative AI that guesses or invents fake security data.",
            ],
            "user_control_guarantee": (
                "All security defaults are pre-configured for maximum protection. "
                "To activate your One-Click Shield, please type your full name below to confirm "
                "you understand and agree to this privacy disclosure."
            ),
        }

    @classmethod
    def verify_and_sign_consent(cls, registered_name: str, typed_signature: str) -> Tuple[bool, str, Dict[str, Any]]:
        if not isinstance(registered_name, str) or not isinstance(typed_signature, str):
            return False, "Please enter your full name in text format to sign the disclosure.", {}

        clean_reg = " ".join(registered_name.strip().split())
        clean_sig = " ".join(typed_signature.strip().split())

        if len(clean_reg) < 2:
            return False, "Please provide your real name (at least 2 characters) to create your account.", {}

        if not clean_sig:
            return False, "Signature required: Please type your name to agree to the Privacy Disclosure before turning on protection.", {}

        if clean_reg.lower() != clean_sig.lower():
            return (
                False,
                f"Signature mismatch: You typed '{clean_sig}', which does not match your account name '{clean_reg}']. "
                "Please type your exact name to confirm you read the disclosure.",
                {},
            )

        signed_at = round(time.time(), 4)
        receipt_payload = f"{clean_reg.lower()}|{cls.DISCLOSURE_VERSION}|{signed_at}"
        signature_hash = hashlib.sha256(receipt_payload.encode("utf-8")).hexdigest()

        return True, "Disclosure signed and verified. You are ready for One-Click Protection.", {
            "account_holder": clean_reg,
            "typed_signature": clean_sig,
            "disclosure_version": cls.DISCLOSURE_VERSION,
            "signed_timestamp": signed_at,
            "cryptographic_consent_receipt": signature_hash,
        }