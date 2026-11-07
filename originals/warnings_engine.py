"""
warnings_engine.py - Plain-Language, Actionable, & Timed Warnings Module
- Converts complex technical alerts into calm, plain-English explanations.
- Implements anti-fatigue timing cooldowns so users aren't spammed with repetitive popups.
"""

import time
from typing import Any, Dict, List, Tuple


class PlainLanguageWarningEngine:
    COOLDOWN_SECONDS = 30.0

    def __init__(self) -> None:
        self._last_warning_times: Dict[str, float] = {}

    def build_user_warning(
        self,
        verdict_decision: str,
        triggered_signals: List[Dict[str, Any]],
        destination_host: str,
        ad_blocked: bool = False,
    ) -> Dict[str, Any]:
        now = time.time()

        if ad_blocked:
            return {
                "alert_level": "SAFE_BACKGROUND_BLOCK",
                "interrupt_user_now": False,
                "delivery_timing": "SILENT_DASHBOARD_COUNTER_ONLY",
                "why_timed_this_way": "Ads and trackers are blocked silently in the background so you are never interrupted while browsing.",
                "plain_english_title": "Ad / Tracker Blocked Automatically",
                "what_happened": f"We quietly stopped an advertising or tracking server ({destination_host}) from following you.",
                "what_you_should_do": "No action needed. Keep browsing normally.",
            }

        if verdict_decision == "ALLOW_TUNNEL":
            return {
                "alert_level": "NONE",
                "interrupt_user_now": False,
                "delivery_timing": "NO_ALERT_NEEDED",
                "plain_english_title": "Connection Verified & Encrypted",
                "what_happened": f"Your connection to {destination_host} is verified, encrypted, and safe.",
                "what_you_should_do": "No action needed.",
            }

        primary_code = triggered_signals[0]["signal"] if triggered_signals else "UNKNOWN_ANOMALY"
        title, explanation, action_step, urgency = self._translate_signal_to_plain_english(primary_code, destination_host)

        dedup_key = f"{primary_code.split()[0]}:{destination_host}"
        last_shown = self._last_warning_times.get(dedup_key, 0.0)
        in_cooldown = (now - last_shown) < self.COOLDOWN_SECONDS

        if urgency == "CRITICAL_IMMEDIATE" or not in_cooldown:
            self._last_warning_times[dedup_key] = now
            should_interrupt = True
            timing_mode = "IMMEDIATE_INTERVENTION_AT_MOMENT_OF_RISK"
        else:
            should_interrupt = False
            timing_mode = "COOLDOWN_ACTIVE_CONSOLIDATED_BANNER"

        return {
            "alert_level": urgency,
            "interrupt_user_now": should_interrupt,
            "delivery_timing": timing_mode,
            "plain_english_title": title,
            "what_happened": explanation,
            "what_you_should_do": action_step,
            "technical_reference_for_developers": primary_code,
        }

    @staticmethod
    def _translate_signal_to_plain_english(signal_code: str, host: str) -> Tuple[str, str, str, str]:
        if "UNRESOLVABLE_DESTINATION_HOST" in signal_code:
            return (
                "Website Address Does Not Exist",
                f"We could not find '{host}' on the real internet. It may be a typo, or a fake link trying to trick you.",
                f"Check the spelling of '{host}', or close the page if you clicked a suspicious link.",
                "MEDIUM_ACTIONABLE",
            )
        if "DNS_REBINDING" in signal_code or "NON_GLOBAL" in signal_code:
            return (
                "Blocked Attempt to Peek at Your Local Wi-Fi",
                f"The address '{host}' tried to secretly redirect into your private home/office network.",
                "Leave this website immediately. Your One-Click Shield has already blocked the connection.",
                "CRITICAL_IMMEDIATE",
            )
        if "BINARY_OPCODE_SLED" in signal_code or "SYSTEM_BINARY" in signal_code or "EXECUTABLE" in signal_code or "NULL_BYTE" in signal_code or "PATH_TRAVERSAL" in signal_code:
            return (
                "Harmful Attack Code Blocked",
                f"Traffic heading to '{host}' contained hidden computer commands designed to break into a system.",
                "Do not download or open files from this source. Your VPN Shield safely dropped the connection.",
                "CRITICAL_IMMEDIATE",
            )
        if "INVALID_OR_UNTRUSTED_TLS_CERTIFICATE" in signal_code:
            return (
                "Untrusted Website Security Certificate",
                f"'{host}' failed its cryptographic identity check. Someone on the network could be impersonating this website.",
                "Do not enter passwords or credit cards on this site. Try reconnecting on a different network.",
                "CRITICAL_IMMEDIATE",
            )
        if "LIVE_TCP_ENDPOINT_UNREACHABLE" in signal_code:
            return (
                "Website Server Is Currently Offline",
                f"'{host}' is a real address, but its server refused to answer our connection test.",
                "Wait a minute and try again, or check if the website is down for maintenance.",
                "MEDIUM_ACTIONABLE",
            )
        if "HIGH_ENTROPY_SUBDOMAIN" in signal_code:
            return (
                "Suspicious Computer-Generated Web Address",
                f"'{host}' looks like a scrambled address often used by malware to hide communication.",
                "Close the tab that opened this connection unless you specifically recognize this service.",
                "HIGH_ACTIONABLE",
            )
        return (
            "Unusual Network Connection Paused",
            f"Connection to '{host}' used an uncommon port and network pattern that looked unsafe.",
            "If you are a developer testing a custom port, verify your server's TLS certificate; otherwise stay disconnected.",
            "HIGH_ACTIONABLE",
        )