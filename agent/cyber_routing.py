"""AgentCyber task-route classification helpers.

This module is intentionally pure: it classifies task text and provider-family
preference, but it does not switch live models or send any requests. Runtime
model selection can consume these decisions in a later, separately approved
lane.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CyberRoute(str, Enum):
    """AgentCyber route labels from the Hermes Cyber Edition mandate."""

    GENERAL = "general"
    CYBER_LAB = "cyber_lab"
    IR_BREAKGLASS = "ir_breakglass"
    MALWARE_RE = "malware_re"
    OSINT = "osint"
    CREDENTIALS_SENSITIVE = "credentials_sensitive"
    DESTRUCTIVE_HIGH_RISK = "destructive_high_risk"


class ProviderPreference(str, Enum):
    """Provider-family preference for a classified task."""

    DEFAULT = "default"
    LOCAL_OPEN_WEIGHT = "local_open_weight"
    HOSTED = "hosted"


@dataclass(frozen=True)
class CyberRouteDecision:
    """Classification result for a single operator request."""

    route: CyberRoute
    provider_preference: ProviderPreference
    reason: str
    requires_hosted_secret_confirmation: bool = False
    explicit_override: str | None = None


_LOCAL_OVERRIDE_PHRASES = (
    "use local model",
    "use a local model",
    "use local",
    "local model",
)
_AZURE_OVERRIDE_PHRASES = (
    "use azure",
    "use microsoft",
    "azure model",
)
_CYBER_OVERRIDE_PHRASES = (
    "use cyber route",
    "cyber route",
    "cyber model",
)

_DESTRUCTIVE_TERMS = (
    "wipe",
    "destroy",
    "delete all",
    "rm -rf",
    "format disk",
    "factory reset",
    "reset the firewall",
    "password reset",
    "rotate credentials",
    "disable account",
)
_BREAKGLASS_TERMS = (
    "locked out",
    "password changed",
    "can't access",
    "cant access",
    "get me back in",
    "emergency access",
    "incident response",
    "incident timeline",
    "access recovery",
    "restore access",
)
_CREDENTIAL_TERMS = (
    "credential",
    "password",
    "secret",
    "api key",
    "token",
    "ssh key",
    "mfa",
)
_MALWARE_TERMS = (
    "malware",
    "worm",
    "ransomware",
    "ioc",
    "reverse engineering",
    "reverse engineer",
    "sample",
    "sandbox",
)
_EXPLOIT_TERMS = (
    "exploit",
    "payload",
    "c2",
    "persistence",
    "evasion",
    "fingerprinting",
    "vulnerability",
    "scan",
    "nmap",
)
_LAB_SCOPE_TERMS = (
    "owned",
    "lab",
    "vm ",
    "proxmox",
    "breaking circuits",
    "bc-owned",
    "my server",
)
_OSINT_TERMS = (
    "osint",
    "public records",
    "public company",
    "domain research",
    "recon",
    "open source intelligence",
)


def classify_cyber_route(message: str) -> CyberRouteDecision:
    """Classify a user request into the first AgentCyber routing slice.

    The route captures task type/safety sensitivity. The provider preference is
    a non-executing recommendation: sensitive cyber routes prefer local or
    open-weight models, ordinary work stays on the configured default, and
    explicit operator overrides are recorded without hiding the underlying
    route.
    """

    text = message.lower()
    override = _explicit_override(text)
    route, reason = _classify_route(text)
    provider_preference = _provider_preference(route, override)
    requires_hosted_secret_confirmation = route in {
        CyberRoute.CREDENTIALS_SENSITIVE,
        CyberRoute.IR_BREAKGLASS,
    }

    return CyberRouteDecision(
        route=route,
        provider_preference=provider_preference,
        reason=reason,
        requires_hosted_secret_confirmation=requires_hosted_secret_confirmation,
        explicit_override=override,
    )


def _explicit_override(text: str) -> str | None:
    if _contains_any(text, _LOCAL_OVERRIDE_PHRASES):
        return "local"
    if _contains_any(text, _AZURE_OVERRIDE_PHRASES):
        return "azure"
    if _contains_any(text, _CYBER_OVERRIDE_PHRASES):
        return "cyber"
    return None


def _classify_route(text: str) -> tuple[CyberRoute, str]:
    if _contains_any(text, _DESTRUCTIVE_TERMS):
        return CyberRoute.DESTRUCTIVE_HIGH_RISK, "destructive or high-impact operation"
    if _contains_any(text, _BREAKGLASS_TERMS):
        return CyberRoute.IR_BREAKGLASS, "lockout or incident recovery request"
    if _contains_any(text, _CREDENTIAL_TERMS):
        return CyberRoute.CREDENTIALS_SENSITIVE, "credential or secret handling request"
    if _contains_any(text, _MALWARE_TERMS):
        return CyberRoute.MALWARE_RE, "malware or reverse-engineering request"
    if _contains_any(text, _OSINT_TERMS):
        return CyberRoute.OSINT, "OSINT or public-source investigation"
    if _contains_any(text, _EXPLOIT_TERMS) and _contains_any(text, _LAB_SCOPE_TERMS):
        return CyberRoute.CYBER_LAB, "authorized lab security testing request"
    if _contains_any(text, _EXPLOIT_TERMS):
        return CyberRoute.CYBER_LAB, "cyber-sensitive testing request needing scope tracking"
    return CyberRoute.GENERAL, "ordinary general task"


def _provider_preference(route: CyberRoute, override: str | None) -> ProviderPreference:
    if override in {"local", "cyber"}:
        return ProviderPreference.LOCAL_OPEN_WEIGHT
    if override == "azure":
        return ProviderPreference.HOSTED
    if route in {
        CyberRoute.CYBER_LAB,
        CyberRoute.IR_BREAKGLASS,
        CyberRoute.MALWARE_RE,
        CyberRoute.CREDENTIALS_SENSITIVE,
        CyberRoute.DESTRUCTIVE_HIGH_RISK,
    }:
        return ProviderPreference.LOCAL_OPEN_WEIGHT
    return ProviderPreference.DEFAULT


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)
