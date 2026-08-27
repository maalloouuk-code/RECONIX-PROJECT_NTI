from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from enum import Enum
from time import perf_counter
from typing import Any, Dict, List, Optional, Tuple, Union

from colorama import Fore, Style, init


# ==============================================================================
# MODULE: models.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Data Models
Defines type-safe data structures, enums, and schemas for passive behavioral security analysis.
"""



class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class BehaviorStatus(str, Enum):
    RESTRICTIVE = "RESTRICTIVE"
    CONSISTENT = "CONSISTENT"
    PERMISSIVE = "PERMISSIVE"
    INCONSISTENT = "INCONSISTENT"
    RISKY = "RISKY"
    ANOMALOUS = "ANOMALOUS"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW_MEDIUM = "LOW/MEDIUM"
    LOW = "LOW"


class ConsistencyLevel(str, Enum):
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    CRITICAL_INCONSISTENCY = "CRITICAL INCONSISTENCY"


class AnomalyClassification(str, Enum):
    NORMAL_BEHAVIOR = "NORMAL BEHAVIOR"
    WARNING = "WARNING"
    ANOMALY = "ANOMALY"
    HIGH_RISK_BEHAVIOR = "HIGH-RISK BEHAVIOR"


@dataclass
class EvidenceObservation:
    title: str
    category: str
    severity: Severity
    confidence: int  # 0 - 100
    observation: str
    evidence: List[str]
    impact: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "confidence": self.confidence,
            "observation": self.observation,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
        }


@dataclass
class RedirectStep:
    step: int
    status_code: int
    source_url: str
    destination_url: str
    protocol_change: str  # "NONE", "UPGRADE_TO_HTTPS", "DOWNGRADE_TO_HTTP"
    host_change: bool
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TransitionBehavior(str, Enum):
    CANONICAL_UPGRADE = "CANONICAL_UPGRADE"
    TEMPORARY_UPGRADE = "TEMPORARY_UPGRADE"
    DOWNGRADE = "DOWNGRADE"
    SAME_SCHEME = "SAME_SCHEME"
    UNKNOWN = "UNKNOWN"


class ChainBehavior(str, Enum):
    SINGLE_HOP = "SINGLE_HOP"
    MULTI_HOP = "MULTI_HOP"
    EXCESSIVE = "EXCESSIVE"
    LOOP = "LOOP"
    UNKNOWN = "UNKNOWN"


class DomainBehavior(str, Enum):
    SAME_DOMAIN = "SAME_DOMAIN"
    CROSS_DOMAIN = "CROSS_DOMAIN"
    UNKNOWN = "UNKNOWN"


class FinalTransportBehavior(str, Enum):
    HTTPS = "HTTPS"
    HTTP = "HTTP"
    UNKNOWN = "UNKNOWN"


@dataclass
class RedirectBehavior:
    transition_behavior: TransitionBehavior = TransitionBehavior.UNKNOWN
    chain_behavior: ChainBehavior = ChainBehavior.UNKNOWN
    domain_behavior: DomainBehavior = DomainBehavior.UNKNOWN
    final_transport: FinalTransportBehavior = FinalTransportBehavior.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transition_behavior": self.transition_behavior.value if isinstance(self.transition_behavior, Enum) else str(self.transition_behavior),
            "chain_behavior": self.chain_behavior.value if isinstance(self.chain_behavior, Enum) else str(self.chain_behavior),
            "domain_behavior": self.domain_behavior.value if isinstance(self.domain_behavior, Enum) else str(self.domain_behavior),
            "final_transport": self.final_transport.value if isinstance(self.final_transport, Enum) else str(self.final_transport),
        }


@dataclass
class RedirectProfile:
    score: int
    status: BehaviorStatus
    total_hops: int
    pattern_classification: str
    redirect_chain: List[RedirectStep] = field(default_factory=list)
    has_downgrade: bool = False
    has_excessive_hops: bool = False
    is_circular: bool = False
    findings: List[str] = field(default_factory=list)
    behavior: RedirectBehavior = field(default_factory=RedirectBehavior)
    confidence: int = 0
    confidence_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["status"] = self.status.value if isinstance(self.status, BehaviorStatus) else str(self.status)
        res["behavior"] = self.behavior.to_dict() if isinstance(self.behavior, RedirectBehavior) else self.behavior
        return res


@dataclass
class CookieAttribute:
    name: str
    value_preview: str
    secure: bool
    httponly: bool
    samesite: Optional[str]  # "Strict", "Lax", "None", None
    domain: Optional[str]
    path: Optional[str]
    max_age: Optional[int]
    expires: Optional[str]
    has_secure_prefix: bool
    has_host_prefix: bool
    is_sensitive: bool
    is_persistent: bool = False
    is_csrf_token: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SessionProtectionBehavior(str, Enum):
    SECURE_SESSION_BEHAVIOR = "SECURE_SESSION_BEHAVIOR"
    PARTIAL_SESSION_PROTECTION = "PARTIAL_SESSION_PROTECTION"
    WEAK_SESSION_PROTECTION = "WEAK_SESSION_PROTECTION"
    NO_SENSITIVE_COOKIES = "NO_SENSITIVE_COOKIES"
    UNKNOWN = "UNKNOWN"


class ScriptAccessibilityBehavior(str, Enum):
    SCRIPT_RESTRICTED = "SCRIPT_RESTRICTED"
    SCRIPT_ACCESSIBLE = "SCRIPT_ACCESSIBLE"
    UNKNOWN = "UNKNOWN"


class CrossSiteBehavior(str, Enum):
    CROSS_SITE_RESTRICTED = "CROSS_SITE_RESTRICTED"
    CROSS_SITE_ALLOWED = "CROSS_SITE_ALLOWED"
    CROSS_SITE_UNSPECIFIED = "CROSS_SITE_UNSPECIFIED"
    UNKNOWN = "UNKNOWN"


class ScopeBehavior(str, Enum):
    HOST_ONLY = "HOST_ONLY"
    DOMAIN_SCOPED = "DOMAIN_SCOPED"
    HYBRID_SCOPED = "HYBRID_SCOPED"
    UNKNOWN = "UNKNOWN"


class PrefixBehavior(str, Enum):
    PREFIX_HARDENED = "PREFIX_HARDENED"
    PREFIX_STANDARD = "PREFIX_STANDARD"
    PREFIX_VIOLATION = "PREFIX_VIOLATION"
    UNKNOWN = "UNKNOWN"


class CookieConsistencyBehavior(str, Enum):
    CONSISTENT_POLICY = "CONSISTENT_POLICY"
    INCONSISTENT_COOKIE_POLICY = "INCONSISTENT_COOKIE_POLICY"
    UNKNOWN = "UNKNOWN"


@dataclass
class CookieBehavior:
    session_protection: SessionProtectionBehavior = SessionProtectionBehavior.UNKNOWN
    script_accessibility: ScriptAccessibilityBehavior = ScriptAccessibilityBehavior.UNKNOWN
    cross_site_behavior: CrossSiteBehavior = CrossSiteBehavior.UNKNOWN
    scope_behavior: ScopeBehavior = ScopeBehavior.UNKNOWN
    prefix_behavior: PrefixBehavior = PrefixBehavior.UNKNOWN
    consistency_behavior: CookieConsistencyBehavior = CookieConsistencyBehavior.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_protection": self.session_protection.value if isinstance(self.session_protection, Enum) else str(self.session_protection),
            "script_accessibility": self.script_accessibility.value if isinstance(self.script_accessibility, Enum) else str(self.script_accessibility),
            "cross_site_behavior": self.cross_site_behavior.value if isinstance(self.cross_site_behavior, Enum) else str(self.cross_site_behavior),
            "scope_behavior": self.scope_behavior.value if isinstance(self.scope_behavior, Enum) else str(self.scope_behavior),
            "prefix_behavior": self.prefix_behavior.value if isinstance(self.prefix_behavior, Enum) else str(self.prefix_behavior),
            "consistency_behavior": self.consistency_behavior.value if isinstance(self.consistency_behavior, Enum) else str(self.consistency_behavior),
        }


@dataclass
class CookieProfile:
    score: int
    status: BehaviorStatus
    cookies_analyzed: List[CookieAttribute] = field(default_factory=list)
    total_cookies: int = 0
    sensitive_cookies_count: int = 0
    inconsistent_attributes: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    behavior: CookieBehavior = field(default_factory=CookieBehavior)
    confidence: int = 0
    confidence_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["status"] = self.status.value if isinstance(self.status, BehaviorStatus) else str(self.status)
        res["behavior"] = self.behavior.to_dict() if isinstance(self.behavior, CookieBehavior) else self.behavior
        return res


class HttpsEnforcementBehavior(str, Enum):
    STRONG = "STRONG"
    PARTIAL = "PARTIAL"
    WEAK = "WEAK"
    UNKNOWN = "UNKNOWN"


class CleartextExposureBehavior(str, Enum):
    RESTRICTED = "RESTRICTED"
    REDIRECTED = "REDIRECTED"
    DIRECT = "DIRECT"
    UNKNOWN = "UNKNOWN"


class RedirectPolicyBehavior(str, Enum):
    CANONICAL = "CANONICAL"
    TEMPORARY = "TEMPORARY"
    NON_HTTPS = "NON_HTTPS"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class HstsPolicyBehavior(str, Enum):
    STRONG = "STRONG"
    BASIC = "BASIC"
    MISSING = "MISSING"
    UNKNOWN = "UNKNOWN"


class ProtocolConsistencyBehavior(str, Enum):
    CONSISTENT = "CONSISTENT"
    INCONSISTENT = "INCONSISTENT"
    UNKNOWN = "UNKNOWN"


@dataclass
class TransportBehavior:
    https_enforcement: HttpsEnforcementBehavior = HttpsEnforcementBehavior.UNKNOWN
    cleartext_exposure: CleartextExposureBehavior = CleartextExposureBehavior.UNKNOWN
    redirect_policy: RedirectPolicyBehavior = RedirectPolicyBehavior.UNKNOWN
    hsts_policy: HstsPolicyBehavior = HstsPolicyBehavior.UNKNOWN
    protocol_consistency: ProtocolConsistencyBehavior = ProtocolConsistencyBehavior.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "https_enforcement": self.https_enforcement.value if isinstance(self.https_enforcement, Enum) else str(self.https_enforcement),
            "cleartext_exposure": self.cleartext_exposure.value if isinstance(self.cleartext_exposure, Enum) else str(self.cleartext_exposure),
            "redirect_policy": self.redirect_policy.value if isinstance(self.redirect_policy, Enum) else str(self.redirect_policy),
            "hsts_policy": self.hsts_policy.value if isinstance(self.hsts_policy, Enum) else str(self.hsts_policy),
            "protocol_consistency": self.protocol_consistency.value if isinstance(self.protocol_consistency, Enum) else str(self.protocol_consistency),
        }


@dataclass
class TransportProfile:
    score: int
    status: BehaviorStatus
    http_accessible: bool
    https_accessible: bool
    enforces_https: bool
    hsts_present: bool
    hsts_max_age: Optional[int]
    hsts_include_subdomains: bool
    hsts_preload: bool
    http_redirect_code: Optional[int]
    findings: List[str] = field(default_factory=list)
    behavior: TransportBehavior = field(default_factory=TransportBehavior)
    confidence: int = 0
    confidence_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["status"] = self.status.value if isinstance(self.status, BehaviorStatus) else str(self.status)
        res["behavior"] = self.behavior.to_dict() if isinstance(self.behavior, TransportBehavior) else self.behavior
        return res


class OriginTrustBehavior(str, Enum):
    SAME_ORIGIN_ONLY = "SAME_ORIGIN_ONLY"
    PUBLIC_WILDCARD = "PUBLIC_WILDCARD"
    REFLECTED_ORIGIN = "REFLECTED_ORIGIN"
    NULL_ORIGIN_TRUSTED = "NULL_ORIGIN_TRUSTED"
    RESTRICTED_SPECIFIC_ORIGIN = "RESTRICTED_SPECIFIC_ORIGIN"
    UNKNOWN = "UNKNOWN"


class CredentialExposureBehavior(str, Enum):
    CREDENTIALS_EXPOSED = "CREDENTIALS_EXPOSED"
    CREDENTIALS_RESTRICTED = "CREDENTIALS_RESTRICTED"
    CREDENTIALS_UNSPECIFIED = "CREDENTIALS_UNSPECIFIED"
    UNKNOWN = "UNKNOWN"


class PreflightBehavior(str, Enum):
    PREFLIGHT_STANDARD = "PREFLIGHT_STANDARD"
    PREFLIGHT_PERMISSIVE_WILDCARD = "PREFLIGHT_PERMISSIVE_WILDCARD"
    PREFLIGHT_RESTRICTED = "PREFLIGHT_RESTRICTED"
    PREFLIGHT_NOT_APPLICABLE = "PREFLIGHT_NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class CORSBehavior:
    origin_trust: OriginTrustBehavior = OriginTrustBehavior.UNKNOWN
    credential_exposure: CredentialExposureBehavior = CredentialExposureBehavior.UNKNOWN
    preflight_behavior: PreflightBehavior = PreflightBehavior.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin_trust": self.origin_trust.value if isinstance(self.origin_trust, Enum) else str(self.origin_trust),
            "credential_exposure": self.credential_exposure.value if isinstance(self.credential_exposure, Enum) else str(self.credential_exposure),
            "preflight_behavior": self.preflight_behavior.value if isinstance(self.preflight_behavior, Enum) else str(self.preflight_behavior),
        }


@dataclass
class CORSProfile:
    score: int
    status: BehaviorStatus
    access_control_allow_origin: Optional[str]
    access_control_allow_credentials: bool
    access_control_allow_methods: List[str] = field(default_factory=list)
    access_control_allow_headers: List[str] = field(default_factory=list)
    is_wildcard: bool = False
    is_null_origin_allowed: bool = False
    is_origin_reflected: bool = False
    policy_risk: str = "SAFE"
    findings: List[str] = field(default_factory=list)
    behavior: CORSBehavior = field(default_factory=CORSBehavior)
    confidence: int = 0
    confidence_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["status"] = self.status.value if isinstance(self.status, BehaviorStatus) else str(self.status)
        res["behavior"] = self.behavior.to_dict() if isinstance(self.behavior, CORSBehavior) else self.behavior
        return res


@dataclass
class MethodProfile:
    score: int
    status: BehaviorStatus
    advertised_methods: List[str] = field(default_factory=list)
    options_response_code: Optional[int] = None
    trace_enabled: bool = False
    track_enabled: bool = False
    put_delete_advertised: bool = False
    connect_advertised: bool = False
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["status"] = self.status.value if isinstance(self.status, BehaviorStatus) else str(self.status)
        return res


@dataclass
class DisclosureProfile:
    score: int
    status: BehaviorStatus
    server_banner: Optional[str] = None
    x_powered_by: Optional[str] = None
    framework_headers: Dict[str, str] = field(default_factory=dict)
    detailed_versions_exposed: List[str] = field(default_factory=list)
    debug_headers_detected: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["status"] = self.status.value if isinstance(self.status, BehaviorStatus) else str(self.status)
        return res


@dataclass
class BehavioralAnomaly:
    title: str
    category: str
    classification: AnomalyClassification
    description: str
    evidence: List[str]
    severity: Severity
    affected_domains: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "classification": self.classification.value if isinstance(self.classification, AnomalyClassification) else str(self.classification),
            "description": self.description,
            "evidence": self.evidence,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "affected_domains": self.affected_domains,
        }


@dataclass
class CorrelatedRisk:
    rule_id: str
    title: str
    primary_domains: List[str]
    severity: Severity
    confidence: int
    combined_mechanism: str
    trigger_observations: List[str]
    evidence: List[str]
    impact: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "primary_domains": self.primary_domains,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "confidence": self.confidence,
            "combined_mechanism": self.combined_mechanism,
            "trigger_observations": self.trigger_observations,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
        }


@dataclass
class OverallAssessment:
    score: int
    risk_level: RiskLevel
    behavioral_consistency: ConsistencyLevel
    anomalies_count: int
    correlated_risks_count: int
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else str(self.risk_level),
            "behavioral_consistency": self.behavioral_consistency.value if isinstance(self.behavioral_consistency, ConsistencyLevel) else str(self.behavioral_consistency),
            "anomalies_count": self.anomalies_count,
            "correlated_risks_count": self.correlated_risks_count,
            "summary": self.summary,
        }


@dataclass
class SecurityBehaviorReport:
    feature: str
    target: str
    scan_timestamp: str
    overall: OverallAssessment
    profile: Dict[str, Any]
    observations: List[EvidenceObservation]
    anomalies: List[BehavioralAnomaly]
    correlated_risks: List[CorrelatedRisk]
    recommendations: List[Dict[str, Any]]
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "target": self.target,
            "scan_timestamp": self.scan_timestamp,
            "overall": self.overall.to_dict(),
            "profile": self.profile,
            "observations": [o.to_dict() for o in self.observations],
            "anomalies": [a.to_dict() for a in self.anomalies],
            "correlated_risks": [c.to_dict() for c in self.correlated_risks],
            "recommendations": self.recommendations,
            "execution_time_ms": round(self.execution_time_ms, 2),
        }


# ==============================================================================
# MODULE: rules.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Rules and Constants
Configurable thresholds, weights, heuristic signatures, and detection rules.
"""


# Domain Scoring Weights (Sum = 1.0)
DOMAIN_WEIGHTS = {
    "transport_security": 0.22,
    "redirect_behavior": 0.16,
    "cookie_behavior": 0.20,
    "cors_behavior": 0.16,
    "http_method_behavior": 0.14,
    "information_disclosure": 0.12,
}

# Score Thresholds for Risk Classification
RISK_THRESHOLDS = [
    (90, RiskLevel.LOW),
    (75, RiskLevel.LOW_MEDIUM),
    (50, RiskLevel.MEDIUM),
    (25, RiskLevel.HIGH),
    (0, RiskLevel.CRITICAL),
]

# Sensitive Session and Authentication Cookie Name Patterns (Case-insensitive substrings/regexes)
SENSITIVE_COOKIE_PATTERNS = [
    "session",
    "sess",
    "jwt",
    "token",
    "auth",
    "sid",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "remember",
    "account",
    "user",
    "logged_in",
    "sso",
]

# Client-Readable Double-Submit CSRF Token Patterns (Legitimately client-readable via JS)
CSRF_TOKEN_COOKIE_PATTERNS = [
    "csrf",
    "xsrf",
    "_csrf",
    "csrftoken",
    "xsrf-token",
    "csrf-token",
    "x-csrftoken",
]

# Dangerous or Risky HTTP Methods
DANGEROUS_METHODS = {
    "TRACE": (Severity.HIGH, "Cross-Site Tracing (XST) risk allowing extraction of credentials from headers"),
    "TRACK": (Severity.HIGH, "Diagnostic method similar to TRACE posing header reflection risk"),
    "CONNECT": (Severity.MEDIUM, "Tunnel proxying method should not be exposed on standard web endpoints"),
    "PUT": (Severity.LOW, "State-modifying method advertised in unauthenticated context"),
    "DELETE": (Severity.LOW, "State-modifying method advertised in unauthenticated context"),
}

# Known Information Disclosure Headers
DISCLOSURE_HEADERS = {
    "server": "Server software and operating system banner",
    "x-powered-by": "Application runtime or framework technology",
    "x-aspnet-version": "ASP.NET framework version",
    "x-aspnetmvc-version": "ASP.NET MVC framework version",
    "x-generator": "Content management system or site generator",
    "x-runtime": "Backend execution environment duration",
    "x-version": "Application version identifier",
    "x-backend-server": "Internal infrastructure server name",
    "x-debug-token": "Active debugger session token",
    "via": "Intermediate proxy / reverse proxy information",
}

# Standard Recommended Security Headers (for normalized header consumption)
RECOMMENDED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

# ==========================================
# Transport Security Domain Rules & Weights
# ==========================================

# HSTS Configuration Thresholds (in seconds)
HSTS_MIN_RECOMMENDED_MAX_AGE = 15768000   # 180 days (~6 months) minimum baseline
HSTS_STRONG_RECOMMENDED_MAX_AGE = 31536000 # 365 days (1 year) industry standard best practice

# Core Transport Security Scoring Deductions
TRANSPORT_DEDUCTION_NO_HTTPS = 60          # HTTPS endpoint unavailable / handshake failed
TRANSPORT_DEDUCTION_CLEARTEXT_SERVED = 45  # HTTP directly serves content (200 OK) without HTTPS upgrade
TRANSPORT_DEDUCTION_REDIRECT_NOT_HTTPS = 25 # HTTP redirects to another non-HTTPS endpoint
TRANSPORT_DEDUCTION_TEMPORARY_REDIRECT = 5  # HTTP uses temporary redirect (302/307) instead of 301/308

# Transport Hardening Scoring Deductions (Missing hardening should NOT cause HIGH_RISK on its own)
TRANSPORT_DEDUCTION_MISSING_HSTS = 20      # HSTS absent on HTTPS response
TRANSPORT_DEDUCTION_SHORT_HSTS = 10        # HSTS max-age < 31536000 (1 year)
TRANSPORT_DEDUCTION_NO_SUBDOMAINS = 5      # HSTS missing 'includeSubDomains'
TRANSPORT_DEDUCTION_NO_PRELOAD = 0         # Informational only; missing preload is not penalized as a vulnerability

# Transport Domain Behavior Status Thresholds
TRANSPORT_STATUS_RESTRICTIVE_THRESHOLD = 90
TRANSPORT_STATUS_CONSISTENT_THRESHOLD = 75
TRANSPORT_STATUS_PERMISSIVE_THRESHOLD = 50
TRANSPORT_STATUS_INCONSISTENT_THRESHOLD = 25

# ==========================================
# Redirect Behavior Domain Rules & Weights
# ==========================================

REDIRECT_EXCESSIVE_HOPS_THRESHOLD = 3
REDIRECT_DEDUCTION_DOWNGRADE = 45           # Severe: Insecure protocol downgrade HTTPS -> HTTP
REDIRECT_DEDUCTION_EXCESSIVE_PER_HOP = 10   # Deduct 10 pts per hop exceeding 3
REDIRECT_DEDUCTION_EXCESSIVE_MAX = 30       # Cap excessive hop deduction at 30 pts
REDIRECT_DEDUCTION_LOOP = 50                # Severe: Circular redirect loop
REDIRECT_DEDUCTION_TEMPORARY_UPGRADE = 5    # Minor: HTTP -> HTTPS upgrade via 302/307 rather than 301/308
REDIRECT_DEDUCTION_CROSS_DOMAIN = 0         # Cross-domain routing is a behavioral classification, not a deduction

# Redirect Domain Behavior Status Thresholds
REDIRECT_STATUS_CONSISTENT_THRESHOLD = 75
REDIRECT_STATUS_PERMISSIVE_THRESHOLD = 50
REDIRECT_STATUS_INCONSISTENT_THRESHOLD = 25

# ==========================================
# Cookie Security Domain Rules & Weights
# ==========================================

COOKIE_DEDUCTION_SENSITIVE_MISSING_SECURE = 30     # Sensitive cookie missing Secure attribute
COOKIE_DEDUCTION_NON_SENSITIVE_MISSING_SECURE = 10 # Non-sensitive cookie missing Secure attribute
COOKIE_DEDUCTION_SENSITIVE_MISSING_HTTPONLY = 25   # Sensitive cookie missing HttpOnly attribute
COOKIE_DEDUCTION_MISSING_SAMESITE = 8              # Missing SameSite attribute
COOKIE_DEDUCTION_SAMESITE_NONE_INSECURE = 35       # SameSite=None without Secure attribute (rejected by modern browsers)
COOKIE_DEDUCTION_SECURE_PREFIX_VIOLATION = 25      # __Secure- prefix without Secure attribute
COOKIE_DEDUCTION_HOST_PREFIX_VIOLATION = 30        # __Host- prefix without Secure, Path=/, or with Domain set
COOKIE_DEDUCTION_INCONSISTENT_SECURE = 15          # Inconsistent Secure attribute usage across cookies
COOKIE_DEDUCTION_INCONSISTENT_HTTPONLY = 15        # Inconsistent HttpOnly attribute usage across sensitive cookies
COOKIE_DEDUCTION_INCONSISTENT_SAMESITE = 10        # Inconsistent SameSite policies across cookies

# Cookie Domain Behavior Status Thresholds
COOKIE_STATUS_RESTRICTIVE_THRESHOLD = 90
COOKIE_STATUS_CONSISTENT_THRESHOLD = 75
COOKIE_STATUS_PERMISSIVE_THRESHOLD = 50
COOKIE_STATUS_INCONSISTENT_THRESHOLD = 25

# ==========================================
# CORS Security Domain Rules & Weights
# ==========================================

CORS_DEDUCTION_REFLECTED_ORIGIN = 25              # Reflected requesting origin without credentials
CORS_DEDUCTION_REFLECTED_ORIGIN_CREDENTIALS = 65  # Critical: Reflected requesting origin WITH credentials enabled
CORS_DEDUCTION_NULL_ORIGIN = 20                   # 'null' origin allowed without credentials
CORS_DEDUCTION_NULL_ORIGIN_CREDENTIALS = 50       # High Risk: 'null' origin trusted WITH credentials enabled
CORS_DEDUCTION_WILDCARD = 15                      # Public wildcard Access-Control-Allow-Origin: *
CORS_DEDUCTION_WILDCARD_CREDENTIALS = 40          # Incompatible/Risky: Wildcard origin with credentials
CORS_DEDUCTION_WILDCARD_HEADERS = 5               # Wildcard Access-Control-Allow-Headers: *
CORS_DEDUCTION_EXCESSIVE_MAX_AGE = 5              # Access-Control-Max-Age exceeding 24 hours (86400s)

# CORS Domain Behavior Status Thresholds
CORS_STATUS_RESTRICTIVE_THRESHOLD = 90
CORS_STATUS_CONSISTENT_THRESHOLD = 75
CORS_STATUS_PERMISSIVE_THRESHOLD = 50
CORS_STATUS_INCONSISTENT_THRESHOLD = 25
CORS_STATUS_RISKY_THRESHOLD = 0


# ==============================================================================
# MODULE: utils.py
# ==============================================================================
def normalize_and_validate_url(url: str) -> Tuple[str, str, str, int]:
    if not isinstance(url, str):
        raise ValueError("Target URL must be a string")

    url = url.strip()

    if not url:
        raise ValueError("Target URL cannot be empty")

    if "://" in url:
        candidate_scheme = url.split("://", 1)[0].lower()
        if candidate_scheme not in ("http", "https"):
            raise ValueError("Target URL must use HTTP or HTTPS")
    else:
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
        raise ValueError(f"Invalid URL structure: {url}")

    if parsed.username or parsed.password:
        raise ValueError("Target URL must not contain embedded credentials")

    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Target URL has an invalid port") from exc

    path = parsed.path if parsed.path else "/"

    normalized = f"{scheme}://{host}"

    if (scheme == "http" and port != 80) or (
        scheme == "https" and port != 443
    ):
        normalized += f":{port}"

    normalized += path

    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized, scheme, host, port


def assert_public_target(host: str, port: int) -> None:
    if os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true":
        return

    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror as exc:
        raise ValueError("Target host could not be resolved") from exc

    if not addresses:
        raise ValueError("Target host did not resolve to an address")

    for address in addresses:
        ip = ipaddress.ip_address(address)

        if not ip.is_global:
            raise ValueError(
                "Private, loopback, link-local, multicast, and reserved "
                "targets are not allowed"
            )


def parse_single_set_cookie(cookie_str: str) -> CookieAttribute:
    parts = [p.strip() for p in cookie_str.split(";")]

    if not parts:
        return CookieAttribute(
            name="unknown",
            value_preview="[EMPTY]",
            secure=False,
            httponly=False,
            samesite=None,
            domain=None,
            path=None,
            max_age=None,
            expires=None,
            has_secure_prefix=False,
            has_host_prefix=False,
            is_sensitive=False,
        )

    nv = parts[0].split("=", 1)

    name = nv[0].strip()

    raw_val = nv[1].strip() if len(nv) > 1 else ""

    if len(raw_val) > 14:
        val_preview = raw_val[:6] + "..." + raw_val[-4:]
    elif raw_val:
        val_preview = "[REDACTED]"
    else:
        val_preview = "[EMPTY]"

    secure = False
    httponly = False
    samesite = None
    domain = None
    path = None
    max_age = None
    expires = None

    for attr in parts[1:]:
        attr_lower = attr.lower()

        if attr_lower == "secure":
            secure = True

        elif attr_lower == "httponly":
            httponly = True

        elif attr_lower.startswith("samesite="):
            ss_val = attr.split("=", 1)[1].strip()

            if ss_val.lower() == "strict":
                samesite = "Strict"
            elif ss_val.lower() == "lax":
                samesite = "Lax"
            elif ss_val.lower() == "none":
                samesite = "None"
            else:
                samesite = ss_val

        elif attr_lower.startswith("domain="):
            domain = attr.split("=", 1)[1].strip()

        elif attr_lower.startswith("path="):
            path = attr.split("=", 1)[1].strip()

        elif attr_lower.startswith("max-age="):
            try:
                max_age = int(attr.split("=", 1)[1].strip())
            except ValueError:
                max_age = None

        elif attr_lower.startswith("expires="):
            expires = attr.split("=", 1)[1].strip()

    name_lower = name.lower()

    has_secure_prefix = name.startswith("__Secure-")
    has_host_prefix = name.startswith("__Host-")

    is_sensitive = any(
        pattern.lower() in name_lower
        for pattern in SENSITIVE_COOKIE_PATTERNS
    )

    return CookieAttribute(
        name=name,
        value_preview=val_preview,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        domain=domain,
        path=path,
        max_age=max_age,
        expires=expires,
        has_secure_prefix=has_secure_prefix,
        has_host_prefix=has_host_prefix,
        is_sensitive=is_sensitive,
    )


class SafeNoRedirectHandler(urllib.request.HTTPRedirectHandler):

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    def http_error_303(self, req, fp, code, msg, headers):
        return fp

    def http_error_307(self, req, fp, code, msg, headers):
        return fp

    def http_error_308(self, req, fp, code, msg, headers):
        return fp


class SafeHttpProbe:

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "Reconix-SecurityBehaviorProfiler/1.0 "
        "(Academic Passive Assessment)"
    )

    def __init__(
        self,
        timeout: float = 6.0,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
    ):
        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT

        if self.verify_ssl:
            self.ssl_context = ssl.create_default_context()
        else:
            self.ssl_context = ssl._create_unverified_context()

    def send_single_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = False,
    ) -> Dict[str, Any]:

        _, _, host, port = normalize_and_validate_url(url)

        assert_public_target(host, port)

        req_headers = {
            "User-Agent": self.user_agent,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
        }

        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(
            url,
            headers=req_headers,
            method=method,
        )

        handlers = [
            urllib.request.HTTPSHandler(
                context=self.ssl_context
            )
        ]

        if not follow_redirects:
            handlers.append(SafeNoRedirectHandler())

        opener = urllib.request.build_opener(*handlers)

        start_time = time.perf_counter()

        try:
            with opener.open(req, timeout=self.timeout) as response:

                latency_ms = (
                    time.perf_counter() - start_time
                ) * 1000.0

                status_code = getattr(
                    response,
                    "status",
                    getattr(response, "code", 200),
                )

                resp_headers = {
                    k.lower(): v
                    for k, v in response.headers.items()
                }

                raw_cookies = []

                if hasattr(response.headers, "get_all"):
                    raw_cookies = (
                        response.headers.get_all("Set-Cookie")
                        or []
                    )

                if not raw_cookies and "set-cookie" in resp_headers:
                    raw_cookies = [
                        resp_headers["set-cookie"]
                    ]

                try:
                    body_preview = (
                        response.read(4096)
                        .decode("utf-8", errors="ignore")
                    )
                except Exception:
                    body_preview = ""

                return {
                    "success": True,
                    "url": url,
                    "status_code": status_code,
                    "headers": resp_headers,
                    "raw_cookies": raw_cookies,
                    "body_preview": body_preview,
                    "latency_ms": latency_ms,
                    "error": None,
                }

        except urllib.error.HTTPError as e:

            latency_ms = (
                time.perf_counter() - start_time
            ) * 1000.0

            resp_headers = {}

            if hasattr(e, "headers") and e.headers:
                resp_headers = {
                    k.lower(): v
                    for k, v in e.headers.items()
                }

            raw_cookies = []

            if (
                hasattr(e, "headers")
                and hasattr(e.headers, "get_all")
            ):
                raw_cookies = (
                    e.headers.get_all("Set-Cookie")
                    or []
                )

            if not raw_cookies and "set-cookie" in resp_headers:
                raw_cookies = [
                    resp_headers["set-cookie"]
                ]

            return {
                "success": True,
                "url": url,
                "status_code": e.code,
                "headers": resp_headers,
                "raw_cookies": raw_cookies,
                "body_preview": "",
                "latency_ms": latency_ms,
                "error": None,
            }

        except Exception as ex:

            latency_ms = (
                time.perf_counter() - start_time
            ) * 1000.0

            return {
                "success": False,
                "url": url,
                "status_code": 0,
                "headers": {},
                "raw_cookies": [],
                "body_preview": "",
                "latency_ms": latency_ms,
                "error": str(ex),
            }

    def trace_redirect_chain(
        self,
        start_url: str,
        max_hops: int = 8,
    ) -> Tuple[
        List[RedirectStep],
        Optional[Dict[str, Any]]
    ]:

        chain = []
        current_url = start_url
        visited_urls = set()
        last_response = None

        for hop_index in range(1, max_hops + 1):

            if current_url in visited_urls:
                chain.append(
                    RedirectStep(
                        step=hop_index,
                        status_code=310,
                        source_url=current_url,
                        destination_url=(
                            "[CIRCULAR_REDIRECT_LOOP_DETECTED]"
                        ),
                        protocol_change="NONE",
                        host_change=False,
                    )
                )
                break

            visited_urls.add(current_url)

            resp = self.send_single_request(
                current_url,
                method="GET",
                follow_redirects=False,
            )

            last_response = resp

            if not resp["success"]:
                break

            status = resp["status_code"]
            headers = resp["headers"]
            location = headers.get("location")

            if status in (301, 302, 303, 307, 308) and location:

                next_url = urllib.parse.urljoin(
                    current_url,
                    location,
                )

                normalize_and_validate_url(next_url)

                curr_parsed = urllib.parse.urlparse(
                    current_url
                )

                next_parsed = urllib.parse.urlparse(
                    next_url
                )

                curr_scheme = curr_parsed.scheme.lower()
                next_scheme = next_parsed.scheme.lower()

                if (
                    curr_scheme == "http"
                    and next_scheme == "https"
                ):
                    protocol_change = "UPGRADE_TO_HTTPS"

                elif (
                    curr_scheme == "https"
                    and next_scheme == "http"
                ):
                    protocol_change = "DOWNGRADE_TO_HTTP"

                else:
                    protocol_change = "NONE"

                host_change = (
                    curr_parsed.hostname
                    != next_parsed.hostname
                )

                chain.append(
                    RedirectStep(
                        step=hop_index,
                        status_code=status,
                        source_url=current_url,
                        destination_url=next_url,
                        protocol_change=protocol_change,
                        host_change=host_change,
                        latency_ms=round(
                            resp["latency_ms"],
                            2,
                        ),
                    )
                )

                current_url = next_url

            else:

                chain.append(
                    RedirectStep(
                        step=hop_index,
                        status_code=status,
                        source_url=current_url,
                        destination_url=current_url,
                        protocol_change="NONE",
                        host_change=False,
                        latency_ms=round(
                            resp["latency_ms"],
                            2,
                        ),
                    )
                )

                break

        return chain, last_response


# ==============================================================================
# MODULE: collector.py
# ==============================================================================
@dataclass
class RedirectHopObservation:
    hop_index: int
    status_code: int
    source_url: str
    destination_url: str
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CookieObservation:
    name: str
    secure: bool
    httponly: bool
    samesite: Optional[str]
    domain: Optional[str]
    path: Optional[str]
    expires: Optional[str]
    max_age: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BasicHttpObservation:
    target_url: str
    final_url: str
    request_method: str
    status_code: int
    http_version: str
    response_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RedirectChainObservation:
    redirect_count: int
    final_destination: str
    hops: List[RedirectHopObservation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "redirect_count": self.redirect_count,
            "final_destination": self.final_destination,
            "hops": [h.to_dict() for h in self.hops],
        }


@dataclass
class TransportObservation:
    initial_scheme: str
    final_scheme: str
    is_https: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorsObservation:
    access_control_allow_origin: Optional[str]
    access_control_allow_credentials: Optional[str]
    access_control_allow_methods: Optional[str]
    access_control_allow_headers: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServerObservation:
    server: Optional[str]
    x_powered_by: Optional[str]
    via: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HttpMethodObservation:
    options_status_code: Optional[int]
    allow_header: Optional[str]
    advertised_methods: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimingObservation:
    response_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RawObservations:
    basic_http: BasicHttpObservation
    redirect_chain: RedirectChainObservation
    transport: TransportObservation
    response_headers: Dict[str, str]
    cookies: List[CookieObservation]
    cors: CorsObservation
    server: ServerObservation
    http_methods: HttpMethodObservation
    timing: TimingObservation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "basic_http": self.basic_http.to_dict(),
            "redirect_chain": self.redirect_chain.to_dict(),
            "transport": self.transport.to_dict(),
            "response_headers": dict(self.response_headers),
            "cookies": [c.to_dict() for c in self.cookies],
            "cors": self.cors.to_dict(),
            "server": self.server.to_dict(),
            "http_methods": self.http_methods.to_dict(),
            "timing": self.timing.to_dict(),
        }


def validate_and_normalize_target_url(
    url: str,
) -> Tuple[str, str, str, int]:

    if not isinstance(url, str):
        raise ValueError("Target URL must be a string")

    cleaned_url = url.strip()

    if not cleaned_url:
        raise ValueError("Target URL cannot be empty")

    if "://" in cleaned_url:
        scheme_candidate = cleaned_url.split(
            "://",
            1,
        )[0].lower()

        if scheme_candidate not in ("http", "https"):
            raise ValueError(
                f"Unsupported URL scheme '{scheme_candidate}'. "
                "Must be http or https."
            )
    else:
        cleaned_url = "https://" + cleaned_url

    parsed = urllib.parse.urlparse(cleaned_url)

    if not parsed.netloc:
        raise ValueError(
            f"Invalid URL structure: {url}"
        )

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme '{scheme}'. "
            "Must be http or https."
        )

    host = parsed.hostname.lower() if parsed.hostname else ""

    if not host:
        raise ValueError(
            f"Target URL must include a valid host: {url}"
        )

    port = parsed.port or (
        443 if scheme == "https" else 80
    )

    path = parsed.path if parsed.path else "/"

    normalized = f"{scheme}://{host}"

    if (
        scheme == "http"
        and port != 80
    ) or (
        scheme == "https"
        and port != 443
    ):
        normalized += f":{port}"

    normalized += path

    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized, scheme, host, port


def parse_cookie_header(
    cookie_header_str: str,
) -> CookieObservation:

    parts = [
        p.strip()
        for p in cookie_header_str.split(";")
    ]

    if not parts:
        return CookieObservation(
            name="",
            secure=False,
            httponly=False,
            samesite=None,
            domain=None,
            path=None,
            expires=None,
            max_age=None,
        )

    first_part = parts[0]

    name = (
        first_part.split("=", 1)[0].strip()
        if "=" in first_part
        else first_part.strip()
    )

    secure = False
    httponly = False
    samesite = None
    domain = None
    path = None
    expires = None
    max_age = None

    for attr in parts[1:]:

        attr_lower = attr.lower()

        if attr_lower == "secure":
            secure = True

        elif attr_lower == "httponly":
            httponly = True

        elif attr_lower.startswith("samesite="):

            samesite_raw = attr.split(
                "=",
                1,
            )[1].strip()

            samesite_lower = samesite_raw.lower()

            if samesite_lower == "strict":
                samesite = "Strict"

            elif samesite_lower == "lax":
                samesite = "Lax"

            elif samesite_lower == "none":
                samesite = "None"

            else:
                samesite = samesite_raw

        elif attr_lower.startswith("domain="):

            domain = attr.split(
                "=",
                1,
            )[1].strip()

        elif attr_lower.startswith("path="):

            path = attr.split(
                "=",
                1,
            )[1].strip()

        elif attr_lower.startswith("expires="):

            expires = attr.split(
                "=",
                1,
            )[1].strip()

        elif attr_lower.startswith("max-age="):

            try:
                max_age = int(
                    attr.split(
                        "=",
                        1,
                    )[1].strip()
                )
            except ValueError:
                max_age = None

    return CookieObservation(
        name=name,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        domain=domain,
        path=path,
        expires=expires,
        max_age=max_age,
    )


class _NoRedirectHandler(
    urllib.request.HTTPRedirectHandler
):

    def http_error_301(
        self,
        req,
        fp,
        code,
        msg,
        headers,
    ):
        return fp

    def http_error_302(
        self,
        req,
        fp,
        code,
        msg,
        headers,
    ):
        return fp

    def http_error_303(
        self,
        req,
        fp,
        code,
        msg,
        headers,
    ):
        return fp

    def http_error_307(
        self,
        req,
        fp,
        code,
        msg,
        headers,
    ):
        return fp

    def http_error_308(
        self,
        req,
        fp,
        code,
        msg,
        headers,
    ):
        return fp


class DataCollector:

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "Reconix-SecurityBehaviorCollector/1.0 "
        "(Safe Observation Collector)"
    )

    def __init__(
        self,
        timeout: float = 6.0,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
        max_redirect_hops: int = 8,
    ):

        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.user_agent = (
            user_agent or self.DEFAULT_USER_AGENT
        )
        self.max_redirect_hops = max(
            1,
            int(max_redirect_hops),
        )

        if self.verify_ssl:
            self.ssl_context = (
                ssl.create_default_context()
            )
        else:
            self.ssl_context = (
                ssl._create_unverified_context()
            )

    def _execute_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:

        _, _, host, port = (
            validate_and_normalize_target_url(url)
        )

        assert_public_target(
            host,
            port,
        )

        req_headers = {
            "User-Agent": self.user_agent,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
        }

        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(
            url,
            headers=req_headers,
            method=method,
        )

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(
                context=self.ssl_context
            ),
            _NoRedirectHandler(),
        )

        start_time = time.perf_counter()
        http_version = "HTTP/1.1"

        try:

            with opener.open(
                req,
                timeout=self.timeout,
            ) as response:

                latency_ms = (
                    time.perf_counter()
                    - start_time
                ) * 1000.0

                status_code = getattr(
                    response,
                    "status",
                    getattr(
                        response,
                        "code",
                        200,
                    ),
                )

                resp_headers: Dict[str, str] = {}

                for k, v in response.headers.items():
                    resp_headers[k.lower()] = v

                raw_cookies: List[str] = []

                if hasattr(
                    response.headers,
                    "get_all",
                ):

                    raw_cookies = (
                        response.headers.get_all(
                            "Set-Cookie"
                        )
                        or []
                    )

                elif "set-cookie" in resp_headers:

                    raw_cookies = [
                        resp_headers["set-cookie"]
                    ]

                if hasattr(
                    response,
                    "version",
                ):

                    version_num = getattr(
                        response,
                        "version",
                    )

                    if version_num == 10:
                        http_version = "HTTP/1.0"

                    elif version_num == 11:
                        http_version = "HTTP/1.1"

                    elif version_num == 20:
                        http_version = "HTTP/2"

                return {
                    "success": True,
                    "url": url,
                    "status_code": status_code,
                    "headers": resp_headers,
                    "raw_cookies": raw_cookies,
                    "http_version": http_version,
                    "latency_ms": latency_ms,
                    "error": None,
                }

        except urllib.error.HTTPError as e:

            latency_ms = (
                time.perf_counter()
                - start_time
            ) * 1000.0

            resp_headers = {}

            if (
                hasattr(e, "headers")
                and e.headers
            ):

                for k, v in e.headers.items():
                    resp_headers[k.lower()] = v

            raw_cookies = []

            if (
                hasattr(e, "headers")
                and hasattr(
                    e.headers,
                    "get_all",
                )
            ):

                raw_cookies = (
                    e.headers.get_all(
                        "Set-Cookie"
                    )
                    or []
                )

            elif "set-cookie" in resp_headers:

                raw_cookies = [
                    resp_headers["set-cookie"]
                ]

            return {
                "success": True,
                "url": url,
                "status_code": e.code,
                "headers": resp_headers,
                "raw_cookies": raw_cookies,
                "http_version": http_version,
                "latency_ms": latency_ms,
                "error": None,
            }

        except Exception as ex:

            latency_ms = (
                time.perf_counter()
                - start_time
            ) * 1000.0

            return {
                "success": False,
                "url": url,
                "status_code": 0,
                "headers": {},
                "raw_cookies": [],
                "http_version": http_version,
                "latency_ms": latency_ms,
                "error": str(ex),
            }

    def collect(
        self,
        target_url: str,
        inspect_options: bool = True,
    ) -> RawObservations:

        (
            normalized_url,
            initial_scheme,
            _,
            _,
        ) = validate_and_normalize_target_url(
            target_url
        )

        hops: List[
            RedirectHopObservation
        ] = []

        current_url = normalized_url
        visited_urls = set()
        last_resp = None
        total_latency_ms = 0.0

        for hop_idx in range(
            1,
            self.max_redirect_hops + 1,
        ):

            if current_url in visited_urls:
                break

            visited_urls.add(current_url)

            resp = self._execute_request(
                current_url,
                method="GET",
            )

            last_resp = resp

            total_latency_ms += (
                resp["latency_ms"]
            )

            if not resp["success"]:

                hops.append(
                    RedirectHopObservation(
                        hop_index=hop_idx,
                        status_code=resp[
                            "status_code"
                        ],
                        source_url=current_url,
                        destination_url=current_url,
                        latency_ms=round(
                            resp["latency_ms"],
                            2,
                        ),
                    )
                )

                break

            status = resp["status_code"]

            location = resp[
                "headers"
            ].get("location")

            if (
                status
                in (
                    301,
                    302,
                    303,
                    307,
                    308,
                )
                and location
            ):

                next_url = urllib.parse.urljoin(
                    current_url,
                    location,
                )

                validate_and_normalize_target_url(
                    next_url
                )

                hops.append(
                    RedirectHopObservation(
                        hop_index=hop_idx,
                        status_code=status,
                        source_url=current_url,
                        destination_url=next_url,
                        latency_ms=round(
                            resp["latency_ms"],
                            2,
                        ),
                    )
                )

                current_url = next_url

            else:

                hops.append(
                    RedirectHopObservation(
                        hop_index=hop_idx,
                        status_code=status,
                        source_url=current_url,
                        destination_url=current_url,
                        latency_ms=round(
                            resp["latency_ms"],
                            2,
                        ),
                    )
                )

                break

        final_url = current_url

        final_scheme = (
            urllib.parse.urlparse(
                final_url
            ).scheme.lower()
            or initial_scheme
        )

        is_https = (
            final_scheme == "https"
        )

        headers = (
            last_resp.get(
                "headers",
                {},
            )
            if last_resp
            else {}
        )

        status_code = (
            last_resp.get(
                "status_code",
                0,
            )
            if last_resp
            else 0
        )

        http_version = (
            last_resp.get(
                "http_version",
                "HTTP/1.1",
            )
            if last_resp
            else "HTTP/1.1"
        )

        raw_cookie_headers = (
            last_resp.get(
                "raw_cookies",
                [],
            )
            if last_resp
            else []
        )

        parsed_cookies: List[
            CookieObservation
        ] = []

        for cookie_str in raw_cookie_headers:

            if cookie_str:
                parsed_cookies.append(
                    parse_cookie_header(
                        cookie_str
                    )
                )

        cors_obs = CorsObservation(
            access_control_allow_origin=headers.get(
                "access-control-allow-origin"
            ),
            access_control_allow_credentials=headers.get(
                "access-control-allow-credentials"
            ),
            access_control_allow_methods=headers.get(
                "access-control-allow-methods"
            ),
            access_control_allow_headers=headers.get(
                "access-control-allow-headers"
            ),
        )

        server_obs = ServerObservation(
            server=headers.get("server"),
            x_powered_by=headers.get(
                "x-powered-by"
            ),
            via=headers.get("via"),
        )

        options_status_code = None
        allow_header = None
        advertised_methods: List[str] = []

        if inspect_options:

            options_resp = self._execute_request(
                final_url,
                method="OPTIONS",
            )

            if options_resp.get("success"):

                options_status_code = (
                    options_resp.get(
                        "status_code"
                    )
                )

                allow_header = (
                    options_resp.get(
                        "headers",
                        {},
                    ).get("allow")
                )

                if allow_header:

                    advertised_methods = [
                        m.strip().upper()
                        for m in allow_header.split(",")
                        if m.strip()
                    ]

        method_obs = HttpMethodObservation(
            options_status_code=options_status_code,
            allow_header=allow_header,
            advertised_methods=advertised_methods,
        )

        redirect_count = (
            max(
                0,
                len(hops) - 1,
            )
            if hops
            else 0
        )

        redirect_chain_obs = (
            RedirectChainObservation(
                redirect_count=redirect_count,
                final_destination=final_url,
                hops=hops,
            )
        )

        basic_http_obs = BasicHttpObservation(
            target_url=target_url,
            final_url=final_url,
            request_method="GET",
            status_code=status_code,
            http_version=http_version,
            response_time_ms=round(
                total_latency_ms,
                2,
            ),
        )

        transport_obs = TransportObservation(
            initial_scheme=initial_scheme,
            final_scheme=final_scheme,
            is_https=is_https,
        )

        timing_obs = TimingObservation(
            response_time_ms=round(
                total_latency_ms,
                2,
            )
        )

        return RawObservations(
            basic_http=basic_http_obs,
            redirect_chain=redirect_chain_obs,
            transport=transport_obs,
            response_headers=headers,
            cookies=parsed_cookies,
            cors=cors_obs,
            server=server_obs,
            http_methods=method_obs,
            timing=timing_obs,
        )


def collect_observations(
    target_url: str,
    timeout: float = 6.0,
    verify_ssl: bool = True,
    user_agent: Optional[str] = None,
    inspect_options: bool = True,
) -> Dict[str, Any]:

    collector = DataCollector(
        timeout=timeout,
        verify_ssl=verify_ssl,
        user_agent=user_agent,
    )

    observations = collector.collect(
        target_url,
        inspect_options=inspect_options,
    )

    return observations.to_dict()


# ==============================================================================
# MODULE: transport_analyzer.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Transport Security Analyzer
Analyzes HTTP/HTTPS availability, transport upgrades, HSTS policies, and transport boundary consistency.
Refactored to consume typed RawObservations with centralized rules and dynamic confidence scoring.
"""




class TransportAnalyzer:
    """
    Evaluates observable transport layer behavior:
    1. Core Transport Security: TLS/HTTPS availability, cleartext enforcement, redirect target schemes.
    2. Transport Hardening: HSTS header presence, max-age policy duration, subdomains, and preload.
    """

    def __init__(self):
        pass

    def _calculate_dynamic_confidence(
        self,
        has_http_probe: bool,
        has_https_probe: bool,
        has_route_evidence: bool,
        has_status_code: bool,
        has_headers: bool,
    ) -> Tuple[int, str]:
        """
        Calculates factual observation confidence (0 - 100) based on telemetry completeness.
        Considers HTTP probe, HTTPS probe, route evidence (direct/redirect), status codes, and headers.
        """
        score = 0
        reasons = []

        if has_https_probe:
            score += 30
            reasons.append("HTTPS endpoint probed")
        else:
            reasons.append("HTTPS probe missing")

        if has_http_probe:
            score += 25
            reasons.append("HTTP endpoint probed")
        else:
            reasons.append("HTTP probe missing")

        if has_route_evidence:
            score += 20
            reasons.append("cleartext route behavior verified")

        if has_status_code:
            score += 15
            reasons.append("status codes verified")

        if has_headers:
            score += 10
            reasons.append("response headers parsed")

        confidence_level = "High" if score >= 85 else ("Medium" if score >= 60 else "Low")
        reason_text = f"{confidence_level} confidence ({score}%): {', '.join(reasons)}."
        return score, reason_text

    def analyze_raw(
        self,
        raw_obs: RawObservations,
    ) -> Tuple[TransportProfile, List[EvidenceObservation]]:
        """
        Analyzes a structured RawObservations instance from Phase 1 DataCollector.
        """
        target_url = raw_obs.basic_http.target_url
        parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"https://{target_url}")
        target_host = parsed.hostname or target_url

        # Synthesize normalized probe models from raw observations
        final_url = raw_obs.basic_http.final_url
        is_https_final = raw_obs.transport.is_https
        status_code = raw_obs.basic_http.status_code

        # Evaluate redirect chain
        hops = raw_obs.redirect_chain.hops
        first_hop = hops[0] if hops else None
        
        http_probe: Optional[Dict[str, Any]] = None
        https_probe: Optional[Dict[str, Any]] = None

        if raw_obs.transport.initial_scheme == "http":
            if hops:
                http_probe = {
                    "success": True,
                    "status_code": first_hop.status_code if first_hop else status_code,
                    "headers": raw_obs.response_headers if len(hops) == 1 else {"location": first_hop.destination_url if first_hop else ""},
                }
            else:
                http_probe = {
                    "success": True,
                    "status_code": status_code,
                    "headers": raw_obs.response_headers,
                }
        else:
            # Initial scheme was HTTPS
            https_probe = {
                "success": True,
                "status_code": status_code,
                "headers": raw_obs.response_headers,
            }

        if is_https_final:
            https_probe = {
                "success": True,
                "status_code": status_code,
                "headers": raw_obs.response_headers,
            }

        return self.analyze_probes(
            target_host=target_host,
            http_probe=http_probe,
            https_probe=https_probe,
            normalized_headers=raw_obs.response_headers,
        )

    def analyze_probes(
        self,
        target_host: str,
        http_probe: Optional[Dict[str, Any]],
        https_probe: Optional[Dict[str, Any]],
        normalized_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[TransportProfile, List[EvidenceObservation]]:
        """
        Core algorithmic evaluation of transport security.
        Separates Core Transport Security (HTTPS, redirect enforcement) from Hardening (HSTS).
        """
        findings: List[str] = []
        observations: List[EvidenceObservation] = []
        core_deductions = 0
        hardening_deductions = 0

        http_ok = http_probe is not None and http_probe.get("success", False)
        https_ok = https_probe is not None and https_probe.get("success", False)
        
        http_status = http_probe.get("status_code", 0) if http_probe else 0
        https_status = https_probe.get("status_code", 0) if https_probe else 0

        http_headers = http_probe.get("headers", {}) if http_probe else {}
        https_headers = https_probe.get("headers", {}) if https_probe else {}
        
        # Calculate dynamic confidence
        confidence_val, confidence_reason = self._calculate_dynamic_confidence(
            has_http_probe=http_probe is not None,
            has_https_probe=https_probe is not None,
            has_route_evidence=http_status in (200, 301, 302, 303, 307, 308) or (http_probe is not None and not http_ok),
            has_status_code=(http_status > 0 or https_status > 0),
            has_headers=bool(http_headers or https_headers or normalized_headers),
        )

        # -------------------------------------------------------------
        # 1. HSTS Header Directive Parsing
        # -------------------------------------------------------------
        hsts_val = https_headers.get("strict-transport-security", "")
        if not hsts_val and normalized_headers:
            hsts_val = normalized_headers.get("strict-transport-security", "")

        hsts_present = bool(hsts_val)
        hsts_max_age: Optional[int] = None
        hsts_include_subdomains = False
        hsts_preload = False

        if hsts_present:
            hsts_lower = hsts_val.lower()
            if "includesubdomains" in hsts_lower:
                hsts_include_subdomains = True
            if "preload" in hsts_lower:
                hsts_preload = True
            
            for part in hsts_lower.split(";"):
                part = part.strip()
                if part.startswith("max-age="):
                    try:
                        hsts_max_age = int(part.split("=")[1].strip())
                    except ValueError:
                        pass

        # -------------------------------------------------------------
        # 2. Core Transport Security: Cleartext HTTP Handling
        # -------------------------------------------------------------
        enforces_https = False
        http_redirect_code = None

        if http_ok:
            if http_status in (301, 308):
                loc = http_headers.get("location", "")
                if loc.lower().startswith("https://"):
                    enforces_https = True
                    http_redirect_code = http_status
                    findings.append(f"HTTP permanently upgrades to HTTPS via canonical HTTP {http_status}.")
                else:
                    findings.append(f"HTTP redirects ({http_status}) but target location is not HTTPS: {loc}")
                    core_deductions += TRANSPORT_DEDUCTION_REDIRECT_NOT_HTTPS
                    observations.append(
                        EvidenceObservation(
                            title="HTTP Redirect Does Not Target HTTPS",
                            category="Transport Security",
                            severity=Severity.HIGH,
                            confidence=confidence_val,
                            observation="Cleartext HTTP endpoint responds with a redirect, but the Location header does not enforce HTTPS.",
                            evidence=[
                                f"http_status: {http_status}",
                                f"location: {loc or '[MISSING]'}",
                                f"target_host: {target_host}",
                            ],
                            impact="User sessions and initial requests remain vulnerable to active Man-in-the-Middle (MitM) wiretapping.",
                            recommendation="Configure the web server to immediately redirect all cleartext HTTP requests to HTTPS using 301 Moved Permanently.",
                        )
                    )
            elif http_status in (302, 303, 307):
                loc = http_headers.get("location", "")
                http_redirect_code = http_status
                if loc.lower().startswith("https://"):
                    enforces_https = True
                    core_deductions += TRANSPORT_DEDUCTION_TEMPORARY_REDIRECT
                    findings.append(f"HTTP temporarily upgrades to HTTPS via HTTP {http_status} (permanent 301/308 preferred).")
                    observations.append(
                        EvidenceObservation(
                            title="Temporary HTTP to HTTPS Redirection",
                            category="Transport Security",
                            severity=Severity.LOW,
                            confidence=confidence_val,
                            observation=f"HTTP endpoint uses temporary redirect ({http_status}) rather than permanent redirect (301/308) to upgrade to HTTPS.",
                            evidence=[
                                f"http_status: {http_status}",
                                f"location: {loc}",
                                f"upgrade_type: temporary",
                            ],
                            impact="Browsers may not cache the HTTPS upgrade directive, causing repeated insecure cleartext roundtrips.",
                            recommendation="Change HTTP redirection status to 301 Moved Permanently or 308 Permanent Redirect.",
                        )
                    )
                else:
                    core_deductions += TRANSPORT_DEDUCTION_REDIRECT_NOT_HTTPS + TRANSPORT_DEDUCTION_TEMPORARY_REDIRECT
                    findings.append(f"HTTP temporarily redirects to non-HTTPS target: {loc}")
            elif http_status == 200:
                # Direct content served on cleartext HTTP without upgrading
                enforces_https = False
                core_deductions += TRANSPORT_DEDUCTION_CLEARTEXT_SERVED
                findings.append("HTTP serves direct content (HTTP 200) without redirecting to HTTPS.")
                observations.append(
                    EvidenceObservation(
                        title="Cleartext HTTP Accessible Without HTTPS Enforcement",
                        category="Transport Security",
                        severity=Severity.HIGH,
                        confidence=confidence_val,
                        observation="The web application accepts unencrypted HTTP connections and serves direct 200 OK responses instead of forcing an HTTPS upgrade.",
                        evidence=[
                            f"target_url: http://{target_host}",
                            "http_status: 200",
                            f"redirect_code: None",
                            f"https_available: {https_ok}",
                            f"initial_scheme: http",
                            f"final_scheme: http",
                        ],
                        impact="Users accessing the site without explicitly typing 'https://' will transmit authentication cookies, credentials, and data in cleartext.",
                        recommendation="Enforce a strict server-level rewrite rule redirecting all port 80 / HTTP traffic to HTTPS.",
                    )
                )
            else:
                findings.append(f"HTTP returned status code {http_status}.")
        else:
            findings.append("HTTP cleartext port is unreachable or closed.")

        # -------------------------------------------------------------
        # 3. HTTPS Availability & Transport Hardening
        # -------------------------------------------------------------
        if https_ok:
            findings.append(f"HTTPS service is active (Status: {https_status}).")
            
            # Transport Hardening Evaluation
            if hsts_present:
                findings.append(f"HSTS is enabled with max-age={hsts_max_age or 'unknown'}.")
                if hsts_max_age is not None and hsts_max_age < HSTS_STRONG_RECOMMENDED_MAX_AGE:
                    hardening_deductions += TRANSPORT_DEDUCTION_SHORT_HSTS
                    findings.append(f"HSTS max-age ({hsts_max_age}s) is below recommended 1 year ({HSTS_STRONG_RECOMMENDED_MAX_AGE}s).")
                    observations.append(
                        EvidenceObservation(
                            title="Short HSTS Policy Duration",
                            category="Transport Security",
                            severity=Severity.LOW,
                            confidence=confidence_val,
                            observation=f"Strict-Transport-Security header specifies max-age={hsts_max_age}, which is shorter than the 1-year industry baseline.",
                            evidence=[
                                f"hsts_header: {hsts_val}",
                                f"max_age_seconds: {hsts_max_age}",
                                f"recommended_minimum: {HSTS_STRONG_RECOMMENDED_MAX_AGE}",
                            ],
                            impact="Clients will revert to insecure HTTP sooner if not regularly visiting the domain.",
                            recommendation="Increase HSTS max-age to at least 31536000 (1 year) and consider adding includeSubDomains and preload.",
                        )
                    )
                elif hsts_max_age is not None and hsts_max_age >= HSTS_STRONG_RECOMMENDED_MAX_AGE:
                    findings.append("HSTS policy duration meets industry best practices (>= 1 year).")

                if not hsts_include_subdomains:
                    hardening_deductions += TRANSPORT_DEDUCTION_NO_SUBDOMAINS
                    findings.append("HSTS does not include 'includeSubDomains' directive.")
            else:
                # Missing HSTS is a hardening gap (MEDIUM severity, not critical on its own if HTTPS works)
                hardening_deductions += TRANSPORT_DEDUCTION_MISSING_HSTS
                findings.append("Strict-Transport-Security (HSTS) header is missing on HTTPS response.")
                observations.append(
                    EvidenceObservation(
                        title="Missing Strict-Transport-Security (HSTS) Header",
                        category="Transport Security",
                        severity=Severity.MEDIUM,
                        confidence=confidence_val,
                        observation="HTTPS endpoint does not advertise a Strict-Transport-Security header to mandate secure browser connections.",
                        evidence=[
                            f"target_url: https://{target_host}",
                            "hsts_header_present: False",
                        ],
                        impact="Vulnerable to SSL stripping attacks on initial user connections or untrusted Wi-Fi networks.",
                        recommendation="Add header 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on all HTTPS responses.",
                    )
                )
        else:
            core_deductions += TRANSPORT_DEDUCTION_NO_HTTPS
            findings.append("HTTPS endpoint is unreachable or failed SSL handshake.")
            observations.append(
                EvidenceObservation(
                    title="HTTPS Transport Unavailable or Misconfigured",
                    category="Transport Security",
                    severity=Severity.CRITICAL,
                    confidence=confidence_val,
                    observation="Failed to establish secure TLS/HTTPS connection to the target host.",
                    evidence=[
                        f"target_url: https://{target_host}",
                        f"error: {https_probe.get('error') if https_probe else 'Unreachable'}",
                    ],
                    impact="All traffic over the wire is susceptible to passive interception and manipulation.",
                    recommendation="Deploy a valid TLS certificate and configure web server to listen on port 443 with modern cipher suites.",
                )
            )

        # -------------------------------------------------------------
        # 4. Structured Behavioral Classifications (Separated from Score)
        # -------------------------------------------------------------
        # Cleartext Exposure
        if http_probe is None:
            cleartext_behavior = CleartextExposureBehavior.UNKNOWN
        elif not http_ok:
            cleartext_behavior = CleartextExposureBehavior.RESTRICTED
        elif http_status in (301, 302, 303, 307, 308):
            cleartext_behavior = CleartextExposureBehavior.REDIRECTED
        elif http_status == 200:
            cleartext_behavior = CleartextExposureBehavior.DIRECT
        else:
            cleartext_behavior = CleartextExposureBehavior.UNKNOWN

        # Redirect Policy
        if http_probe is None or not http_ok:
            redirect_policy = RedirectPolicyBehavior.NONE if (http_probe is not None and not http_ok) else RedirectPolicyBehavior.UNKNOWN
        elif http_status in (301, 308):
            loc = http_headers.get("location", "")
            redirect_policy = RedirectPolicyBehavior.CANONICAL if loc.lower().startswith("https://") else RedirectPolicyBehavior.NON_HTTPS
        elif http_status in (302, 303, 307):
            loc = http_headers.get("location", "")
            redirect_policy = RedirectPolicyBehavior.TEMPORARY if loc.lower().startswith("https://") else RedirectPolicyBehavior.NON_HTTPS
        elif http_status == 200:
            redirect_policy = RedirectPolicyBehavior.NONE
        else:
            redirect_policy = RedirectPolicyBehavior.UNKNOWN

        # HSTS Policy
        if https_probe is None or not https_ok:
            hsts_policy = HstsPolicyBehavior.UNKNOWN
        elif not hsts_present:
            hsts_policy = HstsPolicyBehavior.MISSING
        elif hsts_max_age is not None and hsts_max_age >= HSTS_STRONG_RECOMMENDED_MAX_AGE and hsts_include_subdomains:
            hsts_policy = HstsPolicyBehavior.STRONG
        else:
            hsts_policy = HstsPolicyBehavior.BASIC

        # HTTPS Enforcement
        if https_probe is None or not https_ok:
            https_enforcement = HttpsEnforcementBehavior.UNKNOWN if https_probe is None else HttpsEnforcementBehavior.WEAK
        elif enforces_https and hsts_policy == HstsPolicyBehavior.STRONG:
            https_enforcement = HttpsEnforcementBehavior.STRONG
        elif enforces_https or (not http_ok and https_ok):
            https_enforcement = HttpsEnforcementBehavior.PARTIAL
        else:
            https_enforcement = HttpsEnforcementBehavior.WEAK

        # Protocol Consistency
        if http_probe is None or https_probe is None:
            protocol_consistency = ProtocolConsistencyBehavior.UNKNOWN
        elif (not http_ok or enforces_https) and https_ok:
            protocol_consistency = ProtocolConsistencyBehavior.CONSISTENT
        elif http_ok and https_ok and not enforces_https:
            # Both serve content without mutual upgrade policy
            protocol_consistency = ProtocolConsistencyBehavior.INCONSISTENT
        else:
            protocol_consistency = ProtocolConsistencyBehavior.UNKNOWN

        transport_behavior = TransportBehavior(
            https_enforcement=https_enforcement,
            cleartext_exposure=cleartext_behavior,
            redirect_policy=redirect_policy,
            hsts_policy=hsts_policy,
            protocol_consistency=protocol_consistency,
        )

        # -------------------------------------------------------------
        # 5. Final Score & Behavior Status Mapping
        # -------------------------------------------------------------
        total_deductions = core_deductions + hardening_deductions
        score = max(0, min(100, 100 - total_deductions))
        
        # Determine Behavioral Status using centralized thresholds
        if score >= TRANSPORT_STATUS_RESTRICTIVE_THRESHOLD and enforces_https and hsts_present:
            status = BehaviorStatus.RESTRICTIVE
        elif score >= TRANSPORT_STATUS_CONSISTENT_THRESHOLD and (enforces_https or not http_ok):
            status = BehaviorStatus.CONSISTENT
        elif score >= TRANSPORT_STATUS_PERMISSIVE_THRESHOLD:
            status = BehaviorStatus.PERMISSIVE
        elif score >= TRANSPORT_STATUS_INCONSISTENT_THRESHOLD:
            status = BehaviorStatus.INCONSISTENT
        else:
            status = BehaviorStatus.RISKY

        profile = TransportProfile(
            score=score,
            status=status,
            http_accessible=http_ok,
            https_accessible=https_ok,
            enforces_https=enforces_https,
            hsts_present=hsts_present,
            hsts_max_age=hsts_max_age,
            hsts_include_subdomains=hsts_include_subdomains,
            hsts_preload=hsts_preload,
            http_redirect_code=http_redirect_code,
            findings=findings,
            behavior=transport_behavior,
            confidence=confidence_val,
            confidence_reason=confidence_reason,
        )

        return profile, observations


def analyze_transport_security(
    target_host: str,
    http_probe: Optional[Dict[str, Any]],
    https_probe: Optional[Dict[str, Any]],
    normalized_headers: Optional[Dict[str, str]] = None,
) -> Tuple[TransportProfile, List[EvidenceObservation]]:
    """
    Backwards-compatible functional interface for Transport Security analysis.
    """
    analyzer = TransportAnalyzer()
    return analyzer.analyze_probes(
        target_host=target_host,
        http_probe=http_probe,
        https_probe=https_probe,
        normalized_headers=normalized_headers,
    )


# ==============================================================================
# MODULE: redirect_analyzer.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Redirect Behavior Profiler
Analyzes hop-by-hop redirect sequences, protocol transitions, domain transfers, and loop detection.
Refactored to cleanly separate behavioral classification from numerical risk scoring with dynamic confidence.
"""




class RedirectAnalyzer:
    """
    Evaluates observed redirect chains and sequences:
    1. Behavioral Classification: transition (upgrade/downgrade/same), chain length (single/multi/excessive/loop), domain scope (same/cross), final transport.
    2. Numerical Scoring: risk penalties for downgrades, excessive chains, circular loops, and temporary upgrades.
    """

    def __init__(self):
        pass

    def _calculate_dynamic_confidence(
        self,
        has_steps: bool,
        has_valid_status_codes: bool,
        has_resolvable_urls: bool,
        has_terminal_resolution: bool,
    ) -> Tuple[int, str]:
        """
        Calculates dynamic observation confidence (0 - 100) based on telemetry completeness.
        """
        score = 0
        reasons = []

        if has_steps:
            score += 30
            reasons.append("redirect steps recorded")
        else:
            reasons.append("no redirect steps recorded")

        if has_valid_status_codes:
            score += 25
            reasons.append("valid HTTP status codes verified")

        if has_resolvable_urls:
            score += 25
            reasons.append("source and destination URLs resolved")

        if has_terminal_resolution:
            score += 20
            reasons.append("terminal resolution reached")

        confidence_level = "High" if score >= 85 else ("Medium" if score >= 60 else "Low")
        reason_text = f"{confidence_level} confidence ({score}%): {', '.join(reasons)}."
        return score, reason_text

    def analyze_raw(
        self,
        raw_obs: RawObservations,
    ) -> Tuple[RedirectProfile, List[EvidenceObservation]]:
        """
        Analyzes a structured RawObservations instance from Phase 1 DataCollector.
        """
        chain: List[RedirectStep] = []
        initial_url = raw_obs.basic_http.target_url

        for hop in raw_obs.redirect_chain.hops:
            src_p = urllib.parse.urlparse(hop.source_url)
            dst_p = urllib.parse.urlparse(hop.destination_url)

            src_scheme = src_p.scheme.lower()
            dst_scheme = dst_p.scheme.lower()

            if src_scheme == "http" and dst_scheme == "https":
                protocol_change = "UPGRADE_TO_HTTPS"
            elif src_scheme == "https" and dst_scheme == "http":
                protocol_change = "DOWNGRADE_TO_HTTP"
            else:
                protocol_change = "NONE"

            host_change = (src_p.hostname != dst_p.hostname) if (src_p.hostname and dst_p.hostname) else False

            chain.append(
                RedirectStep(
                    step=hop.hop_index,
                    status_code=hop.status_code,
                    source_url=hop.source_url,
                    destination_url=hop.destination_url,
                    protocol_change=protocol_change,
                    host_change=host_change,
                    latency_ms=hop.latency_ms,
                )
            )

        return self.analyze(chain, initial_url)

    def analyze(
        self,
        chain: Optional[List[RedirectStep]],
        initial_url: Optional[str] = "",
    ) -> Tuple[RedirectProfile, List[EvidenceObservation]]:
        """
        Core evaluation of observed redirect behavior and scoring.
        """
        findings: List[str] = []
        observations: List[EvidenceObservation] = []
        deductions = 0

        # Handle missing / unobserved telemetry
        if not chain:
            confidence_val, confidence_reason = self._calculate_dynamic_confidence(
                has_steps=False,
                has_valid_status_codes=False,
                has_resolvable_urls=False,
                has_terminal_resolution=False,
            )
            empty_behavior = RedirectBehavior(
                transition_behavior=TransitionBehavior.UNKNOWN,
                chain_behavior=ChainBehavior.UNKNOWN,
                domain_behavior=DomainBehavior.UNKNOWN,
                final_transport=FinalTransportBehavior.UNKNOWN,
            )
            profile = RedirectProfile(
                score=100,
                status=BehaviorStatus.CONSISTENT,
                total_hops=0,
                pattern_classification="NO_TELEMETRY",
                redirect_chain=[],
                has_downgrade=False,
                has_excessive_hops=False,
                is_circular=False,
                findings=["No redirect telemetry observed."],
                behavior=empty_behavior,
                confidence=confidence_val,
                confidence_reason=confidence_reason,
            )
            return profile, observations

        total_hops = len(chain)

        # Telemetry validation for dynamic confidence
        has_valid_codes = all(step.status_code > 0 for step in chain)
        has_resolvable_urls = all(
            bool(urllib.parse.urlparse(step.source_url).scheme) for step in chain
        )
        has_terminal = any(step.status_code in (200, 403, 404, 310) or step.destination_url == "[CIRCULAR_REDIRECT_LOOP_DETECTED]" for step in chain) or total_hops >= 1

        confidence_val, confidence_reason = self._calculate_dynamic_confidence(
            has_steps=total_hops > 0,
            has_valid_status_codes=has_valid_codes,
            has_resolvable_urls=has_resolvable_urls,
            has_terminal_resolution=has_terminal,
        )

        is_circular = any(
            step.status_code == 310 or step.destination_url == "[CIRCULAR_REDIRECT_LOOP_DETECTED]"
            for step in chain
        )

        # Count actual redirect hops (3xx codes with location transitions)
        redirect_hops = [step for step in chain if step.status_code in (301, 302, 303, 307, 308)]
        actual_redirect_count = len(redirect_hops)
        has_excessive_hops = actual_redirect_count > REDIRECT_EXCESSIVE_HOPS_THRESHOLD or total_hops > 4

        has_downgrade = False
        has_cross_domain = False
        upgrade_status_code: Optional[int] = None
        has_upgrade = False
        all_same_scheme = True
        first_scheme = None

        # -------------------------------------------------------------
        # 1. Step-by-Step Telemetry Analysis
        # -------------------------------------------------------------
        for step in chain:
            src_p = urllib.parse.urlparse(step.source_url)
            dst_p = urllib.parse.urlparse(step.destination_url)
            src_scheme = src_p.scheme.lower()
            dst_scheme = dst_p.scheme.lower() if step.destination_url != "[CIRCULAR_REDIRECT_LOOP_DETECTED]" else ""

            if first_scheme is None and src_scheme:
                first_scheme = src_scheme

            # Check for protocol changes
            if step.protocol_change == "DOWNGRADE_TO_HTTP" or (src_scheme == "https" and dst_scheme == "http"):
                has_downgrade = True
                deductions += REDIRECT_DEDUCTION_DOWNGRADE
                findings.append(f"Insecure protocol downgrade detected at Step {step.step}: HTTPS -> HTTP ({step.source_url} -> {step.destination_url})")
                observations.append(
                    EvidenceObservation(
                        title="Insecure Protocol Downgrade in Redirect Chain",
                        category="Redirect Behavior",
                        severity=Severity.CRITICAL,
                        confidence=confidence_val,
                        observation=f"Hop #{step.step} redirects from a secure HTTPS origin to an unencrypted HTTP destination.",
                        evidence=[
                            f"step: {step.step}",
                            f"status_code: {step.status_code}",
                            f"source_url: {step.source_url}",
                            f"destination_url: {step.destination_url}",
                            f"source_scheme: {src_scheme}",
                            f"destination_scheme: {dst_scheme}",
                        ],
                        impact="Users are transitioned from encrypted channel into cleartext channel, exposing active sessions to interception and SSL stripping.",
                        recommendation="Remove HTTP fallback in redirect sequence. Ensure all intermediate and destination redirect targets use HTTPS.",
                    )
                )
            elif step.protocol_change == "UPGRADE_TO_HTTPS" or (src_scheme == "http" and dst_scheme == "https"):
                has_upgrade = True
                upgrade_status_code = step.status_code
                all_same_scheme = False
            elif dst_scheme and src_scheme and src_scheme != dst_scheme:
                all_same_scheme = False

            # Check for cross-domain transitions
            if step.host_change or (src_p.hostname and dst_p.hostname and src_p.hostname != dst_p.hostname and not is_circular):
                has_cross_domain = True
                findings.append(f"Cross-host transition at Step {step.step}: {src_p.netloc} -> {dst_p.netloc}")

        # Check for excessive redirects
        if has_excessive_hops:
            excess = max(1, actual_redirect_count - REDIRECT_EXCESSIVE_HOPS_THRESHOLD if actual_redirect_count > REDIRECT_EXCESSIVE_HOPS_THRESHOLD else total_hops - 3)
            deductions += min(REDIRECT_DEDUCTION_EXCESSIVE_MAX, excess * REDIRECT_DEDUCTION_EXCESSIVE_PER_HOP)
            findings.append(f"Excessive redirect chain observed ({total_hops} steps, {actual_redirect_count} redirects). Standard limit is <= 3 redirects.")
            observations.append(
                EvidenceObservation(
                    title="Excessive Redirect Chain Length",
                    category="Redirect Behavior",
                    severity=Severity.MEDIUM,
                    confidence=confidence_val,
                    observation=f"The application executes {total_hops} redirect steps before resolving the final resource.",
                    evidence=[
                        f"total_hops: {total_hops}",
                        f"actual_redirect_count: {actual_redirect_count}",
                        f"threshold: {REDIRECT_EXCESSIVE_HOPS_THRESHOLD}",
                        f"initial_url: {initial_url or chain[0].source_url}",
                        f"final_destination: {chain[-1].destination_url if chain else ''}",
                    ],
                    impact="Increases latency, degrades TLS session caching, and expands attack surface for redirect manipulation or open redirect chaining.",
                    recommendation="Flatten routing rules to collapse intermediate redirects into a single direct response or 1-hop canonical rewrite.",
                )
            )

        # Check for circular redirect loops
        if is_circular:
            deductions += REDIRECT_DEDUCTION_LOOP
            findings.append("Circular redirect loop detected during path traversal.")
            observations.append(
                EvidenceObservation(
                    title="Circular Redirect Loop Detected",
                    category="Redirect Behavior",
                    severity=Severity.HIGH,
                    confidence=confidence_val,
                    observation="Web server configuration triggers an infinite loop or self-referential redirect sequence.",
                    evidence=[
                        f"loop_detected_at_step: {total_hops}",
                        f"final_url: {chain[-1].source_url if chain else ''}",
                        "status_code: 310",
                    ],
                    impact="Causes Denial of Service for visiting clients and disrupts automated security scanners.",
                    recommendation="Audit rewrite/proxy rules to eliminate cyclic destination loops.",
                )
            )

        # -------------------------------------------------------------
        # 2. Structured Behavioral Classifications (Independent of Scoring)
        # -------------------------------------------------------------
        # A. Transition Behavior
        if has_downgrade:
            transition_behavior = TransitionBehavior.DOWNGRADE
        elif has_upgrade:
            if upgrade_status_code in (301, 308):
                transition_behavior = TransitionBehavior.CANONICAL_UPGRADE
            elif upgrade_status_code in (302, 303, 307):
                transition_behavior = TransitionBehavior.TEMPORARY_UPGRADE
                deductions += REDIRECT_DEDUCTION_TEMPORARY_UPGRADE
            else:
                transition_behavior = TransitionBehavior.CANONICAL_UPGRADE
        elif all_same_scheme and first_scheme in ("http", "https"):
            transition_behavior = TransitionBehavior.SAME_SCHEME
        elif not any(step.status_code in (301, 302, 303, 307, 308) for step in chain):
            transition_behavior = TransitionBehavior.SAME_SCHEME
        else:
            transition_behavior = TransitionBehavior.UNKNOWN

        # B. Chain Behavior
        if is_circular:
            chain_behavior = ChainBehavior.LOOP
        elif actual_redirect_count > REDIRECT_EXCESSIVE_HOPS_THRESHOLD or total_hops > 4:
            chain_behavior = ChainBehavior.EXCESSIVE
        elif actual_redirect_count in (2, 3) or (total_hops in (3, 4) and actual_redirect_count >= 2):
            chain_behavior = ChainBehavior.MULTI_HOP
        elif actual_redirect_count <= 1:
            chain_behavior = ChainBehavior.SINGLE_HOP
        else:
            chain_behavior = ChainBehavior.UNKNOWN

        # C. Domain Behavior
        if has_cross_domain:
            domain_behavior = DomainBehavior.CROSS_DOMAIN
        else:
            domain_behavior = DomainBehavior.SAME_DOMAIN

        # D. Final Transport Behavior
        last_step = chain[-1]
        final_target = last_step.destination_url if last_step.destination_url != "[CIRCULAR_REDIRECT_LOOP_DETECTED]" else last_step.source_url
        final_parsed = urllib.parse.urlparse(final_target)
        final_scheme = final_parsed.scheme.lower()

        if final_scheme == "https":
            final_transport = FinalTransportBehavior.HTTPS
        elif final_scheme == "http":
            final_transport = FinalTransportBehavior.HTTP
        else:
            final_transport = FinalTransportBehavior.UNKNOWN

        redirect_behavior = RedirectBehavior(
            transition_behavior=transition_behavior,
            chain_behavior=chain_behavior,
            domain_behavior=domain_behavior,
            final_transport=final_transport,
        )

        # -------------------------------------------------------------
        # 3. Pattern Classification (Backward Compatible)
        # -------------------------------------------------------------
        if is_circular:
            pattern = "CIRCULAR_REDIRECT_LOOP"
        elif has_downgrade:
            pattern = "PROTOCOL_DOWNGRADE_RISK"
        elif total_hops == 1 and chain[0].status_code in (200, 403, 404):
            pattern = "DIRECT_RESPONSE"
            findings.append("Resource resolved directly without redirection.")
        elif (total_hops == 2 and chain[0].protocol_change == "UPGRADE_TO_HTTPS") or transition_behavior == TransitionBehavior.CANONICAL_UPGRADE:
            pattern = "CANONICAL_HTTPS_UPGRADE"
            findings.append("Optimal single-hop HTTP -> HTTPS upgrade observed.")
        elif has_cross_domain:
            pattern = "CROSS_DOMAIN_DISPATCH"
        elif has_excessive_hops:
            pattern = "EXCESSIVE_CHAIN"
        else:
            pattern = "INTERNAL_CANONICALIZATION"

        # -------------------------------------------------------------
        # 4. Numerical Risk Scoring
        # -------------------------------------------------------------
        score = max(0, min(100, 100 - deductions))

        if score >= 90 and not has_downgrade and not has_excessive_hops:
            status = BehaviorStatus.CONSISTENT
        elif score >= REDIRECT_STATUS_CONSISTENT_THRESHOLD:
            status = BehaviorStatus.CONSISTENT
        elif score >= REDIRECT_STATUS_PERMISSIVE_THRESHOLD:
            status = BehaviorStatus.PERMISSIVE
        elif score >= REDIRECT_STATUS_INCONSISTENT_THRESHOLD:
            status = BehaviorStatus.INCONSISTENT
        else:
            status = BehaviorStatus.RISKY

        profile = RedirectProfile(
            score=score,
            status=status,
            total_hops=total_hops,
            pattern_classification=pattern,
            redirect_chain=chain,
            has_downgrade=has_downgrade,
            has_excessive_hops=has_excessive_hops,
            is_circular=is_circular,
            findings=findings,
            behavior=redirect_behavior,
            confidence=confidence_val,
            confidence_reason=confidence_reason,
        )

        return profile, observations


def analyze_redirect_chain(
    chain: List[RedirectStep],
    initial_url: str,
) -> Tuple[RedirectProfile, List[EvidenceObservation]]:
    """
    Backwards-compatible functional entry point for redirect chain evaluation.
    """
    analyzer = RedirectAnalyzer()
    return analyzer.analyze(chain, initial_url)


# ==============================================================================
# MODULE: cookie_analyzer.py
# ==============================================================================
class CookieAnalyzer:

    def __init__(self):
        self._sensitive_regexes = [
            re.compile(
                rf"(^|_|-){re.escape(pat)}(_|-|$)",
                re.IGNORECASE,
            )
            for pat in SENSITIVE_COOKIE_PATTERNS
        ]

    def _is_csrf_token_cookie(self, name: str) -> bool:
        if not name:
            return False

        name_lower = name.lower()

        for pat in CSRF_TOKEN_COOKIE_PATTERNS:
            if pat in name_lower:
                return True

        return False

    def _is_sensitive_cookie_name(self, name: str) -> bool:
        if not name:
            return False

        name_lower = name.lower()

        for pat in (
            "phpsessid",
            "jsessionid",
            "asp.net_sessionid",
            "logged_in",
            "remember_me",
            "session",
        ):
            if pat in name_lower:
                return True

        tokens = re.findall(r"[a-z0-9]+", name_lower)

        sensitive_exact_tokens = {
            "session",
            "sess",
            "jwt",
            "token",
            "auth",
            "sid",
            "remember",
            "account",
            "user",
            "sso",
        }

        for token in tokens:
            if token in sensitive_exact_tokens:
                return True

            for sensitive_token in (
                "session",
                "auth",
                "account",
            ):
                if (
                    token.startswith(sensitive_token)
                    or token.endswith(sensitive_token)
                ):
                    return True

        return False

    def _calculate_dynamic_confidence(
        self,
        has_headers: bool,
        cookies_count: int,
        has_parsed_attributes: bool,
        has_sensitive_cookies: bool,
    ) -> Tuple[int, str]:

        if not has_headers:
            return (
                0,
                "No cookie telemetry observed (unobserved / uncollected).",
            )

        if cookies_count == 0:
            return (
                30,
                "Low-Medium confidence (30%): Response observed without Set-Cookie headers (stateless endpoint).",
            )

        score = 40
        reasons = [f"{cookies_count} cookie(s) parsed"]

        if has_parsed_attributes:
            score += 30
            reasons.append(
                "RFC attributes parsed"
            )

        if has_sensitive_cookies:
            score += 20
            reasons.append(
                "session/auth cookies identified and matched"
            )
        else:
            score += 10
            reasons.append(
                "non-sensitive cookies classified"
            )

        score = min(100, score + 10)

        confidence_level = (
            "High"
            if score >= 85
            else "Medium"
            if score >= 60
            else "Low"
        )

        reason_text = (
            f"{confidence_level} confidence ({score}%): "
            f"{', '.join(reasons)}."
        )

        return score, reason_text

    def analyze_raw(
        self,
        raw_obs: RawObservations,
    ) -> Tuple[CookieProfile, List[EvidenceObservation]]:

        return self.analyze_observations(
            cookies=raw_obs.cookies,
            is_https=raw_obs.transport.is_https,
        )

    def analyze(
        self,
        raw_cookie_headers: Optional[List[str]],
        is_https: bool = True,
    ) -> Tuple[CookieProfile, List[EvidenceObservation]]:

        if raw_cookie_headers is None:
            return self.analyze_observations(
                None,
                is_https=is_https,
            )

        parsed_obs: List[CookieObservation] = []

        for header in raw_cookie_headers:
            parsed_obs.append(
                parse_cookie_header(header)
            )

        return self.analyze_observations(
            parsed_obs,
            is_https=is_https,
        )

    def analyze_observations(
        self,
        cookies: Optional[List[CookieObservation]],
        is_https: bool = True,
    ) -> Tuple[CookieProfile, List[EvidenceObservation]]:

        findings: List[str] = []
        observations: List[EvidenceObservation] = []
        inconsistent_attributes: List[str] = []
        deductions = 0

        if cookies is None:

            confidence_val, confidence_reason = (
                self._calculate_dynamic_confidence(
                    has_headers=False,
                    cookies_count=0,
                    has_parsed_attributes=False,
                    has_sensitive_cookies=False,
                )
            )

            empty_behavior = CookieBehavior(
                session_protection=SessionProtectionBehavior.UNKNOWN,
                script_accessibility=ScriptAccessibilityBehavior.UNKNOWN,
                cross_site_behavior=CrossSiteBehavior.UNKNOWN,
                scope_behavior=ScopeBehavior.UNKNOWN,
                prefix_behavior=PrefixBehavior.UNKNOWN,
                consistency_behavior=CookieConsistencyBehavior.UNKNOWN,
            )

            profile = CookieProfile(
                score=100,
                status=BehaviorStatus.CONSISTENT,
                cookies_analyzed=[],
                total_cookies=0,
                sensitive_cookies_count=0,
                inconsistent_attributes=[],
                findings=["No cookie telemetry observed."],
                behavior=empty_behavior,
                confidence=confidence_val,
                confidence_reason=confidence_reason,
            )

            return profile, observations

        if len(cookies) == 0:

            confidence_val, confidence_reason = (
                self._calculate_dynamic_confidence(
                    has_headers=True,
                    cookies_count=0,
                    has_parsed_attributes=True,
                    has_sensitive_cookies=False,
                )
            )

            stateless_behavior = CookieBehavior(
                session_protection=SessionProtectionBehavior.NO_SENSITIVE_COOKIES,
                script_accessibility=ScriptAccessibilityBehavior.UNKNOWN,
                cross_site_behavior=CrossSiteBehavior.UNKNOWN,
                scope_behavior=ScopeBehavior.HOST_ONLY,
                prefix_behavior=PrefixBehavior.PREFIX_STANDARD,
                consistency_behavior=CookieConsistencyBehavior.CONSISTENT_POLICY,
            )

            profile = CookieProfile(
                score=100,
                status=BehaviorStatus.RESTRICTIVE,
                cookies_analyzed=[],
                total_cookies=0,
                sensitive_cookies_count=0,
                inconsistent_attributes=[],
                findings=[
                    "No Set-Cookie headers observed in server response."
                ],
                behavior=stateless_behavior,
                confidence=confidence_val,
                confidence_reason=confidence_reason,
            )

            return profile, observations

        analyzed_cookies: List[CookieAttribute] = []

        for obs in cookies:

            name = obs.name

            is_csrf = self._is_csrf_token_cookie(name)
            is_sensitive = (
                self._is_sensitive_cookie_name(name)
                and not is_csrf
            )

            has_secure_prefix = name.startswith(
                "__Secure-"
            )

            has_host_prefix = name.startswith(
                "__Host-"
            )

            is_persistent = bool(
                obs.max_age is not None
                or obs.expires is not None
            )

            analyzed_cookies.append(
                CookieAttribute(
                    name=name,
                    value_preview="***",
                    secure=obs.secure,
                    httponly=obs.httponly,
                    samesite=obs.samesite,
                    domain=obs.domain,
                    path=obs.path,
                    max_age=obs.max_age,
                    expires=obs.expires,
                    has_secure_prefix=has_secure_prefix,
                    has_host_prefix=has_host_prefix,
                    is_sensitive=is_sensitive,
                    is_persistent=is_persistent,
                    is_csrf_token=is_csrf,
                )
            )

        total_cookies = len(analyzed_cookies)

        sensitive_cookies = [
            c
            for c in analyzed_cookies
            if c.is_sensitive
        ]

        sensitive_count = len(sensitive_cookies)

        csrf_cookies = [
            c
            for c in analyzed_cookies
            if c.is_csrf_token
        ]

        csrf_count = len(csrf_cookies)

        confidence_val, confidence_reason = (
            self._calculate_dynamic_confidence(
                has_headers=True,
                cookies_count=total_cookies,
                has_parsed_attributes=True,
                has_sensitive_cookies=(
                    sensitive_count + csrf_count
                ) > 0,
            )
        )

        findings.append(
            f"Analyzed {total_cookies} cookie(s) "
            f"({sensitive_count} sensitive/session candidate(s), "
            f"{csrf_count} CSRF token candidate(s))."
        )

        for c in analyzed_cookies:

            evidence_data = [
                f"cookie_name: {c.name}",
                f"secure: {c.secure}",
                f"httponly: {c.httponly}",
                f"samesite: {c.samesite if c.samesite is not None else 'unspecified'}",
                f"domain: {c.domain if c.domain is not None else 'host-only'}",
                f"path: {c.path if c.path is not None else '/'}",
                f"lifecycle: {'persistent' if c.is_persistent else 'session'}",
                f"is_sensitive: {c.is_sensitive}",
                f"is_csrf_token: {c.is_csrf_token}",
            ]

            if not c.secure:

                if c.is_sensitive:

                    deductions += (
                        COOKIE_DEDUCTION_SENSITIVE_MISSING_SECURE
                    )

                    findings.append(
                        f"Sensitive cookie '{c.name}' "
                        f"is missing the 'Secure' attribute."
                    )

                    observations.append(
                        EvidenceObservation(
                            title=(
                                "Sensitive Cookie Missing Secure "
                                f"Attribute ({c.name})"
                            ),
                            category="Cookie Security",
                            severity=Severity.HIGH,
                            confidence=confidence_val,
                            observation=(
                                f"Cookie '{c.name}' appears to carry "
                                "session or authentication state but "
                                "lacks the 'Secure' directive."
                            ),
                            evidence=evidence_data,
                            impact=(
                                "The browser will transmit this "
                                "sensitive cookie over unencrypted "
                                "HTTP requests."
                            ),
                            recommendation=(
                                f"Append '; Secure' to the Set-Cookie "
                                f"directive for '{c.name}'."
                            ),
                        )
                    )

                elif c.is_csrf_token:

                    deductions += (
                        COOKIE_DEDUCTION_SENSITIVE_MISSING_SECURE
                    )

                    findings.append(
                        f"CSRF token cookie '{c.name}' "
                        "is missing the 'Secure' attribute."
                    )

                    observations.append(
                        EvidenceObservation(
                            title=(
                                "CSRF Token Cookie Missing Secure "
                                f"Attribute ({c.name})"
                            ),
                            category="Cookie Security",
                            severity=Severity.HIGH,
                            confidence=confidence_val,
                            observation=(
                                f"CSRF token cookie '{c.name}' "
                                "is transmitted without the "
                                "Secure directive."
                            ),
                            evidence=evidence_data,
                            impact=(
                                "An active network attacker could "
                                "inspect or manipulate the CSRF "
                                "token over unencrypted HTTP."
                            ),
                            recommendation=(
                                f"Append '; Secure' to the Set-Cookie "
                                f"directive for '{c.name}'."
                            ),
                        )
                    )

                else:

                    deductions += (
                        COOKIE_DEDUCTION_NON_SENSITIVE_MISSING_SECURE
                    )

                    findings.append(
                        f"Cookie '{c.name}' is missing "
                        "the 'Secure' attribute."
                    )

            if not c.httponly:

                if c.is_sensitive:

                    deductions += (
                        COOKIE_DEDUCTION_SENSITIVE_MISSING_HTTPONLY
                    )

                    findings.append(
                        f"Sensitive cookie '{c.name}' "
                        "is missing the 'HttpOnly' attribute."
                    )

                    observations.append(
                        EvidenceObservation(
                            title=(
                                "Sensitive Cookie Missing HttpOnly "
                                f"Attribute ({c.name})"
                            ),
                            category="Cookie Security",
                            severity=Severity.HIGH,
                            confidence=confidence_val,
                            observation=(
                                f"Session/auth cookie '{c.name}' "
                                "is accessible to client-side "
                                "JavaScript via document.cookie."
                            ),
                            evidence=evidence_data,
                            impact=(
                                "If Cross-Site Scripting occurs "
                                "on the domain, attackers may "
                                "exfiltrate this session cookie."
                            ),
                            recommendation=(
                                f"Append '; HttpOnly' to the "
                                f"Set-Cookie directive for '{c.name}'."
                            ),
                        )
                    )

                elif c.is_csrf_token:

                    findings.append(
                        f"CSRF token cookie '{c.name}' is accessible "
                        "to JavaScript."
                    )

                else:

                    findings.append(
                        f"Cookie '{c.name}' is not marked HttpOnly."
                    )

            if not c.samesite:

                deductions += COOKIE_DEDUCTION_MISSING_SAMESITE

                findings.append(
                    f"Cookie '{c.name}' lacks explicit "
                    "'SameSite' attribute."
                )

                if c.is_sensitive:

                    observations.append(
                        EvidenceObservation(
                            title=(
                                "Session Cookie Lacks Explicit "
                                f"SameSite Attribute ({c.name})"
                            ),
                            category="Cookie Security",
                            severity=Severity.MEDIUM,
                            confidence=confidence_val,
                            observation=(
                                f"Cookie '{c.name}' does not "
                                "explicitly declare SameSite=Lax "
                                "or SameSite=Strict."
                            ),
                            evidence=evidence_data,
                            impact=(
                                "Legacy clients may provide weaker "
                                "CSRF protection."
                            ),
                            recommendation=(
                                f"Explicitly set 'SameSite=Lax' "
                                f"or 'SameSite=Strict' for '{c.name}'."
                            ),
                        )
                    )

            elif (
                c.samesite.lower() == "none"
                and not c.secure
            ):

                deductions += (
                    COOKIE_DEDUCTION_SAMESITE_NONE_INSECURE
                )

                findings.append(
                    f"Cookie '{c.name}' specifies SameSite=None "
                    "without Secure flag."
                )

                observations.append(
                    EvidenceObservation(
                        title=(
                            "SameSite=None Without Secure "
                            f"Attribute ({c.name})"
                        ),
                        category="Cookie Security",
                        severity=Severity.HIGH,
                        confidence=confidence_val,
                        observation=(
                            f"Cookie '{c.name}' defines "
                            "SameSite=None but omits the "
                            "mandatory Secure attribute."
                        ),
                        evidence=evidence_data,
                        impact=(
                            "Modern browsers may reject this "
                            "cookie entirely."
                        ),
                        recommendation=(
                            "Ensure all SameSite=None cookies "
                            "include the Secure attribute."
                        ),
                    )
                )

            if c.has_secure_prefix and not c.secure:

                deductions += (
                    COOKIE_DEDUCTION_SECURE_PREFIX_VIOLATION
                )

                findings.append(
                    f"Cookie prefix violation: '{c.name}' "
                    "starts with __Secure- but lacks Secure."
                )

                observations.append(
                    EvidenceObservation(
                        title=(
                            "__Secure- Prefix Integrity "
                            f"Violation ({c.name})"
                        ),
                        category="Cookie Security",
                        severity=Severity.HIGH,
                        confidence=confidence_val,
                        observation=(
                            f"Cookie '{c.name}' uses the "
                            "__Secure- prefix but omits "
                            "the required Secure attribute."
                        ),
                        evidence=evidence_data,
                        impact=(
                            "Compliant browsers may reject "
                            "the cookie."
                        ),
                        recommendation=(
                            "Set Secure=True for "
                            "__Secure- prefixed cookies."
                        ),
                    )
                )

            if c.has_host_prefix:

                is_host_compliant = (
                    c.secure
                    and c.domain is None
                    and c.path == "/"
                )

                if not is_host_compliant:

                    deductions += (
                        COOKIE_DEDUCTION_HOST_PREFIX_VIOLATION
                    )

                    findings.append(
                        f"Cookie prefix violation: '{c.name}' "
                        "starts with __Host- but violates "
                        "__Host- rules."
                    )

                    observations.append(
                        EvidenceObservation(
                            title=(
                                "__Host- Prefix Integrity "
                                f"Violation ({c.name})"
                            ),
                            category="Cookie Security",
                            severity=Severity.HIGH,
                            confidence=confidence_val,
                            observation=(
                                f"Cookie '{c.name}' uses the "
                                "__Host- prefix but does not "
                                "satisfy strict browser requirements."
                            ),
                            evidence=evidence_data,
                            impact=(
                                "Browsers enforcing cookie prefix "
                                "rules may reject the cookie."
                            ),
                            recommendation=(
                                "Set Secure=True, Path=/, and "
                                "omit Domain for __Host- cookies."
                            ),
                        )
                    )

        if total_cookies > 1:

            secure_flags = [
                c.secure for c in analyzed_cookies
            ]

            if any(secure_flags) and not all(secure_flags):

                inconsistent_attributes.append(
                    "Secure Flag Inconsistency: Some cookies "
                    "specify Secure while others omit it."
                )

                deductions += (
                    COOKIE_DEDUCTION_INCONSISTENT_SECURE
                )

                findings.append(
                    "Inconsistent Secure attribute usage "
                    "observed across cookies."
                )

            if sensitive_count > 1:

                sens_httponly = [
                    c.httponly
                    for c in sensitive_cookies
                ]

                if (
                    any(sens_httponly)
                    and not all(sens_httponly)
                ):

                    inconsistent_attributes.append(
                        "HttpOnly Inconsistency: Some sensitive "
                        "cookies are HttpOnly while others are "
                        "script-accessible."
                    )

                    deductions += (
                        COOKIE_DEDUCTION_INCONSISTENT_HTTPONLY
                    )

                    findings.append(
                        "Inconsistent HttpOnly attribute usage "
                        "observed across sensitive cookies."
                    )

            defined_samesite = [
                c.samesite
                for c in analyzed_cookies
                if c.samesite is not None
            ]

            if (
                len(defined_samesite) > 1
                and len(set(defined_samesite)) > 1
            ):

                inconsistent_attributes.append(
                    "SameSite Inconsistency: Conflicting "
                    "SameSite policies across cookies."
                )

        if sensitive_count == 0:

            session_protection = (
                SessionProtectionBehavior.NO_SENSITIVE_COOKIES
            )

        else:

            fully_protected_sens = [
                c
                for c in sensitive_cookies
                if (
                    c.secure
                    and c.httponly
                    and (
                        c.samesite is None
                        or c.samesite.lower()
                        in ("strict", "lax")
                        or (
                            c.samesite.lower() == "none"
                            and c.secure
                        )
                    )
                )
            ]

            completely_unprotected_sens = [
                c
                for c in sensitive_cookies
                if not c.secure and not c.httponly
            ]

            if len(fully_protected_sens) == sensitive_count:

                session_protection = (
                    SessionProtectionBehavior.SECURE_SESSION_BEHAVIOR
                )

            elif (
                len(completely_unprotected_sens)
                == sensitive_count
            ):

                session_protection = (
                    SessionProtectionBehavior.WEAK_SESSION_PROTECTION
                )

            elif (
                all(
                    not c.secure
                    for c in sensitive_cookies
                )
                or all(
                    not c.httponly
                    for c in sensitive_cookies
                )
            ):

                session_protection = (
                    SessionProtectionBehavior.WEAK_SESSION_PROTECTION
                )

            else:

                session_protection = (
                    SessionProtectionBehavior.PARTIAL_SESSION_PROTECTION
                )

        if sensitive_count == 0:

            script_accessibility = (
                ScriptAccessibilityBehavior.UNKNOWN
            )

        elif all(
            c.httponly
            for c in sensitive_cookies
        ):

            script_accessibility = (
                ScriptAccessibilityBehavior.SCRIPT_RESTRICTED
            )

        else:

            script_accessibility = (
                ScriptAccessibilityBehavior.SCRIPT_ACCESSIBLE
            )

        samesite_lowers = [
            c.samesite.lower()
            for c in analyzed_cookies
            if c.samesite is not None
        ]

        if any(
            s == "none"
            for s in samesite_lowers
        ):

            cross_site_behavior = (
                CrossSiteBehavior.CROSS_SITE_ALLOWED
            )

        elif any(
            s in ("strict", "lax")
            for s in samesite_lowers
        ):

            cross_site_behavior = (
                CrossSiteBehavior.CROSS_SITE_RESTRICTED
            )

        elif all(
            c.samesite is None
            for c in analyzed_cookies
        ):

            cross_site_behavior = (
                CrossSiteBehavior.CROSS_SITE_UNSPECIFIED
            )

        else:

            cross_site_behavior = (
                CrossSiteBehavior.UNKNOWN
            )

        has_domain = any(
            c.domain is not None
            and c.domain != ""
            for c in analyzed_cookies
        )

        has_host_only = any(
            c.domain is None
            or c.domain == ""
            for c in analyzed_cookies
        )

        if has_domain and has_host_only:

            scope_behavior = (
                ScopeBehavior.HYBRID_SCOPED
            )

        elif has_domain:

            scope_behavior = (
                ScopeBehavior.DOMAIN_SCOPED
            )

        elif has_host_only:

            scope_behavior = (
                ScopeBehavior.HOST_ONLY
            )

        else:

            scope_behavior = (
                ScopeBehavior.UNKNOWN
            )

        has_prefix_violation = any(
            (
                c.has_secure_prefix
                and not c.secure
            )
            or (
                c.has_host_prefix
                and (
                    not c.secure
                    or c.domain is not None
                    or c.path != "/"
                )
            )
            for c in analyzed_cookies
        )

        has_prefixes = any(
            c.has_secure_prefix
            or c.has_host_prefix
            for c in analyzed_cookies
        )

        if has_prefix_violation:

            prefix_behavior = (
                PrefixBehavior.PREFIX_VIOLATION
            )

        elif has_prefixes:

            prefix_behavior = (
                PrefixBehavior.PREFIX_HARDENED
            )

        else:

            prefix_behavior = (
                PrefixBehavior.PREFIX_STANDARD
            )

        if total_cookies <= 1:

            consistency_behavior = (
                CookieConsistencyBehavior.CONSISTENT_POLICY
            )

        elif inconsistent_attributes:

            consistency_behavior = (
                CookieConsistencyBehavior.INCONSISTENT_COOKIE_POLICY
            )

        else:

            consistency_behavior = (
                CookieConsistencyBehavior.CONSISTENT_POLICY
            )

        cookie_behavior = CookieBehavior(
            session_protection=session_protection,
            script_accessibility=script_accessibility,
            cross_site_behavior=cross_site_behavior,
            scope_behavior=scope_behavior,
            prefix_behavior=prefix_behavior,
            consistency_behavior=consistency_behavior,
        )

        score = max(
            0,
            min(
                100,
                100 - deductions,
            ),
        )

        if score >= COOKIE_STATUS_RESTRICTIVE_THRESHOLD:

            status = BehaviorStatus.RESTRICTIVE

        elif score >= COOKIE_STATUS_CONSISTENT_THRESHOLD:

            status = BehaviorStatus.CONSISTENT

        elif score >= COOKIE_STATUS_PERMISSIVE_THRESHOLD:

            status = BehaviorStatus.PERMISSIVE

        elif score >= COOKIE_STATUS_INCONSISTENT_THRESHOLD:

            status = BehaviorStatus.INCONSISTENT

        else:

            status = BehaviorStatus.RISKY

        profile = CookieProfile(
            score=score,
            status=status,
            cookies_analyzed=analyzed_cookies,
            total_cookies=total_cookies,
            sensitive_cookies_count=sensitive_count,
            inconsistent_attributes=inconsistent_attributes,
            findings=findings,
            behavior=cookie_behavior,
            confidence=confidence_val,
            confidence_reason=confidence_reason,
        )

        return profile, observations


def analyze_cookies(
    raw_cookie_headers: List[str],
    is_https: bool = True,
) -> Tuple[
    CookieProfile,
    List[EvidenceObservation],
]:

    analyzer = CookieAnalyzer()

    return analyzer.analyze(
        raw_cookie_headers,
        is_https=is_https,
    )


# ==============================================================================
# MODULE: cors_analyzer.py
# ==============================================================================
"""
Security Behavior Profiling Engine - CORS Behavior Profiler
Analyzes Cross-Origin Resource Sharing (CORS) policies, origin reflection, credentials handling,
and preflight behavior without performing intrusive cross-origin exploitation.
"""



class CORSAnalyzer:
    """
    Evaluates observable Cross-Origin Resource Sharing (CORS) behavior from
    factual telemetry (origin trust, credential exposure, and preflight posture).
    """

    def analyze_raw(self, raw_obs: RawObservations) -> Tuple[CORSProfile, List[EvidenceObservation]]:
        """
        Analyzes factual RawObservations directly from the DataCollector layer.
        """
        if not raw_obs:
            return self._create_unknown_profile("No raw observations provided")

        cors_obs = getattr(raw_obs, "cors", None)
        http_methods = getattr(raw_obs, "http_methods", None)
        response_headers = getattr(raw_obs, "response_headers", {}) or {}

        # Synthesize probe headers from response_headers and cors_obs
        cors_headers: Dict[str, str] = {}
        for k, v in response_headers.items():
            if k.lower().startswith("access-control-") or k.lower() == "vary":
                cors_headers[k.lower()] = v

        if cors_obs:
            if cors_obs.access_control_allow_origin:
                cors_headers["access-control-allow-origin"] = cors_obs.access_control_allow_origin
            if cors_obs.access_control_allow_credentials:
                cors_headers["access-control-allow-credentials"] = cors_obs.access_control_allow_credentials
            if cors_obs.access_control_allow_methods:
                cors_headers["access-control-allow-methods"] = cors_obs.access_control_allow_methods
            if cors_obs.access_control_allow_headers:
                cors_headers["access-control-allow-headers"] = cors_obs.access_control_allow_headers

        options_status = getattr(http_methods, "options_status_code", None) if http_methods else None
        advertised_methods = getattr(http_methods, "advertised_methods", []) if http_methods else []

        # If we have verified response telemetry from basic_http
        basic_http = getattr(raw_obs, "basic_http", None)
        has_verified_response = bool(basic_http and basic_http.status_code > 0)

        return self.analyze_observations(
            cors_headers=cors_headers,
            options_status_code=options_status,
            advertised_methods=advertised_methods,
            has_verified_response=has_verified_response,
            telemetry_source="RawObservations",
        )

    def analyze_observations(
        self,
        cors_headers: Optional[Dict[str, str]] = None,
        probe_origin_response: Optional[Dict[str, str]] = None,
        request_origin: Optional[str] = None,
        simulated_origin: str = "https://security-profiler.academic-test.org",
        options_status_code: Optional[int] = None,
        advertised_methods: Optional[List[str]] = None,
        has_verified_response: bool = False,
        telemetry_source: str = "Direct",
    ) -> Tuple[CORSProfile, List[EvidenceObservation]]:
        """
        Core profiling method that maps observed CORS telemetry to behavioral classifications,
        dynamic confidence, and deterministic scoring.
        """
        # Case 1: Missing or completely unprobed telemetry
        if cors_headers is None and probe_origin_response is None and not has_verified_response:
            return self._create_unknown_profile("Missing CORS telemetry (unprobed endpoint)")

        headers = {k.lower(): v for k, v in (cors_headers or {}).items()}
        probe_resp = {k.lower(): v for k, v in (probe_origin_response or {}).items()} if probe_origin_response else {}

        acao = headers.get("access-control-allow-origin")
        acac_raw = headers.get("access-control-allow-credentials", "").lower()
        acac = acac_raw == "true"
        has_acac_header = "access-control-allow-credentials" in headers

        acam_raw = headers.get("access-control-allow-methods", "")
        acam = [m.strip().upper() for m in acam_raw.split(",") if m.strip()] if acam_raw else []

        acah_raw = headers.get("access-control-allow-headers", "")
        acah = [h.strip() for h in acah_raw.split(",") if h.strip()] if acah_raw else []

        acma_raw = headers.get("access-control-max-age")
        max_age: Optional[int] = None
        if acma_raw:
            try:
                max_age = int(acma_raw.strip())
            except ValueError:
                pass

        vary_header = headers.get("vary", "")
        has_vary_origin = "origin" in vary_header.lower()

        # Origin reflection detection from probe or direct header
        is_reflected = False
        target_probe_origin = request_origin or simulated_origin
        if probe_resp:
            probe_acao = probe_resp.get("access-control-allow-origin", "")
            if probe_acao == target_probe_origin or (request_origin and probe_acao == request_origin):
                is_reflected = True

        if target_probe_origin and acao == target_probe_origin and target_probe_origin != "*":
            is_reflected = True

        is_wildcard = (acao == "*")
        is_null = (acao == "null")

        # -------------------------------------------------------------
        # STEP 1: Behavioral Classifications (Independent of Scoring)
        # -------------------------------------------------------------

        # A. Origin Trust Behavior
        if not acao:
            if has_verified_response or cors_headers is not None:
                # Verified response observed with no ACAO -> Same Origin Policy is enforced
                origin_trust = OriginTrustBehavior.SAME_ORIGIN_ONLY
            else:
                origin_trust = OriginTrustBehavior.UNKNOWN
        elif is_wildcard:
            origin_trust = OriginTrustBehavior.PUBLIC_WILDCARD
        elif is_reflected:
            origin_trust = OriginTrustBehavior.REFLECTED_ORIGIN
        elif is_null:
            origin_trust = OriginTrustBehavior.NULL_ORIGIN_TRUSTED
        else:
            origin_trust = OriginTrustBehavior.RESTRICTED_SPECIFIC_ORIGIN

        # B. Credential Exposure Behavior
        if not has_acac_header and not acac:
            if origin_trust == OriginTrustBehavior.UNKNOWN:
                credential_exposure = CredentialExposureBehavior.UNKNOWN
            else:
                credential_exposure = CredentialExposureBehavior.CREDENTIALS_UNSPECIFIED
        elif acac:
            if origin_trust in (
                OriginTrustBehavior.PUBLIC_WILDCARD,
                OriginTrustBehavior.REFLECTED_ORIGIN,
                OriginTrustBehavior.NULL_ORIGIN_TRUSTED,
                OriginTrustBehavior.RESTRICTED_SPECIFIC_ORIGIN,
            ):
                credential_exposure = CredentialExposureBehavior.CREDENTIALS_EXPOSED
            else:
                credential_exposure = CredentialExposureBehavior.CREDENTIALS_RESTRICTED
        else:
            credential_exposure = CredentialExposureBehavior.CREDENTIALS_RESTRICTED

        # C. Preflight Behavior
        if options_status_code is not None or acam or acah or (advertised_methods and len(advertised_methods) > 0):
            if "*" in acam or "*" in acah:
                preflight_behavior = PreflightBehavior.PREFLIGHT_PERMISSIVE_WILDCARD
            elif options_status_code in (200, 204):
                preflight_behavior = PreflightBehavior.PREFLIGHT_STANDARD
            elif options_status_code in (403, 405):
                preflight_behavior = PreflightBehavior.PREFLIGHT_RESTRICTED
            elif acam or acah:
                preflight_behavior = PreflightBehavior.PREFLIGHT_STANDARD
            else:
                preflight_behavior = PreflightBehavior.PREFLIGHT_NOT_APPLICABLE
        else:
            if origin_trust == OriginTrustBehavior.SAME_ORIGIN_ONLY:
                preflight_behavior = PreflightBehavior.PREFLIGHT_NOT_APPLICABLE
            else:
                preflight_behavior = PreflightBehavior.UNKNOWN

        behavior = CORSBehavior(
            origin_trust=origin_trust,
            credential_exposure=credential_exposure,
            preflight_behavior=preflight_behavior,
        )

        # -------------------------------------------------------------
        # STEP 2: Dynamic Confidence Calculation
        # -------------------------------------------------------------
        confidence, confidence_reason = self._calculate_dynamic_confidence(
            has_headers=bool(headers),
            has_acao=bool(acao),
            has_acac=has_acac_header,
            has_probe_response=bool(probe_resp),
            has_options_probe=options_status_code is not None,
            has_verified_response=has_verified_response,
            origin_trust=origin_trust,
        )

        # -------------------------------------------------------------
        # STEP 3: Evidence Generation & Findings
        # -------------------------------------------------------------
        findings: List[str] = []
        observations: List[EvidenceObservation] = []
        policy_risk = "SAFE"

        if origin_trust == OriginTrustBehavior.SAME_ORIGIN_ONLY:
            findings.append("No CORS headers observed; default browser Same-Origin Policy (SOP) is strictly enforced.")
            policy_risk = "SAME_ORIGIN_DEFAULT"

        elif origin_trust == OriginTrustBehavior.REFLECTED_ORIGIN:
            origin_display = acao or target_probe_origin
            findings.append(f"Origin reflection detected: Server mirrors Origin '{origin_display}' into Access-Control-Allow-Origin.")
            if credential_exposure == CredentialExposureBehavior.CREDENTIALS_EXPOSED:
                policy_risk = "CRITICAL_PERMISSIVE_CREDENTIALS"
                findings.append("CRITICAL: Arbitrary origin reflection combined with Access-Control-Allow-Credentials: true.")
                observations.append(
                    EvidenceObservation(
                        title="Overly Permissive CORS Policy with Credentials Allowed",
                        category="CORS Behavior",
                        severity=Severity.CRITICAL,
                        confidence=confidence,
                        observation="Server reflects untrusted requesting Origin and sets Access-Control-Allow-Credentials to true.",
                        evidence=[
                            f"Request Origin: {target_probe_origin}",
                            f"Access-Control-Allow-Origin: {origin_display}",
                            "Access-Control-Allow-Credentials: true",
                            f"Vary Origin Header: {'Present' if has_vary_origin else 'Missing'}",
                        ],
                        impact="Any malicious third-party website visited by an authenticated user can read private API data and execute unauthorized cross-origin requests.",
                        recommendation="Implement a strict allowlist of authorized origin domains. Never dynamically reflect arbitrary Origin headers when credentials are true.",
                    )
                )
            else:
                policy_risk = "REFLECTED_ORIGIN"
                findings.append("Server reflects requesting Origin into Access-Control-Allow-Origin without credentials.")
                observations.append(
                    EvidenceObservation(
                        title="Cross-Origin Resource Sharing Reflects Origin",
                        category="CORS Behavior",
                        severity=Severity.MEDIUM,
                        confidence=confidence,
                        observation="Server reflects untrusted requesting Origin without credentials.",
                        evidence=[
                            f"Request Origin: {target_probe_origin}",
                            f"Access-Control-Allow-Origin: {origin_display}",
                            f"Access-Control-Allow-Credentials: {acac_raw or 'Unspecified'}",
                        ],
                        impact="Untrusted origins can read unauthenticated cross-origin responses from this endpoint.",
                        recommendation="Validate incoming Origin headers against an explicit domain allowlist.",
                    )
                )

        elif origin_trust == OriginTrustBehavior.NULL_ORIGIN_TRUSTED:
            findings.append("Access-Control-Allow-Origin explicitly trusts the 'null' origin.")
            if credential_exposure == CredentialExposureBehavior.CREDENTIALS_EXPOSED:
                policy_risk = "NULL_ORIGIN_CREDENTIALS"
                findings.append("HIGH RISK: 'null' origin trusted with Access-Control-Allow-Credentials: true.")
                observations.append(
                    EvidenceObservation(
                        title="CORS Trusts 'null' Origin with Credentials",
                        category="CORS Behavior",
                        severity=Severity.HIGH,
                        confidence=confidence,
                        observation="Server explicitly permits the 'null' origin while enabling credentials.",
                        evidence=[
                            "Access-Control-Allow-Origin: null",
                            "Access-Control-Allow-Credentials: true",
                        ],
                        impact="Sandboxed iframes, local files, and data: URIs can bypass cross-origin restrictions to access authenticated data.",
                        recommendation="Disallow 'null' as a valid CORS origin. Validate against an explicit protocol+domain allowlist.",
                    )
                )
            else:
                policy_risk = "NULL_ORIGIN"
                observations.append(
                    EvidenceObservation(
                        title="CORS Trusts 'null' Origin",
                        category="CORS Behavior",
                        severity=Severity.MEDIUM,
                        confidence=confidence,
                        observation="Server permits the 'null' origin for cross-origin requests.",
                        evidence=["Access-Control-Allow-Origin: null"],
                        impact="Sandboxed iframes and local file contexts may read unauthenticated data.",
                        recommendation="Avoid allowing 'null' in Access-Control-Allow-Origin.",
                    )
                )

        elif origin_trust == OriginTrustBehavior.PUBLIC_WILDCARD:
            findings.append("Wildcard CORS (Access-Control-Allow-Origin: *) allows any public website to read responses.")
            if credential_exposure == CredentialExposureBehavior.CREDENTIALS_EXPOSED:
                policy_risk = "WILDCARD_CREDENTIALS"
                findings.append("Incompatible CORS configuration: Access-Control-Allow-Origin: * combined with credentials=true.")
                observations.append(
                    EvidenceObservation(
                        title="Incompatible Wildcard CORS with Credentials",
                        category="CORS Behavior",
                        severity=Severity.HIGH,
                        confidence=confidence,
                        observation="Server attempts to enable wildcard origin sharing with credentials (rejected by browsers, but signals misconfiguration).",
                        evidence=[
                            "Access-Control-Allow-Origin: *",
                            "Access-Control-Allow-Credentials: true",
                        ],
                        impact="Standard browsers will reject this response, but non-browser clients or custom HTTP stacks may process unsafe data.",
                        recommendation="Specify an exact origin domain allowlist when credentials are required.",
                    )
                )
            else:
                policy_risk = "PUBLIC_WILDCARD"
                observations.append(
                    EvidenceObservation(
                        title="Wildcard Cross-Origin Resource Sharing Allowed (*)",
                        category="CORS Behavior",
                        severity=Severity.LOW,
                        confidence=confidence,
                        observation="Application serves Access-Control-Allow-Origin: *.",
                        evidence=["Access-Control-Allow-Origin: *"],
                        impact="Appropriate for public static assets or open APIs, but unsafe if endpoint processes sensitive or personalized data.",
                        recommendation="Ensure wildcard CORS is restricted strictly to non-sensitive public endpoints.",
                    )
                )

        elif origin_trust == OriginTrustBehavior.RESTRICTED_SPECIFIC_ORIGIN:
            policy_risk = "RESTRICTED_ORIGIN"
            findings.append(f"CORS Policy restricts access to specific origin: '{acao}'.")

        # Additional Preflight & Header Findings
        if preflight_behavior == PreflightBehavior.PREFLIGHT_PERMISSIVE_WILDCARD:
            findings.append("Preflight allows wildcard methods/headers (*).")
            observations.append(
                EvidenceObservation(
                    title="Permissive CORS Preflight Wildcard Methods/Headers",
                    category="CORS Behavior",
                    severity=Severity.LOW,
                    confidence=confidence,
                    observation="CORS preflight exposes wildcard '*' in allowed headers or methods.",
                    evidence=[
                        f"Allow-Methods: {', '.join(acam) if acam else 'Unspecified'}",
                        f"Allow-Headers: {', '.join(acah) if acah else 'Unspecified'}",
                    ],
                    impact="Permits arbitrary headers and methods in preflight validation.",
                    recommendation="Explicitly list required headers and HTTP methods.",
                )
            )

        if max_age is not None and max_age > 86400:
            findings.append(f"Excessive Access-Control-Max-Age cache duration: {max_age}s (> 24h).")

        # -------------------------------------------------------------
        # STEP 4: Numerical Risk Scoring (Rules-Based)
        # -------------------------------------------------------------
        score, status = self._calculate_score(
            origin_trust=origin_trust,
            credential_exposure=credential_exposure,
            preflight_behavior=preflight_behavior,
            max_age=max_age,
        )

        profile = CORSProfile(
            score=score,
            status=status,
            access_control_allow_origin=acao,
            access_control_allow_credentials=acac,
            access_control_allow_methods=acam,
            access_control_allow_headers=acah,
            is_wildcard=is_wildcard,
            is_null_origin_allowed=is_null,
            is_origin_reflected=is_reflected,
            policy_risk=policy_risk,
            findings=findings,
            behavior=behavior,
            confidence=confidence,
            confidence_reason=confidence_reason,
        )

        return profile, observations

    def _calculate_dynamic_confidence(
        self,
        has_headers: bool,
        has_acao: bool,
        has_acac: bool,
        has_probe_response: bool,
        has_options_probe: bool,
        has_verified_response: bool,
        origin_trust: OriginTrustBehavior,
    ) -> Tuple[int, str]:
        """Calculates dynamic confidence based on factual telemetry completeness."""
        if origin_trust == OriginTrustBehavior.UNKNOWN:
            return 0, "No CORS or HTTP telemetry observed"

        score = 50  # Base for observed response

        if has_verified_response:
            score += 20
        if has_headers:
            score += 10
        if has_acao:
            score += 10
        if has_acac:
            score += 5
        if has_probe_response:
            score += 5
        if has_options_probe:
            score += 5

        confidence = max(20, min(100, score))
        reason = f"Calculated from verified HTTP response (CORS headers={has_headers}, Origin probe={has_probe_response}, Options probe={has_options_probe})"
        return confidence, reason

    def _calculate_score(
        self,
        origin_trust: OriginTrustBehavior,
        credential_exposure: CredentialExposureBehavior,
        preflight_behavior: PreflightBehavior,
        max_age: Optional[int],
    ) -> Tuple[int, BehaviorStatus]:
        """Computes deterministic numerical score and behavior status from rules."""
        if origin_trust == OriginTrustBehavior.UNKNOWN:
            return 0, BehaviorStatus.INCONSISTENT

        deductions = 0

        # Origin & Credential Deductions
        if origin_trust == OriginTrustBehavior.REFLECTED_ORIGIN:
            if credential_exposure == CredentialExposureBehavior.CREDENTIALS_EXPOSED:
                deductions += CORS_DEDUCTION_REFLECTED_ORIGIN_CREDENTIALS
            else:
                deductions += CORS_DEDUCTION_REFLECTED_ORIGIN
        elif origin_trust == OriginTrustBehavior.NULL_ORIGIN_TRUSTED:
            if credential_exposure == CredentialExposureBehavior.CREDENTIALS_EXPOSED:
                deductions += CORS_DEDUCTION_NULL_ORIGIN_CREDENTIALS
            else:
                deductions += CORS_DEDUCTION_NULL_ORIGIN
        elif origin_trust == OriginTrustBehavior.PUBLIC_WILDCARD:
            if credential_exposure == CredentialExposureBehavior.CREDENTIALS_EXPOSED:
                deductions += CORS_DEDUCTION_WILDCARD_CREDENTIALS
            else:
                deductions += CORS_DEDUCTION_WILDCARD
        elif origin_trust == OriginTrustBehavior.SAME_ORIGIN_ONLY:
            deductions += 0

        # Preflight Wildcard Deductions
        if preflight_behavior == PreflightBehavior.PREFLIGHT_PERMISSIVE_WILDCARD:
            deductions += CORS_DEDUCTION_WILDCARD_HEADERS

        # Cache Max-Age Deductions
        if max_age is not None and max_age > 86400:
            deductions += CORS_DEDUCTION_EXCESSIVE_MAX_AGE

        score = max(0, min(100, 100 - deductions))

        if score >= CORS_STATUS_RESTRICTIVE_THRESHOLD:
            status = BehaviorStatus.RESTRICTIVE
        elif score >= CORS_STATUS_CONSISTENT_THRESHOLD:
            status = BehaviorStatus.CONSISTENT
        elif score >= CORS_STATUS_PERMISSIVE_THRESHOLD:
            status = BehaviorStatus.PERMISSIVE
        elif score >= CORS_STATUS_INCONSISTENT_THRESHOLD:
            status = BehaviorStatus.INCONSISTENT
        else:
            status = BehaviorStatus.RISKY

        return score, status

    def _create_unknown_profile(self, reason: str) -> Tuple[CORSProfile, List[EvidenceObservation]]:
        """Creates an unknown CORS profile when telemetry is missing."""
        profile = CORSProfile(
            score=0,
            status=BehaviorStatus.INCONSISTENT,
            access_control_allow_origin=None,
            access_control_allow_credentials=False,
            access_control_allow_methods=[],
            access_control_allow_headers=[],
            is_wildcard=False,
            is_null_origin_allowed=False,
            is_origin_reflected=False,
            policy_risk="UNKNOWN",
            findings=[reason],
            behavior=CORSBehavior(
                origin_trust=OriginTrustBehavior.UNKNOWN,
                credential_exposure=CredentialExposureBehavior.UNKNOWN,
                preflight_behavior=PreflightBehavior.UNKNOWN,
            ),
            confidence=0,
            confidence_reason=reason,
        )
        return profile, []


# Backward compatibility wrapper
def analyze_cors_policy(
    headers: Optional[Dict[str, str]] = None,
    probe_origin_response: Optional[Dict[str, str]] = None,
    simulated_origin: str = "https://security-profiler.academic-test.org",
) -> Tuple[CORSProfile, List[EvidenceObservation]]:
    """
    Backward-compatible wrapper delegating to CORSAnalyzer.
    """
    analyzer = CORSAnalyzer()
    # Note: If headers is passed as a dict (even empty dict {}), it indicates an observed endpoint response
    return analyzer.analyze_observations(
        cors_headers=headers,
        probe_origin_response=probe_origin_response,
        simulated_origin=simulated_origin,
        has_verified_response=headers is not None,
    )


# ==============================================================================
# MODULE: method_analyzer.py
# ==============================================================================
"""
Security Behavior Profiling Engine - HTTP Method Behavior Analyzer

Analyzes observable and advertised HTTP methods, OPTIONS responses,
and potentially dangerous verb exposure without performing destructive actions.
"""




def _normalize_headers(
    headers: Optional[Dict[str, Any]],
) -> Dict[str, str]:
    """
    Normalize response header names to lowercase.
    """
    if not isinstance(headers, dict):
        return {}

    normalized: Dict[str, str] = {}

    for key, value in headers.items():
        if key is None:
            continue

        normalized[str(key).strip().lower()] = (
            "" if value is None else str(value)
        )

    return normalized


def _parse_methods(header_value: str) -> List[str]:
    """
    Parse a comma-separated HTTP method header into normalized method names.
    """
    if not header_value:
        return []

    methods: List[str] = []

    for method in header_value.split(","):
        normalized = method.strip().upper()

        if normalized and normalized not in methods:
            methods.append(normalized)

    return methods


def _is_trace_response_confirmed(
    trace_probe_response: Dict[str, Any],
) -> bool:
    """
    Determine whether TRACE appears to be actually accepted.

    A successful HTTP 200 response is strong evidence that TRACE is accepted.
    """
    return trace_probe_response.get("status_code", 0) == 200


def analyze_http_methods(
    options_response: Optional[Dict[str, Any]],
    trace_probe_response: Optional[Dict[str, Any]] = None,
) -> Tuple[MethodProfile, List[EvidenceObservation]]:
    """
    Evaluate advertised HTTP methods from Allow/Public headers and safely
    assess TRACE behavior.

    This analyzer performs observation only. It does not execute destructive
    methods such as PUT, DELETE, or CONNECT.
    """
    findings: List[str] = []
    observations: List[EvidenceObservation] = []
    advertised_methods: List[str] = []

    deductions = 0

    trace_enabled = False
    track_enabled = False
    put_delete_advertised = False
    connect_advertised = False
    options_code: Optional[int] = None

    # -------------------------------------------------------------
    # 1. OPTIONS / Allow / Public analysis
    # -------------------------------------------------------------
    if (
        isinstance(options_response, dict)
        and options_response.get("success", False)
    ):
        options_code = options_response.get("status_code")

        headers = _normalize_headers(
            options_response.get("headers")
        )

        allow_header = headers.get("allow")
        public_header = headers.get("public")

        # Prefer Allow when present; otherwise use Public.
        allow_hdr = (
            allow_header
            if allow_header
            else public_header
        )

        if allow_hdr:
            advertised_methods = _parse_methods(
                allow_hdr
            )

            if advertised_methods:
                findings.append(
                    "OPTIONS response returned advertised methods: "
                    f"{', '.join(advertised_methods)}"
                )
            else:
                findings.append(
                    f"OPTIONS response returned HTTP "
                    f"{options_code} with an empty method list."
                )
        else:
            findings.append(
                f"OPTIONS response returned HTTP "
                f"{options_code} with no explicit Allow/Public header."
            )

    # -------------------------------------------------------------
    # 2. Safe TRACE probe
    # -------------------------------------------------------------
    if (
        isinstance(trace_probe_response, dict)
        and trace_probe_response.get("success", False)
    ):
        trace_code = trace_probe_response.get(
            "status_code",
            0,
        )

        if _is_trace_response_confirmed(
            trace_probe_response
        ):
            trace_enabled = True
            deductions += 45

            body_preview = trace_probe_response.get(
                "body_preview",
                "",
            )

            body_length = (
                len(body_preview)
                if isinstance(body_preview, str)
                else 0
            )

            findings.append(
                "DANGEROUS: HTTP TRACE method is enabled "
                "and returns HTTP 200 OK."
            )

            observations.append(
                EvidenceObservation(
                    title="HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
                    category="HTTP Method Security",
                    severity=Severity.HIGH,
                    confidence=98,
                    observation=(
                        "The server accepted an HTTP TRACE request "
                        "and returned HTTP 200 OK. TRACE acceptance "
                        "can increase exposure to Cross-Site Tracing "
                        "(XST) attacks depending on server behavior."
                    ),
                    evidence=[
                        "Probed Method: TRACE",
                        "Response Status: 200 OK",
                        f"Body preview length: {body_length}",
                    ],
                    impact=(
                        "An enabled TRACE method may allow request "
                        "headers to be reflected by the server and "
                        "can increase exposure to Cross-Site Tracing "
                        "attack scenarios."
                    ),
                    recommendation=(
                        "Disable HTTP TRACE and TRACK methods when "
                        "they are not explicitly required by the "
                        "application or infrastructure."
                    ),
                )
            )

        elif trace_code in (
            405,
            501,
            403,
            400,
        ):
            findings.append(
                f"HTTP TRACE safely rejected with HTTP {trace_code}."
            )

        else:
            findings.append(
                f"HTTP TRACE responded with status {trace_code}."
            )

    # -------------------------------------------------------------
    # 3. Advertised dangerous methods
    # -------------------------------------------------------------

    if (
        "TRACE" in advertised_methods
        and not trace_enabled
    ):
        trace_enabled = True
        deductions += 35

        findings.append(
            "HTTP TRACE method is advertised in Allow/Public header."
        )

        observations.append(
            EvidenceObservation(
                title="HTTP TRACE Advertised in Options Header",
                category="HTTP Method Security",
                severity=Severity.HIGH,
                confidence=92,
                observation=(
                    "The server advertises support for HTTP TRACE "
                    "in the Allow/Public header."
                ),
                evidence=[
                    "Allow/Public Header: "
                    f"{', '.join(advertised_methods)}"
                ],
                impact=(
                    "Advertised TRACE support may increase exposure "
                    "to Cross-Site Tracing attack scenarios."
                ),
                recommendation=(
                    "Disable TRACE in server config and remove it "
                    "from the allowed methods list when it is not required."
                ),
            )
        )

    if "TRACK" in advertised_methods:
        track_enabled = True
        deductions += 25

        findings.append(
            "HTTP TRACK diagnostic method is advertised."
        )

    if "CONNECT" in advertised_methods:
        connect_advertised = True
        deductions += 20

        findings.append(
            "HTTP CONNECT tunnel method is advertised "
            "on the observed endpoint."
        )

    if (
        "PUT" in advertised_methods
        or "DELETE" in advertised_methods
    ):
        put_delete_advertised = True
        deductions += 15

        findings.append(
            "State-modifying methods (PUT/DELETE) "
            "are advertised on the observed endpoint."
        )

        observations.append(
            EvidenceObservation(
                title="State-Modifying HTTP Methods Advertised",
                category="HTTP Method Security",
                severity=Severity.LOW,
                confidence=85,
                observation=(
                    "The server advertises PUT and/or DELETE "
                    "methods. Advertisement alone does not prove "
                    "that these methods are exploitable or "
                    "unauthenticated."
                ),
                evidence=[
                    "Advertised methods: "
                    f"{', '.join(advertised_methods)}"
                ],
                impact=(
                    "Exposing state-modifying methods can expand "
                    "the attack surface if authorization controls "
                    "are not correctly enforced."
                ),
                recommendation=(
                    "Restrict methods to those required by the "
                    "application and enforce authentication and "
                    "authorization on state-changing operations."
                ),
            )
        )

    # Keep centralized dangerous-method rules available.
    _ = DANGEROUS_METHODS

    # -------------------------------------------------------------
    # 4. Score
    # -------------------------------------------------------------
    score = max(
        0,
        min(
            100,
            100 - deductions,
        ),
    )

    # -------------------------------------------------------------
    # 5. Behavioral status
    # -------------------------------------------------------------
    if score >= 90 and not trace_enabled:
        status = BehaviorStatus.RESTRICTIVE

    elif score >= 75:
        status = BehaviorStatus.CONSISTENT

    elif score >= 50:
        status = BehaviorStatus.PERMISSIVE

    elif score >= 25:
        status = BehaviorStatus.INCONSISTENT

    else:
        status = BehaviorStatus.RISKY

    # -------------------------------------------------------------
    # 6. Final profile
    # -------------------------------------------------------------
    profile = MethodProfile(
        score=score,
        status=status,
        advertised_methods=advertised_methods,
        options_response_code=options_code,
        trace_enabled=trace_enabled,
        track_enabled=track_enabled,
        put_delete_advertised=put_delete_advertised,
        connect_advertised=connect_advertised,
        findings=findings,
    )

    return profile, observations


# ==============================================================================
# MODULE: disclosure_analyzer.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Information Disclosure Analyzer

Analyzes observable response headers for software banners,
framework footprints, debug metadata, and version disclosure.
"""




_VERSION_REGEX = re.compile(
    r"\b\d+\.\d+(?:\.\d+)?(?:\.\d+)?\b"
)


def _normalize_headers(
    headers: Optional[Dict[str, str]],
) -> Dict[str, str]:
    """
    Normalize header names to lowercase so the analyzer behaves
    consistently regardless of the input header casing.
    """
    if not isinstance(headers, dict):
        return {}

    normalized: Dict[str, str] = {}

    for key, value in headers.items():
        if key is None:
            continue

        normalized[str(key).strip().lower()] = (
            "" if value is None else str(value).strip()
        )

    return normalized


def _contains_version(value: str) -> bool:
    """
    Detect common software/runtime version formats such as:
    2.4
    2.4.41
    7.4.3
    """
    return bool(
        value and _VERSION_REGEX.search(value)
    )


def analyze_information_disclosure(
    headers: Optional[Dict[str, str]],
) -> Tuple[DisclosureProfile, List[EvidenceObservation]]:
    """
    Evaluate response headers for:

    - Web server banner disclosure
    - Runtime/framework disclosure
    - Precise software versions
    - Diagnostic/debug metadata

    This function is observation-only and does not perform active probing.
    """
    normalized_headers = _normalize_headers(headers)

    findings: List[str] = []
    observations: List[EvidenceObservation] = []
    deductions = 0

    server_banner = normalized_headers.get("server") or None
    x_powered_by = normalized_headers.get("x-powered-by") or None

    framework_headers: Dict[str, str] = {}
    detailed_versions: List[str] = []
    debug_headers: List[str] = []

    # -------------------------------------------------------------
    # 1. Server header
    # -------------------------------------------------------------
    if server_banner:
        findings.append(
            f"Server header observed: '{server_banner}'"
        )

        if _contains_version(server_banner):
            detailed_versions.append(
                f"Server: {server_banner}"
            )

            deductions += 25

            observations.append(
                EvidenceObservation(
                    title="Detailed Web Server Version Disclosed",
                    category="Information Disclosure",
                    severity=Severity.MEDIUM,
                    confidence=95,
                    observation=(
                        "Server header exposes software and "
                        f"version information: '{server_banner}'."
                    ),
                    evidence=[
                        f"Server: {server_banner}"
                    ],
                    impact=(
                        "Enables threat actors to fingerprint "
                        "specific software versions and identify "
                        "potential version-specific vulnerabilities."
                    ),
                    recommendation=(
                        "Configure the web server to suppress or "
                        "genericize the Server banner, for example "
                        "'ServerTokens Prod' in Apache or "
                        "'server_tokens off;' in Nginx."
                    ),
                )
            )

        else:
            deductions += 5

            findings.append(
                "Server header is generic "
                "(vendor disclosed, version hidden)."
            )

    else:
        findings.append(
            "Server banner is masked or absent (Good practice)."
        )

    # -------------------------------------------------------------
    # 2. X-Powered-By header
    # -------------------------------------------------------------
    if x_powered_by:
        findings.append(
            f"X-Powered-By header observed: '{x_powered_by}'"
        )

        if _contains_version(x_powered_by):
            detailed_versions.append(
                f"X-Powered-By: {x_powered_by}"
            )

            deductions += 30

            observations.append(
                EvidenceObservation(
                    title=(
                        "Runtime Technology Version Disclosed "
                        "(X-Powered-By)"
                    ),
                    category="Information Disclosure",
                    severity=Severity.MEDIUM,
                    confidence=98,
                    observation=(
                        "X-Powered-By reveals active runtime or "
                        f"framework version: '{x_powered_by}'."
                    ),
                    evidence=[
                        f"X-Powered-By: {x_powered_by}"
                    ],
                    impact=(
                        "Assists attackers in fingerprinting backend "
                        "runtime technologies and targeting known "
                        "framework vulnerabilities."
                    ),
                    recommendation=(
                        "Disable X-Powered-By emission in production "
                        "application middleware."
                    ),
                )
            )

        else:
            deductions += 15

            observations.append(
                EvidenceObservation(
                    title="Technology Framework Disclosed in Headers",
                    category="Information Disclosure",
                    severity=Severity.LOW,
                    confidence=90,
                    observation=(
                        "X-Powered-By exposes technology stack: "
                        f"'{x_powered_by}'."
                    ),
                    evidence=[
                        f"X-Powered-By: {x_powered_by}"
                    ],
                    impact=(
                        "Reduces attacker reconnaissance effort by "
                        "confirming the framework or runtime family."
                    ),
                    recommendation=(
                        "Remove the X-Powered-By header across "
                        "production environments."
                    ),
                )
            )

    # -------------------------------------------------------------
    # 3. Other disclosure / diagnostic headers
    # -------------------------------------------------------------
    for hdr_name, desc in DISCLOSURE_HEADERS.items():

        normalized_hdr_name = hdr_name.lower()

        if normalized_hdr_name in (
            "server",
            "x-powered-by",
        ):
            continue

        val = normalized_headers.get(
            normalized_hdr_name
        )

        if not val:
            continue

        framework_headers[
            normalized_hdr_name
        ] = val

        if (
            "debug" in normalized_hdr_name
            or "token" in normalized_hdr_name
        ):
            debug_headers.append(
                f"{normalized_hdr_name}: {val}"
            )

            deductions += 35

            observations.append(
                EvidenceObservation(
                    title=(
                        "Diagnostic / Debug Header Leaked "
                        f"({normalized_hdr_name})"
                    ),
                    category="Information Disclosure",
                    severity=Severity.HIGH,
                    confidence=96,
                    observation=(
                        "Endpoint exposes internal diagnostic "
                        f"metadata header '{normalized_hdr_name}'."
                    ),
                    evidence=[
                        f"{normalized_hdr_name}: {val}"
                    ],
                    impact=(
                        "May expose internal diagnostic identifiers, "
                        "debug information, or profiler metadata "
                        "to external clients."
                    ),
                    recommendation=(
                        f"Remove '{normalized_hdr_name}' from "
                        "production responses."
                    ),
                )
            )

        else:
            deductions += 10

            findings.append(
                f"Disclosure header '{normalized_hdr_name}' "
                f"detected ({desc}): {val}"
            )

    # -------------------------------------------------------------
    # 4. Final score
    # -------------------------------------------------------------
    score = max(
        0,
        min(
            100,
            100 - deductions,
        ),
    )

    # -------------------------------------------------------------
    # 5. Behavioral status
    # -------------------------------------------------------------
    if score >= 90:
        status = BehaviorStatus.RESTRICTIVE

    elif score >= 75:
        status = BehaviorStatus.CONSISTENT

    elif score >= 50:
        status = BehaviorStatus.PERMISSIVE

    elif score >= 25:
        status = BehaviorStatus.INCONSISTENT

    else:
        status = BehaviorStatus.RISKY

    # -------------------------------------------------------------
    # 6. Final profile
    # -------------------------------------------------------------
    profile = DisclosureProfile(
        score=score,
        status=status,
        server_banner=server_banner,
        x_powered_by=x_powered_by,
        framework_headers=framework_headers,
        detailed_versions_exposed=detailed_versions,
        debug_headers_detected=debug_headers,
        findings=findings,
    )

    return profile, observations


# ==============================================================================
# MODULE: anomaly_detector.py
# ==============================================================================
class AnomalyDetector:
    def detect_anomalies(
        self,
        transport: TransportProfile,
        redirect: RedirectProfile,
        cookie: CookieProfile,
        cors: CORSProfile,
        method: MethodProfile,
        disclosure: DisclosureProfile,
    ) -> List[BehavioralAnomaly]:
        anomalies: List[BehavioralAnomaly] = []

        if (
            transport.http_accessible
            and not transport.enforces_https
            and transport.https_accessible
        ):
            anomalies.append(
                BehavioralAnomaly(
                    title="Inconsistent HTTPS Enforcement Anomaly",
                    category="Transport Security",
                    classification=AnomalyClassification.HIGH_RISK_BEHAVIOR,
                    description="The server supports full HTTPS encryption but continues to serve direct cleartext HTTP 200 responses on port 80 without mandatory upgrading.",
                    evidence=[
                        f"HTTP Accessible: {transport.http_accessible}",
                        f"HTTPS Accessible: {transport.https_accessible}",
                        f"Enforces HTTPS: {transport.enforces_https}",
                        f"HTTP Status: {transport.http_redirect_code or 200}",
                    ],
                    severity=Severity.HIGH,
                    affected_domains=[
                        "transport_security",
                        "redirect_behavior",
                    ],
                )
            )

        elif transport.enforces_https and not transport.hsts_present:
            anomalies.append(
                BehavioralAnomaly(
                    title="HTTPS Enforced Without HSTS Policy Memory",
                    category="Transport Security",
                    classification=AnomalyClassification.WARNING,
                    description="The application redirects cleartext traffic to HTTPS but fails to emit Strict-Transport-Security, requiring continuous server-side redirects on every initial visit.",
                    evidence=[
                        "Enforces HTTPS: True",
                        "HSTS Header Present: False",
                    ],
                    severity=Severity.MEDIUM,
                    affected_domains=["transport_security"],
                )
            )

        if redirect.has_downgrade:
            anomalies.append(
                BehavioralAnomaly(
                    title="Protocol Downgrade Anomaly in Redirect Routing",
                    category="Redirect Behavior",
                    classification=AnomalyClassification.HIGH_RISK_BEHAVIOR,
                    description="Redirect execution drops from an encrypted TLS channel (HTTPS) to an unencrypted cleartext channel (HTTP).",
                    evidence=[
                        f"Pattern: {redirect.pattern_classification}",
                        "Downgrade Detected: True",
                        f"Total Hops: {redirect.total_hops}",
                    ],
                    severity=Severity.CRITICAL,
                    affected_domains=[
                        "redirect_behavior",
                        "transport_security",
                    ],
                )
            )

        elif redirect.is_circular:
            anomalies.append(
                BehavioralAnomaly(
                    title="Cyclic Routing Anomaly",
                    category="Redirect Behavior",
                    classification=AnomalyClassification.ANOMALY,
                    description="Redirect chain enters a self-referential or infinite cycle.",
                    evidence=[
                        "Circular Loop: True",
                        f"Chain length before abort: {redirect.total_hops}",
                    ],
                    severity=Severity.HIGH,
                    affected_domains=["redirect_behavior"],
                )
            )

        if cookie.inconsistent_attributes:
            anomalies.append(
                BehavioralAnomaly(
                    title="Cookie Security Flag Inconsistency",
                    category="Cookie Security",
                    classification=AnomalyClassification.ANOMALY,
                    description="Multiple cookies issued by the application exhibit conflicting security postures.",
                    evidence=cookie.inconsistent_attributes
                    + [f"Total Cookies: {cookie.total_cookies}"],
                    severity=Severity.MEDIUM,
                    affected_domains=["cookie_behavior"],
                )
            )

        insecure_sensitive = [
            c.name
            for c in cookie.cookies_analyzed
            if c.is_sensitive and not c.secure
        ]

        if insecure_sensitive:
            anomalies.append(
                BehavioralAnomaly(
                    title="Session State Issued Without Cryptographic Binding",
                    category="Cookie Security",
                    classification=AnomalyClassification.HIGH_RISK_BEHAVIOR,
                    description=f"Identified {len(insecure_sensitive)} sensitive/session cookie(s) lacking the 'Secure' attribute flag.",
                    evidence=[
                        f"Insecure Sensitive Cookies: {', '.join(insecure_sensitive)}"
                    ],
                    severity=Severity.HIGH,
                    affected_domains=[
                        "cookie_behavior",
                        "transport_security",
                    ],
                )
            )

        if (
            cors.is_origin_reflected or cors.is_null_origin_allowed
        ) and cors.access_control_allow_credentials:
            anomalies.append(
                BehavioralAnomaly(
                    title="Cross-Origin Security Boundary Collapse",
                    category="CORS Behavior",
                    classification=AnomalyClassification.HIGH_RISK_BEHAVIOR,
                    description="CORS policy dynamically mirrors untrusted origins while explicitly enabling credentialed request transmission.",
                    evidence=[
                        f"Origin Reflected: {cors.is_origin_reflected}",
                        f"Null Origin Allowed: {cors.is_null_origin_allowed}",
                        f"Allow-Credentials: {cors.access_control_allow_credentials}",
                    ],
                    severity=Severity.CRITICAL,
                    affected_domains=["cors_behavior"],
                )
            )

        if method.trace_enabled:
            anomalies.append(
                BehavioralAnomaly(
                    title="Legacy Debugging Verb Exposed in Active Profile",
                    category="HTTP Method Security",
                    classification=AnomalyClassification.HIGH_RISK_BEHAVIOR,
                    description="HTTP TRACE method is active and echoing payloads, exposing the application to Cross-Site Tracing.",
                    evidence=[
                        "HTTP TRACE Enabled: True",
                        f"Options Code: {method.options_response_code}",
                    ],
                    severity=Severity.HIGH,
                    affected_domains=["http_method_behavior"],
                )
            )

        if (
            disclosure.detailed_versions_exposed
            and disclosure.debug_headers_detected
        ):
            anomalies.append(
                BehavioralAnomaly(
                    title="Verbose Infrastructure Fingerprinting & Debug Leak",
                    category="Information Disclosure",
                    classification=AnomalyClassification.ANOMALY,
                    description="Response exposes both exact patch-level software versions and internal diagnostic debug headers.",
                    evidence=(
                        disclosure.detailed_versions_exposed
                        + disclosure.debug_headers_detected
                    ),
                    severity=Severity.MEDIUM,
                    affected_domains=["information_disclosure"],
                )
            )

        return anomalies


# ==============================================================================
# MODULE: correlation_engine.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Behavioral Correlation Engine

Correlates independent security observations across multiple domains
into actionable compound security risks.

The correlation layer is intentionally evidence-driven:
a correlation is emitted only when the underlying behavioral conditions
are actually present.
"""




class CorrelationEngine:
    """
    Synthesizes cross-domain observations into compound behavioral risks.

    Important design principle:
    - Secure and HttpOnly are treated as separate controls.
    - Generic cookies are not treated as session credentials.
    - Correlations require concrete evidence from the analyzed profiles.
    """

    def correlate(
        self,
        transport: TransportProfile,
        redirect: RedirectProfile,
        cookie: CookieProfile,
        cors: CORSProfile,
        method: MethodProfile,
        disclosure: DisclosureProfile,
        observations: List[EvidenceObservation],
    ) -> List[CorrelatedRisk]:

        correlated: List[CorrelatedRisk] = []

        # -------------------------------------------------------------
        # Derived cookie evidence
        # -------------------------------------------------------------

        insecure_sensitive_cookies = [
            c.name
            for c in cookie.cookies_analyzed
            if c.is_sensitive and not c.secure
        ]

        non_httponly_sensitive = [
            c.name
            for c in cookie.cookies_analyzed
            if c.is_sensitive and not c.httponly
        ]

        sensitive_cookie_names = [
            c.name
            for c in cookie.cookies_analyzed
            if c.is_sensitive
        ]

        # -------------------------------------------------------------
        # CORRELATION 1
        # Transport & Session Security Breakdown
        #
        # Cleartext HTTP + no HTTPS enforcement +
        # sensitive authentication/session cookies without Secure.
        # -------------------------------------------------------------

        if (
            transport.http_accessible
            and not transport.enforces_https
            and insecure_sensitive_cookies
        ):
            correlated.append(
                CorrelatedRisk(
                    rule_id="CORR-TRANS-SESS-01",
                    title="Transport & Session Security Behavior Breakdown",
                    primary_domains=[
                        "Transport Security",
                        "Cookie Security",
                    ],
                    severity=Severity.HIGH,
                    confidence=96,
                    combined_mechanism=(
                        "The application accepts cleartext HTTP connections "
                        "without mandatory HTTPS enforcement while also "
                        "issuing sensitive session or authentication cookies "
                        "without the 'Secure' attribute. These conditions "
                        "combine to create a direct opportunity for sensitive "
                        "cookie values to cross an unencrypted transport path."
                    ),
                    trigger_observations=[
                        "Cleartext HTTP is accessible without mandatory HTTPS enforcement",
                        (
                            "Sensitive cookies missing Secure flag: "
                            + ", ".join(insecure_sensitive_cookies)
                        ),
                    ],
                    evidence=[
                        (
                            "Transport: "
                            f"HTTP accessible = {transport.http_accessible}, "
                            f"Enforces HTTPS = {transport.enforces_https}"
                        ),
                        (
                            "Sensitive cookies lacking Secure: "
                            f"{insecure_sensitive_cookies}"
                        ),
                    ],
                    impact=(
                        "Session tokens may be exposed to passive network "
                        "observation or active transport downgrade attacks, "
                        "potentially enabling session hijacking."
                    ),
                    recommendation=(
                        "1. Configure mandatory HTTP-to-HTTPS redirection "
                        "using 301 or 308.\n"
                        "2. Mark all authentication and session cookies "
                        "with Secure, HttpOnly, and an appropriate SameSite policy."
                    ),
                )
            )

        # -------------------------------------------------------------
        # CORRELATION 2
        # Permissive Origin Credential Exposure
        #
        # Reflected/null origin + credentials enabled.
        # -------------------------------------------------------------

        if (
            (
                cors.is_origin_reflected
                or cors.is_null_origin_allowed
            )
            and cors.access_control_allow_credentials
        ):
            if cors.is_origin_reflected:
                origin_mechanism = (
                    "The application reflects the requesting Origin while "
                    "also allowing credentialed cross-origin requests."
                )
                origin_trigger = "CORS Origin reflection detected"
            else:
                origin_mechanism = (
                    "The application trusts the special 'null' origin while "
                    "also allowing credentialed cross-origin requests."
                )
                origin_trigger = "CORS 'null' origin trust detected"

            correlated.append(
                CorrelatedRisk(
                    rule_id="CORR-CORS-CRED-02",
                    title="Permissive Origin Credential Exposure (CORS Policy Risk)",
                    primary_domains=[
                        "CORS Behavior",
                        "Cookie Security",
                    ],
                    severity=Severity.CRITICAL,
                    confidence=98,
                    combined_mechanism=(
                        origin_mechanism
                        + " When sensitive browser credentials are "
                        "available, an untrusted external origin may be able "
                        "to issue authenticated cross-origin requests and "
                        "read responses that should remain protected by the "
                        "Same-Origin Policy."
                    ),
                    trigger_observations=[
                        origin_trigger,
                        "Access-Control-Allow-Credentials: true",
                    ],
                    evidence=[
                        (
                            "Access-Control-Allow-Origin: "
                            f"{cors.access_control_allow_origin or 'not explicitly reported'}"
                        ),
                        "Access-Control-Allow-Credentials: true",
                        (
                            "Sensitive session/authentication cookies observed: "
                            f"{cookie.sensitive_cookies_count}"
                        ),
                    ],
                    impact=(
                        "An attacker-controlled website may be able to access "
                        "sensitive authenticated API responses, depending on "
                        "browser credential behavior and the application's "
                        "authentication model."
                    ),
                    recommendation=(
                        "1. Replace dynamic origin reflection with an explicit "
                        "allowlist of trusted origins.\n"
                        "2. Do not trust the 'null' origin when credentials "
                        "are enabled.\n"
                        "3. Enable credentialed CORS only where business "
                        "requirements explicitly require it."
                    ),
                )
            )

        # -------------------------------------------------------------
        # CORRELATION 3
        # Attack Surface & Method Exploitation Amplification
        #
        # Detailed software disclosure + TRACE or state-modifying methods.
        # -------------------------------------------------------------

        if (
            disclosure.detailed_versions_exposed
            and (
                method.trace_enabled
                or method.put_delete_advertised
            )
        ):
            correlated.append(
                CorrelatedRisk(
                    rule_id="CORR-DISC-METH-03",
                    title="Attack Surface & Method Exploitation Amplification",
                    primary_domains=[
                        "Information Disclosure",
                        "HTTP Method Security",
                    ],
                    severity=Severity.HIGH,
                    confidence=90,
                    combined_mechanism=(
                        "The application exposes detailed software or "
                        "framework version information while also exposing "
                        "extended or state-affecting HTTP methods. Version "
                        "disclosure can reduce attacker reconnaissance effort "
                        "while the additional method surface may provide "
                        "more opportunities for targeted exploitation."
                    ),
                    trigger_observations=[
                        (
                            "Detailed version banners: "
                            + ", ".join(
                                disclosure.detailed_versions_exposed
                            )
                        ),
                        (
                            "TRACE enabled: "
                            f"{method.trace_enabled}"
                        ),
                        (
                            "State-modifying methods advertised: "
                            f"{method.put_delete_advertised}"
                        ),
                    ],
                    evidence=[
                        (
                            "Exposed versions: "
                            f"{disclosure.detailed_versions_exposed}"
                        ),
                        (
                            "Advertised methods: "
                            f"{method.advertised_methods}"
                        ),
                        (
                            "TRACE active: "
                            f"{method.trace_enabled}"
                        ),
                    ],
                    impact=(
                        "Detailed technology disclosure can accelerate "
                        "targeted reconnaissance, while unnecessary HTTP "
                        "methods increase the exposed attack surface."
                    ),
                    recommendation=(
                        "1. Remove unnecessary software and framework "
                        "version banners.\n"
                        "2. Disable TRACE and other unnecessary diagnostic "
                        "methods.\n"
                        "3. Restrict state-modifying methods to authenticated "
                        "and authorized operations."
                    ),
                )
            )

        # -------------------------------------------------------------
        # CORRELATION 4
        # Protocol Downgrade with Sensitive Transit State
        #
        # HTTPS -> HTTP downgrade + sensitive session/auth cookies.
        #
        # IMPORTANT:
        # Generic cookies alone are NOT sufficient evidence.
        # -------------------------------------------------------------

        if (
            redirect.has_downgrade
            and sensitive_cookie_names
        ):
            correlated.append(
                CorrelatedRisk(
                    rule_id="CORR-DOWN-SESS-04",
                    title="Insecure Transit & Session State Exposure in Downgrade Flow",
                    primary_domains=[
                        "Redirect Behavior",
                        "Cookie Security",
                    ],
                    severity=Severity.CRITICAL,
                    confidence=96,
                    combined_mechanism=(
                        "The redirect sequence contains an HTTPS-to-HTTP "
                        "protocol downgrade while sensitive session or "
                        "authentication cookies are present. The cleartext "
                        "hop creates a transport path where session state "
                        "may be exposed if the affected cookies are permitted "
                        "on HTTP requests."
                    ),
                    trigger_observations=[
                        "HTTPS -> HTTP downgrade hop detected",
                        (
                            "Sensitive session/authentication cookies observed: "
                            + ", ".join(sensitive_cookie_names)
                        ),
                    ],
                    evidence=[
                        (
                            "Redirect pattern: "
                            f"{redirect.pattern_classification}"
                        ),
                        (
                            "Sensitive cookies observed: "
                            f"{sensitive_cookie_names}"
                        ),
                        (
                            "Sensitive cookies without Secure: "
                            f"{insecure_sensitive_cookies}"
                        ),
                    ],
                    impact=(
                        "A downgrade path can expose session state to active "
                        "network attackers and may enable session interception "
                        "when sensitive cookies are not cryptographically "
                        "bound to HTTPS."
                    ),
                    recommendation=(
                        "Eliminate all HTTPS-to-HTTP downgrade hops and ensure "
                        "every intermediate redirect remains on HTTPS. "
                        "Authentication cookies should also use the Secure flag."
                    ),
                )
            )

        # -------------------------------------------------------------
        # CORRELATION 5
        # Weak Transport Defense-in-Depth
        #
        # Missing HSTS + no HTTPS enforcement +
        # sensitive cookies accessible to JavaScript.
        #
        # Secure and HttpOnly intentionally remain separate controls.
        # -------------------------------------------------------------

        if (
            not transport.hsts_present
            and not transport.enforces_https
            and non_httponly_sensitive
        ):
            correlated.append(
                CorrelatedRisk(
                    rule_id="CORR-DEFENSE-DEPTH-05",
                    title="Absence of Defense-in-Depth Controls",
                    primary_domains=[
                        "Transport Security",
                        "Cookie Security",
                    ],
                    severity=Severity.HIGH,
                    confidence=94,
                    combined_mechanism=(
                        "The application lacks multiple independent security "
                        "controls: HSTS is absent, HTTP is not forced to HTTPS, "
                        "and sensitive session cookies are accessible to "
                        "client-side JavaScript because HttpOnly is missing. "
                        "These weaknesses reduce resilience against both "
                        "transport-layer interception and client-side attacks."
                    ),
                    trigger_observations=[
                        "HSTS header absent",
                        "HTTP does not enforce HTTPS",
                        (
                            "Sensitive cookies without HttpOnly: "
                            + ", ".join(non_httponly_sensitive)
                        ),
                    ],
                    evidence=[
                        f"HSTS Present: {transport.hsts_present}",
                        f"HTTPS Enforcement: {transport.enforces_https}",
                        (
                            "Sensitive cookies without HttpOnly: "
                            f"{non_httponly_sensitive}"
                        ),
                    ],
                    impact=(
                        "The application has reduced defense-in-depth: "
                        "network-layer and client-side weaknesses can "
                        "compound rather than being mitigated by independent "
                        "security controls."
                    ),
                    recommendation=(
                        "1. Deploy HSTS with max-age >= 31536000.\n"
                        "2. Enforce HTTP-to-HTTPS redirects.\n"
                        "3. Mark authentication and session cookies as HttpOnly "
                        "where client-side JavaScript access is not required."
                    ),
                )
            )

        return correlated


# ==============================================================================
# MODULE: scoring_engine.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Scoring Engine

Calculates:
- Weighted 0-100 domain score
- Controlled compound-risk adjustment
- Risk level classification
- Behavioral consistency classification

Design principle:
Domain analyzers already account for individual security weaknesses.
The scoring engine therefore avoids heavy double-counting of the same
weaknesses through anomaly/correlation penalties.
"""




class ScoringEngine:
    """
    Computes the final Security Behavior Score.

    The domain scores are the primary quantitative signal.
    Anomalies and correlated risks provide limited contextual penalties
    so the same underlying weakness is not counted multiple times.
    """

    def __init__(
        self,
        domain_weights: Optional[Dict[str, float]] = None,
        risk_thresholds=None,
    ):
        self.domain_weights = (
            domain_weights
            if domain_weights is not None
            else DOMAIN_WEIGHTS
        )

        self.risk_thresholds = (
            risk_thresholds
            if risk_thresholds is not None
            else RISK_THRESHOLDS
        )

    # ---------------------------------------------------------
    # Base score
    # ---------------------------------------------------------

    def _calculate_base_score(
        self,
        domain_scores: Dict[str, int],
    ) -> float:
        """
        Calculate weighted domain score.

        All configured domains must be explicitly supplied. Treating a
        missing domain as 100 would silently inflate the overall score and
        conflate "not assessed" with "secure".
        """

        expected_domains = set(self.domain_weights)
        provided_domains = set(domain_scores)
        missing_domains = expected_domains - provided_domains

        if missing_domains:
            missing = ", ".join(sorted(missing_domains))
            raise ValueError(
                "Incomplete domain score set; missing: " + missing
            )

        base_score = 0.0

        for domain, weight in self.domain_weights.items():
            score = domain_scores[domain]

            score = max(
                0,
                min(100, int(score)),
            )

            base_score += score * weight

        return base_score

    # ---------------------------------------------------------
    # Controlled compound-risk penalty
    # ---------------------------------------------------------

    def _calculate_risk_penalty(
        self,
        anomalies: List[BehavioralAnomaly],
        correlated_risks: List[CorrelatedRisk],
    ) -> float:
        """
        Apply a deliberately small contextual penalty.

        Individual domain weaknesses have already been reflected
        in the domain scores.

        Therefore:
            - correlated risks receive small compound penalties
            - anomalies receive very small contextual penalties
            - total penalty is capped

        This prevents double-counting.
        """

        correlation_penalty = 0.0

        for risk in correlated_risks:
            if risk.severity == Severity.CRITICAL:
                correlation_penalty += 4.0

            elif risk.severity == Severity.HIGH:
                correlation_penalty += 3.0

            elif risk.severity == Severity.MEDIUM:
                correlation_penalty += 2.0

            elif risk.severity == Severity.LOW:
                correlation_penalty += 1.0

        # Compound risks should not dominate the domain score.
        correlation_penalty = min(
            correlation_penalty,
            8.0,
        )

        anomaly_penalty = 0.0

        for anomaly in anomalies:
            if anomaly.severity == Severity.CRITICAL:
                anomaly_penalty += 2.0

            elif anomaly.severity == Severity.HIGH:
                anomaly_penalty += 1.5

            elif anomaly.severity == Severity.MEDIUM:
                anomaly_penalty += 1.0

            elif anomaly.severity == Severity.LOW:
                anomaly_penalty += 0.5

        # Prevent anomaly count from overwhelming the actual
        # measured domain scores.
        anomaly_penalty = min(
            anomaly_penalty,
            6.0,
        )

        return correlation_penalty + anomaly_penalty

    # ---------------------------------------------------------
    # Risk classification
    # ---------------------------------------------------------

    def _classify_risk(
        self,
        score: int,
    ) -> RiskLevel:
        """
        Map final score to the configured risk thresholds.
        """

        for threshold, level in self.risk_thresholds:
            if score >= threshold:
                return level

        return RiskLevel.CRITICAL

    # ---------------------------------------------------------
    # Consistency classification
    # ---------------------------------------------------------

    def _classify_consistency(
        self,
        anomalies: List[BehavioralAnomaly],
        correlated_risks: List[CorrelatedRisk],
    ) -> ConsistencyLevel:
        """
        Determine behavioral consistency.

        CRITICAL_INCONSISTENCY represents strong evidence that multiple
        behavioral signals combine into a systemic or high-impact
        inconsistency.

        The classification considers:
            - number of anomalies
            - severity of anomalies
            - number/severity of correlated risks
            - combination of independent anomaly and correlation signals

        A single critical correlation alone is not enough.
        """

        anomaly_count = len(anomalies)

        critical_anomalies = sum(
            1
            for anomaly in anomalies
            if anomaly.severity == Severity.CRITICAL
        )

        high_risk_anomalies = sum(
            1
            for anomaly in anomalies
            if anomaly.severity == Severity.HIGH
        )

        critical_correlations = sum(
            1
            for risk in correlated_risks
            if risk.severity == Severity.CRITICAL
        )

        high_risk_correlations = sum(
            1
            for risk in correlated_risks
            if risk.severity == Severity.HIGH
        )

        # -----------------------------------------------------
        # Critical inconsistency
        # -----------------------------------------------------
        #
        # Strong systemic evidence can come from:
        #
        # 1. Many anomalies
        # 2. Multiple critical anomalies
        # 3. Multiple critical correlations + anomalies
        # 4. A critical correlation combined with several
        #    independent anomalies
        # 5. A critical anomaly combined with a critical
        #    correlation and additional behavioral deviations
        #
        if (
            anomaly_count >= 5
            or critical_anomalies >= 2
            or (
                critical_correlations >= 2
                and anomaly_count >= 3
            )
            or (
                critical_correlations >= 1
                and anomaly_count >= 3
                and (
                    critical_anomalies >= 1
                    or high_risk_anomalies >= 1
                )
            )
        ):
            return ConsistencyLevel.CRITICAL_INCONSISTENCY

        # -----------------------------------------------------
        # Low consistency
        # -----------------------------------------------------
        #
        # Multiple independent deviations or a serious
        # correlation pattern indicate weak consistency.
        #
        if (
            anomaly_count >= 3
            or high_risk_anomalies >= 2
            or critical_correlations >= 1
            or high_risk_correlations >= 2
        ):
            return ConsistencyLevel.LOW

        # -----------------------------------------------------
        # Moderate consistency
        # -----------------------------------------------------

        if anomaly_count >= 1:
            return ConsistencyLevel.MODERATE

        # -----------------------------------------------------
        # High consistency
        # -----------------------------------------------------

        return ConsistencyLevel.HIGH

    # ---------------------------------------------------------
    # Main calculation
    # ---------------------------------------------------------

    def calculate_overall_score(
        self,
        domain_scores: Dict[str, int],
        anomalies: List[BehavioralAnomaly],
        correlated_risks: List[CorrelatedRisk],
    ) -> OverallAssessment:
        """
        Calculate the final Security Behavior Assessment.

        Formula:

            Base Score
                = Σ(domain_score × domain_weight)

            Final Score
                = Base Score
                  - controlled compound-risk penalty

        Domain scores remain the dominant signal.
        """

        # -----------------------------------------------------
        # 1. Weighted domain score
        # -----------------------------------------------------

        base_score = self._calculate_base_score(
            domain_scores
        )

        # -----------------------------------------------------
        # 2. Controlled contextual penalty
        # -----------------------------------------------------

        contextual_penalty = self._calculate_risk_penalty(
            anomalies=anomalies,
            correlated_risks=correlated_risks,
        )

        # -----------------------------------------------------
        # 3. Final score
        # -----------------------------------------------------

        raw_final = (
            base_score
            - contextual_penalty
        )

        final_score = int(
            max(
                0,
                min(
                    100,
                    round(raw_final),
                ),
            )
        )

        # -----------------------------------------------------
        # 4. Risk classification
        # -----------------------------------------------------

        risk_level = self._classify_risk(
            final_score
        )

        # -----------------------------------------------------
        # 5. Behavioral consistency
        # -----------------------------------------------------

        consistency = self._classify_consistency(
            anomalies=anomalies,
            correlated_risks=correlated_risks,
        )

        # -----------------------------------------------------
        # 6. Executive summary
        # -----------------------------------------------------

        summary = (
            f"Overall Security Behavior Score is "
            f"{final_score}/100 ({risk_level.value}). "
            f"Behavioral consistency is rated "
            f"{consistency.value} with "
            f"{len(anomalies)} anomaly(ies) and "
            f"{len(correlated_risks)} high-risk correlation "
            f"pattern(s) identified."
        )

        return OverallAssessment(
            score=final_score,
            risk_level=risk_level,
            behavioral_consistency=consistency,
            anomalies_count=len(anomalies),
            correlated_risks_count=len(correlated_risks),
            summary=summary,
        )


# ==============================================================================
# MODULE: profiler.py
# ==============================================================================
class SecurityBehaviorProfiler:
    """
    Main orchestration layer for the Security Behavior Profiling Engine.

    Supports:
      - Live target profiling
      - Mock/academic scenario profiling
      - Unified report generation
    """

    def __init__(
        self,
        timeout: float = 6.0,
        verify_ssl: bool = True,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self.probe = SafeHttpProbe(
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

        self.anomaly_detector = AnomalyDetector()
        self.correlation_engine = CorrelationEngine()
        self.scoring_engine = ScoringEngine()

    def profile(self, target: str) -> SecurityBehaviorReport:
        """
        Profile a real HTTP/HTTPS target.
        """

        started = perf_counter()

        normalized_url, scheme, host, port = (
            normalize_and_validate_url(target)
        )

        http_url = f"http://{host}"

        if scheme == "http" and port != 80:
            http_url += f":{port}"

        https_url = f"https://{host}"

        if scheme == "https" and port != 443:
            https_url += f":{port}"

        redirect_chain, final_response = (
            self.probe.trace_redirect_chain(
                target,
                max_hops=8,
            )
        )

        http_probe = self.probe.send_single_request(
            http_url,
            method="GET",
            follow_redirects=False,
        )

        https_probe = self.probe.send_single_request(
            https_url,
            method="GET",
            follow_redirects=False,
        )

        primary_response = (
            final_response
            if final_response
            and final_response.get("success")
            else (
                https_probe
                if https_probe.get("success")
                else http_probe
            )
        )

        headers = (
            primary_response.get("headers", {})
            if primary_response
            else {}
        )

        raw_cookies = (
            primary_response.get("raw_cookies", [])
            if primary_response
            else []
        )

        if http_probe and http_probe.get("raw_cookies"):
            raw_cookies = list(
                set(
                    raw_cookies
                    + http_probe["raw_cookies"]
                )
            )

        return self._build_report(
            target=normalized_url,
            host=host,
            scheme=scheme,
            http_probe=http_probe,
            https_probe=https_probe,
            redirect_chain=redirect_chain,
            headers=headers,
            raw_cookies=raw_cookies,
            started=started,
        )

    def profile_mock(
        self,
        scenario: Dict[str, Any],
    ) -> SecurityBehaviorReport:
        """
        Profile a pre-recorded academic/mock scenario.

        No network requests are made.
        """

        started = perf_counter()

        target = scenario["target"]

        host = scenario.get("host")

        if not host:
            _, _, host, _ = (
                normalize_and_validate_url(target)
            )

        http_probe = scenario.get(
            "http_probe",
            {},
        )

        https_probe = scenario.get(
            "https_probe",
            {},
        )

        # --------------------------------------------------------
        # NORMALIZE MOCK REDIRECTS
        # --------------------------------------------------------

        redirect_chain = [
            step
            if isinstance(step, RedirectStep)
            else RedirectStep(
                step=int(
                    step.get(
                        "step",
                        index + 1,
                    )
                ),
                status_code=int(
                    step.get(
                        "status_code",
                        0,
                    )
                ),
                source_url=str(
                    step.get(
                        "source_url",
                        "",
                    )
                ),
                destination_url=str(
                    step.get(
                        "destination_url",
                        "",
                    )
                ),
                protocol_change=str(
                    step.get(
                        "protocol_change",
                        "UNKNOWN",
                    )
                ),
                host_change=bool(
                    step.get(
                        "host_change",
                        False,
                    )
                ),
                latency_ms=float(
                    step.get(
                        "latency_ms",
                        0.0,
                    )
                ),
            )
            for index, step in enumerate(
                scenario.get(
                    "redirect_chain",
                    [],
                )
            )
        ]

        headers = scenario.get(
            "headers",
            {},
        )

        # --------------------------------------------------------
        # MERGE COOKIES FROM ALL TRANSPORT OBSERVATIONS
        # --------------------------------------------------------
        #
        # Academic scenarios may define cookies separately
        # under HTTP and HTTPS probes.
        #
        # We must preserve both observations so the cookie
        # analyzer can detect inconsistent security attributes.
        #

        raw_cookies = list(
            scenario.get(
                "raw_cookies",
                [],
            )
        )

        http_cookies = http_probe.get(
            "raw_cookies",
            [],
        )

        https_cookies = https_probe.get(
            "raw_cookies",
            [],
        )

        raw_cookies.extend(
            http_cookies
        )

        raw_cookies.extend(
            https_cookies
        )

        # Remove exact duplicate observations while
        # preserving insertion order.
        raw_cookies = list(
            dict.fromkeys(
                raw_cookies
            )
        )

        return self._build_report(
            target=target,
            host=host,
            scheme=(
                "https"
                if target.lower().startswith(
                    "https://"
                )
                else "http"
            ),
            http_probe=http_probe,
            https_probe=https_probe,
            redirect_chain=redirect_chain,
            headers=headers,
            raw_cookies=raw_cookies,
            probe_origin_response=scenario.get(
                "probe_origin_response"
            ),
            options_response=scenario.get(
                "options_response"
            ),
            trace_response=scenario.get(
                "trace_response"
            ),
            started=started,
        )

    def analyze_scan_data(
        self,
        scan_data: Dict[str, Any],
    ) -> SecurityBehaviorReport:
        """
        Analysis-only entry point: takes the already-fetched network data
        produced by http_scanner.capture_network_data() (or embedded under
        run_full_scan()'s "network_capture" key) and runs the full
        behavioral analysis on it. Unlike profile(), this method makes NO
        network requests of its own — http_scanner.py is the only module
        that talks to the network; this one only analyzes what it's given.
        """

        started = perf_counter()

        target = scan_data.get("requested_url") or scan_data.get("final_url")
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or ""
        scheme = parsed.scheme or "https"

        http_probe = scan_data.get("http_probe") or {}
        https_probe = scan_data.get("https_probe") or {}
        main = scan_data.get("main") or {}
        options_response = scan_data.get("options_response") or {}
        trace_response = scan_data.get("trace_response") or {}
        origin_probe = scan_data.get("origin_probe") or {}

        # Always a dict (never None) so _build_report's "if X is None: fetch
        # live" fallback never fires — analyze_scan_data must make zero
        # network calls of its own, even if the origin probe itself failed.
        origin_headers = origin_probe.get("headers", {})

        headers = main.get("headers", {})

        redirect_chain = [
            RedirectStep(
                step=int(hop.get("step", index + 1)),
                status_code=int(hop.get("status_code", 0)),
                source_url=str(hop.get("source_url", "")),
                destination_url=str(hop.get("destination_url", "")),
                protocol_change=str(hop.get("protocol_change", "NONE")),
                host_change=bool(hop.get("host_change", False)),
                latency_ms=float(hop.get("latency_ms", 0.0)),
            )
            for index, hop in enumerate(scan_data.get("redirect_chain", []))
        ]

        raw_cookies = list(dict.fromkeys(
            main.get("raw_cookies", [])
            + http_probe.get("raw_cookies", [])
            + https_probe.get("raw_cookies", [])
        ))

        return self._build_report(
            target=target,
            host=host,
            scheme=scheme,
            http_probe=http_probe,
            https_probe=https_probe,
            redirect_chain=redirect_chain,
            headers=headers,
            raw_cookies=raw_cookies,
            probe_origin_response=origin_headers,
            options_response=options_response,
            trace_response=trace_response,
            started=started,
        )

    def _build_report(
        self,
        target: str,
        host: str,
        scheme: str,
        http_probe: Dict[str, Any],
        https_probe: Dict[str, Any],
        redirect_chain: list,
        headers: Dict[str, Any],
        raw_cookies: list,
        started: float,
        probe_origin_response: Optional[
            Dict[str, Any]
        ] = None,
        options_response: Optional[
            Dict[str, Any]
        ] = None,
        trace_response: Optional[
            Dict[str, Any]
        ] = None,
    ) -> SecurityBehaviorReport:

        # --------------------------------------------------------
        # TRANSPORT SECURITY
        # --------------------------------------------------------

        transport_prof, obs_trans = (
            analyze_transport_security(
                host,
                http_probe,
                https_probe,
                None,
            )
        )

        # --------------------------------------------------------
        # REDIRECT BEHAVIOR
        # --------------------------------------------------------

        redirect_prof, obs_redir = (
            analyze_redirect_chain(
                redirect_chain,
                target,
            )
        )

        # --------------------------------------------------------
        # COOKIE SECURITY
        # --------------------------------------------------------

        cookie_prof, obs_cookie = analyze_cookies(
            raw_cookies,
            is_https=(scheme == "https"),
        )

        # --------------------------------------------------------
        # CORS BEHAVIOR
        # --------------------------------------------------------

        if probe_origin_response is None:

            sim_origin = (
                "https://security-profiler.academic-test.org"
            )

            try:

                origin_result = (
                    self.probe.send_single_request(
                        target,
                        method="GET",
                        headers={
                            "Origin": sim_origin,
                        },
                        follow_redirects=False,
                    )
                )

                probe_origin_response = (
                    origin_result.get(
                        "headers",
                        {},
                    )
                    if origin_result.get(
                        "success"
                    )
                    else None
                )

            except Exception:

                probe_origin_response = None

        cors_prof, obs_cors = (
            analyze_cors_policy(
                headers,
                probe_origin_response,
            )
        )

        # --------------------------------------------------------
        # HTTP METHOD SECURITY
        # --------------------------------------------------------

        if options_response is None:

            try:

                options_response = (
                    self.probe.send_single_request(
                        target,
                        method="OPTIONS",
                        follow_redirects=False,
                    )
                )

            except Exception:

                options_response = {}

        if trace_response is None:

            try:

                trace_response = (
                    self.probe.send_single_request(
                        target,
                        method="TRACE",
                        follow_redirects=False,
                    )
                )

            except Exception:

                trace_response = {}

        method_prof, obs_method = (
            analyze_http_methods(
                options_response,
                trace_response,
            )
        )

        # --------------------------------------------------------
        # INFORMATION DISCLOSURE
        # --------------------------------------------------------

        disc_prof, obs_disc = (
            analyze_information_disclosure(
                headers
            )
        )

        # --------------------------------------------------------
        # COLLECT ALL OBSERVATIONS
        # --------------------------------------------------------

        all_observations = (
            obs_trans
            + obs_redir
            + obs_cookie
            + obs_cors
            + obs_method
            + obs_disc
        )

        # --------------------------------------------------------
        # ANOMALY DETECTION
        # --------------------------------------------------------

        anomalies = (
            self.anomaly_detector.detect_anomalies(
                transport=transport_prof,
                redirect=redirect_prof,
                cookie=cookie_prof,
                cors=cors_prof,
                method=method_prof,
                disclosure=disc_prof,
            )
        )

        # --------------------------------------------------------
        # CORRELATED RISKS
        # --------------------------------------------------------

        correlated_risks = (
            self.correlation_engine.correlate(
                transport=transport_prof,
                redirect=redirect_prof,
                cookie=cookie_prof,
                cors=cors_prof,
                method=method_prof,
                disclosure=disc_prof,
                observations=all_observations,
            )
        )

        # --------------------------------------------------------
        # DOMAIN SCORES
        # --------------------------------------------------------

        domain_scores = {
            "transport_security":
                transport_prof.score,

            "redirect_behavior":
                redirect_prof.score,

            "cookie_behavior":
                cookie_prof.score,

            "cors_behavior":
                cors_prof.score,

            "http_method_behavior":
                method_prof.score,

            "information_disclosure":
                disc_prof.score,
        }

        # --------------------------------------------------------
        # OVERALL SCORE
        # --------------------------------------------------------

        overall = (
            self.scoring_engine.calculate_overall_score(
                domain_scores=domain_scores,
                anomalies=anomalies,
                correlated_risks=correlated_risks,
            )
        )

        execution_time_ms = (
            perf_counter() - started
        ) * 1000

        # --------------------------------------------------------
        # PROFILE SERIALIZATION
        # --------------------------------------------------------

        profile = {
            "transport_security":
                transport_prof.to_dict(),

            "redirect_behavior":
                redirect_prof.to_dict(),

            "cookie_behavior":
                cookie_prof.to_dict(),

            "cors_behavior":
                cors_prof.to_dict(),

            "http_method_behavior":
                method_prof.to_dict(),

            "information_disclosure":
                disc_prof.to_dict(),
        }

        # --------------------------------------------------------
        # RECOMMENDATIONS
        # --------------------------------------------------------

        recommendations = (
            self._build_recommendations(
                anomalies,
                correlated_risks,
            )
        )

        # --------------------------------------------------------
        # FINAL REPORT
        # --------------------------------------------------------

        return SecurityBehaviorReport(
            feature="Security Behavior Profiling",
            target=target,
            scan_timestamp=self._timestamp(),
            execution_time_ms=execution_time_ms,
            profile=profile,
            observations=all_observations,
            anomalies=anomalies,
            correlated_risks=correlated_risks,
            overall=overall,
            recommendations=recommendations,
        )

    @staticmethod
    def _build_recommendations(
        anomalies,
        correlated_risks,
    ):

        recommendations = []

        for risk in correlated_risks:

            recommendation = getattr(
                risk,
                "recommendation",
                None,
            )

            if recommendation:

                recommendations.append(
                    recommendation
                )

        for anomaly in anomalies:

            description = getattr(
                anomaly,
                "description",
                None,
            )

            if description:

                recommendations.append(
                    description
                )

        return list(
            dict.fromkeys(
                recommendations
            )
        )

    @staticmethod
    def _timestamp() -> str:

        from datetime import datetime, timezone

        return datetime.now(
            timezone.utc
        ).isoformat()


if __name__ == "__main__":
    pass


# ==============================================================================
# MODULE: flask_integration.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Flask Integration Blueprint
Provides a clean, modular Flask Blueprint for direct plug-and-play integration into the Reconix Web Security Assessment Tool backend.
"""


def create_security_behavior_blueprint():
    """
    Factory function creating a Flask Blueprint.
    Can be mounted in a Flask app:
    
        app.register_blueprint(create_security_behavior_blueprint(), url_prefix="/api/v1/behavior")
    """
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        # Flask not installed in current environment; return a stub or informative object
        return None

    bp = Blueprint("security_behavior", __name__)
    profiler = SecurityBehaviorProfiler()

    @bp.route("/profile", methods=["POST"])
    def profile_endpoint():
        data = request.get_json() or {}
        target_url = data.get("target") or data.get("url")
        if not target_url:
            return jsonify({"error": "Missing required 'target' parameter in request body"}), 400

        timeout = float(data.get("timeout", 6.0))
        verify_ssl = bool(data.get("verify_ssl", True))
        normalized_headers = data.get("normalized_headers")

        try:
            custom_profiler = SecurityBehaviorProfiler(timeout=timeout, verify_ssl=verify_ssl)
            report = custom_profiler.profile(target_url, normalized_headers=normalized_headers)
            return jsonify(report.to_dict()), 200
        except Exception as e:
            return jsonify({"error": f"Behavioral profiling failed: {str(e)}"}), 500

    @bp.route("/profile/mock", methods=["POST"])
    def profile_mock_endpoint():
        data = request.get_json() or {}
        try:
            report = profiler.profile_mock(data)
            return jsonify(report.to_dict()), 200
        except Exception as e:
            return jsonify({"error": f"Mock profiling failed: {str(e)}"}), 500

    @bp.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "module": "Security Behavior Profiling Engine",
            "status": "operational",
            "version": "1.0.0",
        }), 200

    return bp


# ==============================================================================
# MODULE: cli.py
# ==============================================================================
"""
Security Behavior Profiling Engine - Command Line Interface

Professional interactive CLI for:
- Live security behavior profiling
- Academic scenario execution
- JSON report export
- Color-coded security results
- Professional security posture feedback
"""





# ============================================================
# COLORAMA INITIALIZATION
# ============================================================

init(autoreset=True)


# ============================================================
# PROFESSIONAL COLOR PALETTE
# ============================================================

CYAN = Fore.CYAN
BLUE = Fore.BLUE
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RED = Fore.RED
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE
DIM = Style.DIM
BRIGHT = Style.BRIGHT
RESET = Style.RESET_ALL


# ============================================================
# PRE-DEFINED ACADEMIC TEST SCENARIOS
# ============================================================

ACADEMIC_SCENARIOS = {
    "banking_inconsistent": {
        "target": "https://secure-ebanking.academic-demo.org",
        "host": "secure-ebanking.academic-demo.org",

        "http_probe": {
            "success": True,
            "status_code": 200,
            "headers": {
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3",
            },
            "raw_cookies": [
                "PHPSESSID=9f8a81234bc; path=/"
            ],
            "body_preview": "<html>Login Portal</html>",
        },

        "https_probe": {
            "success": True,
            "status_code": 200,
            "headers": {
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3",
                "strict-transport-security": "max-age=600",
            },
            "raw_cookies": [
                "PHPSESSID=9f8a81234bc; path=/; Secure",
                "remember_user=john_doe; path=/",
            ],
        },

        "headers": {
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
            "access-control-allow-origin":
                "https://security-profiler.academic-test.org",
            "access-control-allow-credentials": "true",
        },

        "probe_origin_response": {
            "access-control-allow-origin":
                "https://security-profiler.academic-test.org",
            "access-control-allow-credentials": "true",
        },

        "trace_response": {
            "success": True,
            "status_code": 200,
            "body_preview":
                "TRACE / HTTP/1.1\r\n"
                "Host: secure-ebanking.academic-demo.org\r\n",
        },

        "options_response": {
            "success": True,
            "status_code": 200,
            "headers": {
                "allow": "GET, POST, OPTIONS, TRACE, PUT"
            },
        },
    },

    "hardened_enterprise": {
        "target": "https://vault.enterprise-defense.org",
        "host": "vault.enterprise-defense.org",

        "http_probe": {
            "success": True,
            "status_code": 301,
            "headers": {
                "location":
                    "https://vault.enterprise-defense.org/"
            },
        },

        "https_probe": {
            "success": True,
            "status_code": 200,
            "headers": {
                "strict-transport-security":
                    "max-age=63072000; includeSubDomains; preload",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
            "raw_cookies": [
                "__Host-sess=k89a17283bc; Secure; HttpOnly; "
                "SameSite=Strict; Path=/",
                "__Secure-csrf=cf9203910aa; Secure; HttpOnly; "
                "SameSite=Strict; Path=/",
            ],
        },

        "headers": {
            "strict-transport-security":
                "max-age=63072000; includeSubDomains; preload",
        },

        "options_response": {
            "success": True,
            "status_code": 200,
            "headers": {
                "allow": "GET, POST, HEAD, OPTIONS"
            },
        },

        "trace_response": {
            "success": True,
            "status_code": 405,
        },
    },

    "downgrade_trap": {
        "target": "https://checkout.retail-portal.local",
        "host": "checkout.retail-portal.local",

        "redirect_chain": [
            {
                "step": 1,
                "status_code": 302,
                "source_url":
                    "https://checkout.retail-portal.local/cart",
                "destination_url":
                    "http://checkout.retail-portal.local/payment-gateway",
                "protocol_change": "DOWNGRADE_TO_HTTP",
                "host_change": False,
            },
            {
                "step": 2,
                "status_code": 200,
                "source_url":
                    "http://checkout.retail-portal.local/payment-gateway",
                "destination_url":
                    "http://checkout.retail-portal.local/payment-gateway",
                "protocol_change": "NONE",
                "host_change": False,
            },
        ],

        "raw_cookies": [
            "cart_token=ct_8192a; path=/",
            "auth_token=at_9102; path=/",
        ],

        "headers": {
            "server": "nginx/1.18.0"
        },
    },
}


# ============================================================
# UI HELPERS
# ============================================================

def clear_screen():
    """Clear terminal screen."""

    os.system(
        "cls" if os.name == "nt" else "clear"
    )


def clean_enum(value):
    """
    Convert Enum-like values into clean CLI text.

    Example:
        RiskLevel.LOW -> LOW
        ConsistencyLevel.HIGH -> HIGH
    """

    value = str(value)

    if "." in value:
        value = value.split(".")[-1]

    return value


def print_banner():
    """Display professional application banner."""

    print()

    print(
        CYAN + BRIGHT +
        "╔══════════════════════════════════════════════╗"
    )

    print(
        CYAN + BRIGHT +
        "║        SECURITY BEHAVIOR PROFILING ENGINE    ║"
    )

    print(
        CYAN + BRIGHT +
        "╚══════════════════════════════════════════════╝"
    )

    print(
        DIM +
        "        Intelligent Security Behavior Analysis"
    )

    print()


def print_section(title):
    """Print a clean section separator."""

    print()

    print(
        BLUE + BRIGHT +
        f"◆ {title}"
    )

    print(
        DIM +
        "─" * 64
    )


def print_success(message):
    print(
        GREEN + BRIGHT +
        f"✓ {message}"
    )


def print_warning(message):
    print(
        YELLOW + BRIGHT +
        f"⚠ {message}"
    )


def print_error(message):
    print(
        RED + BRIGHT +
        f"✗ {message}"
    )


def print_info(message):
    print(
        CYAN +
        f"→ {message}"
    )


def print_score(label, score, status):
    """Print a color-coded security score."""

    if score >= 90:
        score_color = GREEN
    elif score >= 70:
        score_color = CYAN
    elif score >= 50:
        score_color = YELLOW
    else:
        score_color = RED

    status_text = clean_enum(status)

    if "RESTRICTIVE" in status_text:
        status_color = GREEN

    elif "CONSISTENT" in status_text:
        status_color = CYAN

    elif "PERMISSIVE" in status_text:
        status_color = YELLOW

    else:
        status_color = RED

    print(
        f"{WHITE}{label:<27}"
        f"{score_color}{BRIGHT}{score:>3}/100"
        f"{WHITE}  ["
        f"{status_color}{status_text}"
        f"{WHITE}]"
    )


def pause():
    """Pause before returning to menu."""

    print()

    input(
        DIM +
        "Press Enter to return to main menu..."
    )


# ============================================================
# SECURITY POSTURE REACTION
# ============================================================

def print_security_reaction(report):
    """
    Display a professional security posture reaction
    based on the final assessment.
    """

    score = report.overall.score
    anomalies = report.overall.anomalies_count
    risks = report.overall.correlated_risks_count

    print_section("SECURITY POSTURE")

    if score >= 90 and anomalies == 0 and risks == 0:

        print(
            GREEN + BRIGHT +
            "✓ SECURITY POSTURE: STRONG"
        )

        print(
            GREEN +
            "  No significant behavioral weaknesses were detected."
        )

        print(
            CYAN +
            "  The target demonstrates a strong and consistent "
            "security posture."
        )

    elif score >= 70:

        print(
            CYAN + BRIGHT +
            "● SECURITY POSTURE: ACCEPTABLE"
        )

        print(
            CYAN +
            "  Minor behavioral weaknesses may require review."
        )

        print(
            WHITE +
            "  Review the assessment findings for further hardening."
        )

    elif score >= 50:

        print(
            YELLOW + BRIGHT +
            "⚠ SECURITY POSTURE: NEEDS ATTENTION"
        )

        print(
            YELLOW +
            "  Security inconsistencies were detected."
        )

        print(
            WHITE +
            "  Review the identified findings and remediation guidance."
        )

    else:

        print(
            RED + BRIGHT +
            "✗ SECURITY POSTURE: HIGH RISK"
        )

        print(
            RED +
            "  Significant security behavior weaknesses were detected."
        )

        print(
            WHITE +
            "  Immediate remediation is recommended."
        )

    print()

    if risks > 0:

        print(
            RED + BRIGHT +
            f"⚠ {risks} correlated security risk(s) "
            f"require attention."
        )

    elif anomalies > 0:

        print(
            YELLOW + BRIGHT +
            f"⚠ {anomalies} behavioral anomal"
            f"{'y' if anomalies == 1 else 'ies'} detected."
        )

    else:

        print(
            GREEN +
            "✓ No behavioral anomalies detected."
        )


# ============================================================
# TEXT REPORT
# ============================================================

def print_text_report(report):
    """Display a professional color-coded security report."""

    print_section(
        "SECURITY BEHAVIOR PROFILING REPORT"
    )

    print(
        f"{WHITE}Target:      "
        f"{CYAN}{report.target}"
    )

    print(
        f"{WHITE}Timestamp:   "
        f"{DIM}{report.scan_timestamp}"
    )

    print(
        f"{WHITE}Exec Time:   "
        f"{DIM}{report.execution_time_ms:.1f} ms"
    )

    print_section(
        "DOMAIN BEHAVIOR SCORES"
    )

    prof = report.profile

    print_score(
        "Transport Security",
        prof.get(
            "transport_security",
            {}
        ).get("score", 0),
        prof.get(
            "transport_security",
            {}
        ).get("status", "N/A"),
    )

    print_score(
        "Redirect Behavior",
        prof.get(
            "redirect_behavior",
            {}
        ).get("score", 0),
        prof.get(
            "redirect_behavior",
            {}
        ).get("status", "N/A"),
    )

    print_score(
        "Cookie Security",
        prof.get(
            "cookie_behavior",
            {}
        ).get("score", 0),
        prof.get(
            "cookie_behavior",
            {}
        ).get("status", "N/A"),
    )

    print_score(
        "CORS Behavior",
        prof.get(
            "cors_behavior",
            {}
        ).get("score", 0),
        prof.get(
            "cors_behavior",
            {}
        ).get("status", "N/A"),
    )

    print_score(
        "HTTP Method Security",
        prof.get(
            "http_method_behavior",
            {}
        ).get("score", 0),
        prof.get(
            "http_method_behavior",
            {}
        ).get("status", "N/A"),
    )

    print_score(
        "Information Disclosure",
        prof.get(
            "information_disclosure",
            {}
        ).get("score", 0),
        prof.get(
            "information_disclosure",
            {}
        ).get("status", "N/A"),
    )

    print_section(
        "OVERALL SECURITY ASSESSMENT"
    )

    overall_score = report.overall.score

    if overall_score >= 90:

        overall_color = GREEN
        overall_icon = "✓"

    elif overall_score >= 70:

        overall_color = CYAN
        overall_icon = "●"

    elif overall_score >= 50:

        overall_color = YELLOW
        overall_icon = "⚠"

    else:

        overall_color = RED
        overall_icon = "✗"

    risk_level = clean_enum(
        report.overall.risk_level
    )

    consistency = clean_enum(
        report.overall.behavioral_consistency
    )

    print(
        f"{overall_color}{BRIGHT}"
        f"{overall_icon} OVERALL BEHAVIOR SCORE: "
        f"{overall_score}/100"
    )

    print(
        f"{WHITE}Risk Level:             "
        f"{overall_color}{risk_level}"
    )

    print(
        f"{WHITE}Behavioral Consistency: "
        f"{CYAN}{consistency}"
    )

    print(
        f"{WHITE}Anomalies Detected:     "
        f"{RED if report.overall.anomalies_count else GREEN}"
        f"{report.overall.anomalies_count}"
    )

    print(
        f"{WHITE}Correlated Risks:       "
        f"{RED if report.overall.correlated_risks_count else GREEN}"
        f"{report.overall.correlated_risks_count}"
    )

    print_security_reaction(report)

    # --------------------------------------------------------
    # CORRELATED RISKS
    # --------------------------------------------------------

    if report.correlated_risks:

        print_section(
            "CORRELATED BEHAVIORAL RISKS"
        )

        for index, risk in enumerate(
            report.correlated_risks,
            start=1
        ):

            severity = clean_enum(
                risk.severity
            )

            if "CRITICAL" in severity:

                severity_color = RED

            elif "HIGH" in severity:

                severity_color = RED

            elif "MEDIUM" in severity:

                severity_color = YELLOW

            else:

                severity_color = CYAN

            print(
                f"{severity_color}{BRIGHT}"
                f"[{index}] {risk.title}"
            )

            print(
                f"{WHITE}    Severity: "
                f"{severity_color}{severity}"
            )

            print(
                f"{WHITE}    Domains: "
                f"{CYAN}"
                f"{', '.join(risk.primary_domains)}"
            )

            print(
                f"{WHITE}    Confidence: "
                f"{GREEN}{risk.confidence}%"
            )

            print(
                f"{WHITE}    Mechanism: "
                f"{DIM}{risk.combined_mechanism}"
            )

            print(
                f"{GREEN}    Remediation: "
                f"{WHITE}{risk.recommendation}"
            )

            print()

    # --------------------------------------------------------
    # ANOMALIES
    # --------------------------------------------------------

    if report.anomalies:

        print_section(
            "BEHAVIORAL ANOMALIES"
        )

        for index, anomaly in enumerate(
            report.anomalies,
            start=1
        ):

            classification = clean_enum(
                anomaly.classification
            )

            if (
                "HIGH" in classification
                or "CRITICAL" in classification
            ):

                anomaly_color = RED

            elif "MEDIUM" in classification:

                anomaly_color = YELLOW

            else:

                anomaly_color = CYAN

            print(
                f"{anomaly_color}{BRIGHT}"
                f"[{index}] {anomaly.title}"
            )

            print(
                f"{WHITE}    Classification: "
                f"{anomaly_color}{classification}"
            )

            print(
                f"{WHITE}    Category: "
                f"{CYAN}{anomaly.category}"
            )

            print(
                f"{WHITE}    {anomaly.description}"
            )

            print()


# ============================================================
# SCAN TARGET
# ============================================================

def run_scan(profiler):

    print_section(
        "TARGET SECURITY SCAN"
    )

    target = input(
        MAGENTA + BRIGHT +
        "Enter target URL: "
    ).strip()

    if not target:

        print_error(
            "Target URL cannot be empty."
        )

        return None

    try:

        print()

        print_info(
            "Initializing security behavior profiler..."
        )

        print_info(
            "Analyzing transport, redirects, cookies, "
            "CORS and HTTP methods..."
        )

        print()

        report = profiler.profile(
            target
        )

        print_success(
            "Security behavior profiling completed."
        )

        print_text_report(
            report
        )

        return report

    except Exception as e:

        print_error(
            f"Profiling failed: {e}"
        )

        return None


# ============================================================
# RUN ACADEMIC SCENARIO
# ============================================================

def run_scenario(profiler):

    print_section(
        "ACADEMIC SECURITY SCENARIOS"
    )

    scenario_names = list(
        ACADEMIC_SCENARIOS.keys()
    )

    for index, name in enumerate(
        scenario_names,
        start=1
    ):

        print(
            f"{CYAN}{BRIGHT}"
            f"{index:02d}  "
            f"{WHITE}{name}"
        )

    print()

    choice = input(
        MAGENTA + BRIGHT +
        "Select scenario: "
    ).strip()

    try:

        index = int(choice) - 1

        scenario_name = scenario_names[
            index
        ]

    except (
        ValueError,
        IndexError
    ):

        print_error(
            "Invalid scenario selection."
        )

        return None

    try:

        print()

        print_info(
            f"Running scenario: "
            f"{scenario_name}"
        )

        report = profiler.profile_mock(
            ACADEMIC_SCENARIOS[
                scenario_name
            ]
        )

        print_success(
            "Scenario analysis completed."
        )

        print_text_report(
            report
        )

        return report

    except Exception as e:

        print_error(
            f"Scenario failed: {e}"
        )

        return None


# ============================================================
# EXPORT JSON
# ============================================================

def export_json(report):

    if report is None:

        print_error(
            "No report available."
        )

        print_info(
            "Run a scan or scenario first."
        )

        return

    print_section(
        "JSON REPORT EXPORT"
    )

    filename = input(
        MAGENTA + BRIGHT +
        "Enter JSON filename [report.json]: "
    ).strip()

    if not filename:

        filename = "report.json"

    if not filename.lower().endswith(
        ".json"
    ):

        filename += ".json"

    try:

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report.to_dict(),
                file,
                indent=2,
                ensure_ascii=False,
            )

        print_success(
            "JSON report exported successfully:"
        )

        print(
            f"  {CYAN}{filename}"
        )

    except Exception as e:

        print_error(
            f"JSON export failed: {e}"
        )


# ============================================================
# MAIN MENU
# ============================================================

def show_menu():

    print(
        f"{CYAN}{BRIGHT}"
        "01  "
        f"{WHITE}Scan Target"
    )

    print(
        f"{CYAN}{BRIGHT}"
        "02  "
        f"{WHITE}Run Academic Scenario"
    )

    print(
        f"{CYAN}{BRIGHT}"
        "03  "
        f"{WHITE}Export JSON Report"
    )

    print(
        f"{CYAN}{BRIGHT}"
        "04  "
        f"{WHITE}Exit"
    )

    print()


def main():

    profiler = SecurityBehaviorProfiler()

    last_report = None

    while True:

        clear_screen()

        print_banner()

        show_menu()

        choice = input(
            MAGENTA + BRIGHT +
            "Select option: "
        ).strip()

        # ----------------------------------------------------
        # 1. SCAN
        # ----------------------------------------------------

        if choice == "1":

            clear_screen()

            print_banner()

            last_report = run_scan(
                profiler
            )

            pause()

        # ----------------------------------------------------
        # 2. SCENARIO
        # ----------------------------------------------------

        elif choice == "2":

            clear_screen()

            print_banner()

            last_report = run_scenario(
                profiler
            )

            pause()

        # ----------------------------------------------------
        # 3. EXPORT
        # ----------------------------------------------------

        elif choice == "3":

            clear_screen()

            print_banner()

            export_json(
                last_report
            )

            pause()

        # ----------------------------------------------------
        # 4. EXIT
        # ----------------------------------------------------

        elif choice == "4":

            clear_screen()

            print_banner()

            print_success(
                "Security Behavior Profiling Engine stopped."
            )

            print(
                DIM +
                "Thank you for using the assessment engine."
            )

            print()

            break

        # ----------------------------------------------------
        # INVALID OPTION
        # ----------------------------------------------------

        else:

            print()

            print_error(
                "Invalid option. Please select 1-4."
            )

            pause()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()