"""Secret-type classifier for covenant findings.

Classifies a matched secret string into a typed category with severity and
confidence.  Operates purely on regex patterns and Shannon entropy -- no
network, no model calls, no untrusted-input execution.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum


class SecretType(Enum):
    AWS_KEY = "aws_key"
    SLACK_TOKEN = "slack_token"
    GITHUB_PAT = "github_pat"
    JWT = "jwt"
    PRIVATE_KEY = "private_key"
    API_KEY = "api_key"
    PASSWORD = "password"
    DATABASE_URL = "database_url"
    STRIPE_KEY = "stripe_key"
    SENDGRID_KEY = "sendgrid_key"
    UNKNOWN = "unknown"


@dataclass
class ClassifiedSecret:
    raw_match: str
    secret_type: SecretType
    severity: str  # "critical" | "high" | "medium"
    confidence: float  # 0.0 - 1.0
    entropy: float  # Shannon entropy of the matched value


# (pattern, type, severity, confidence)
_RULES: list[tuple[re.Pattern[str], SecretType, str, float]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), SecretType.AWS_KEY, "critical", 0.98),
    (re.compile(r"xoxb-[0-9]+-[0-9A-Za-z]+"), SecretType.SLACK_TOKEN, "critical", 0.97),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), SecretType.GITHUB_PAT, "critical", 0.98),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+"),
        SecretType.JWT,
        "high",
        0.95,
    ),
    (
        re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----"),
        SecretType.PRIVATE_KEY,
        "critical",
        0.99,
    ),
    (
        re.compile(r"(?:postgres|mysql|mongodb)://[^\s]+"),
        SecretType.DATABASE_URL,
        "high",
        0.90,
    ),
    (re.compile(r"sk_live_[A-Za-z0-9]{24}"), SecretType.STRIPE_KEY, "critical", 0.98),
    (
        re.compile(r"SG\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{43}"),
        SecretType.SENDGRID_KEY,
        "critical",
        0.98,
    ),
]


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of *value*.

    Returns 0.0 for an empty string.
    """
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def classify_secret(match: str) -> ClassifiedSecret:
    """Classify a potential secret string by type and severity.

    Applies each pattern rule in order; the first match wins.  Unrecognised
    strings are classified as UNKNOWN / medium / low-confidence, though their
    entropy is still scored (high-entropy UNKNOWN strings are still worth
    investigating).
    """
    entropy = shannon_entropy(match)
    for pattern, secret_type, severity, confidence in _RULES:
        if pattern.search(match):
            return ClassifiedSecret(
                raw_match=match,
                secret_type=secret_type,
                severity=severity,
                confidence=confidence,
                entropy=entropy,
            )
    # No known pattern -- fall back to entropy-based heuristic.
    if entropy > 3.5:
        return ClassifiedSecret(
            raw_match=match,
            secret_type=SecretType.UNKNOWN,
            severity="medium",
            confidence=0.4,
            entropy=entropy,
        )
    return ClassifiedSecret(
        raw_match=match,
        secret_type=SecretType.UNKNOWN,
        severity="medium",
        confidence=0.1,
        entropy=entropy,
    )
