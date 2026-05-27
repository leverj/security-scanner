"""Internal data model. Everything from a scanner normalizes to Finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["dependency", "secret", "sast"]

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class Finding:
    """One normalized finding. Scanner-agnostic shape used everywhere downstream."""

    scanner: str
    category: str
    rule_id: str
    severity: str
    file_path: str
    line: int | None
    title: str
    message: str
    masked_preview: str = ""
    sarif_fingerprint: str | None = None
    extra: dict = field(default_factory=dict)

    def meets_floor(self, floor: str) -> bool:
        return SEVERITY_ORDER.get(self.severity, 0) >= SEVERITY_ORDER.get(floor, 0)


def normalize_severity(level: str | None, security_severity: str | float | None = None) -> str:
    """Map SARIF level + security-severity to our 5-tier scale.

    Per SARIF spec, security-severity is a CVSS 0-10 score when present and takes
    precedence over the coarse error/warning/note level.
    """
    if security_severity is not None:
        try:
            score = float(security_severity)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0.0:
                return "low"
            return "info"

    lvl = (level or "").lower()
    if lvl == "error":
        return "high"
    if lvl == "warning":
        return "medium"
    if lvl == "note":
        return "low"
    return "info"
