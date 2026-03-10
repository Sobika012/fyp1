            
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


# =========================
# HELPERS
# =========================
def clamp_score(x: float) -> float:
    """
    Clamp a confidence score into [0.0, 1.0].
    Accepts weird/None inputs safely.
    """
    try:
        v = float(x)
    except Exception:
        return 0.0

    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


# =========================
# NORMALIZED FINDING (Validator input)
# =========================
@dataclass
class NormalizedFinding:
    # Core fields
    vuln_class: str
    original_tool: str
    severity: str
    url: str
    evidence: str
    phase: str
    raw: Any

    # Extra metadata
    meta: Dict[str, Any] = field(default_factory=dict)

    # ✅ NEW (for POST support)
    method: str = "GET"  # GET/POST
    post_data: str = ""  # urlencoded body (e.g. a=b&c=d)
    content_type: str = "application/x-www-form-urlencoded"

    def to_dict(self) -> Dict[str, Any]:
        """
        JSON-ready dict. raw can be anything; if not JSON serializable,
        your dumping layer should stringify or handle it.
        """
        return asdict(self)


# =========================
# VALIDATION RESULT (Validator output)
# =========================
@dataclass
class ValidationResult:
    """
    status: confirmed | false_positive | needs_manual_review
    confidence: 0.0 to 1.0
    """
    status: str = ""
    reason: str = ""
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        status: str = "",
        reason: str = "",
        confidence: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        # Accept legacy names
        if (not status) and ("validation_status" in kwargs):
            status = str(kwargs.pop("validation_status") or "")

        if (not reason) and ("validation_reason" in kwargs):
            reason = str(kwargs.pop("validation_reason") or "")

        # ✅ Accept confidence_score (your validators use this!)
        if (confidence == 0.0) and ("confidence_score" in kwargs):
            try:
                confidence = float(kwargs.pop("confidence_score") or 0.0)
            except Exception:
                confidence = 0.0

        # Some older code may pass validation_confidence instead of confidence
        if (confidence == 0.0) and ("validation_confidence" in kwargs):
            try:
                confidence = float(kwargs.pop("validation_confidence") or 0.0)
            except Exception:
                confidence = 0.0

        # Accept direct details (safe)
        if details is None and "details" in kwargs:
            details = kwargs.pop("details")

        self.status = str(status)
        self.reason = str(reason)
        self.confidence = clamp_score(confidence)
        self.details = dict(details or {})

    # ✅ Legacy attribute names used by engine.py
    @property
    def validation_status(self) -> str:
        return self.status

    @property
    def validation_reason(self) -> str:
        return self.reason

    @property
    def validation_confidence(self) -> float:
        return float(self.confidence)

    # ✅ NEW: engine/correlation can read this directly
    @property
    def confidence_score(self) -> float:
        return float(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "validation_status": self.status,
            "reason": self.reason,
            "validation_reason": self.reason,
            "confidence": float(self.confidence),
            "confidence_score": float(self.confidence),
            "validation_confidence": float(self.confidence),
            "details": dict(self.details or {}),
        }
