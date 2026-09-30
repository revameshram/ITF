"""Finding / Evidence data model shared by all analyzers.

Every finding answers the questions the SIH problem asks for:
    what we found, why we flagged it, evidence, confidence/severity,
    affected asset(s), limitations
plus *how* it was obtained (method + implementation status) so the UI
can always show whether a conclusion is REAL, HEURISTIC or DEMO.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_WEIGHT = {"INFO": 0.05, "LOW": 0.2, "MEDIUM": 0.45, "HIGH": 0.75, "CRITICAL": 0.95}

# Method status vocabulary (shown verbatim in the UI)
REAL = "REAL"               # deterministic / cryptographic / exact computation
HEURISTIC = "HEURISTIC"     # real computation, but the conclusion is heuristic / uncalibrated
DEMO = "DEMO / SIMULATED"   # produced only to demonstrate a capability


@dataclass
class Evidence:
    kind: str                      # e.g. "sample_list", "hash_comparison", "statistical_test"
    title: str
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)
    assets: list[str] = field(default_factory=list)   # graph node ids

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    pillar: str                    # dataset | model | inference | distribution | governance
    category: str                  # machine-readable, e.g. "dataset.trigger_pattern"
    title: str
    what: str                      # what we found
    why: str                       # why we flagged it
    severity: str
    confidence: float              # 0..1
    confidence_basis: str          # how the number was obtained (calibrated or not)
    method: str
    method_status: str             # REAL | HEURISTIC | DEMO / SIMULATED
    affected: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    tags: dict[str, Any] = field(default_factory=dict)     # used by the correlation engine
    recommendation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


@dataclass
class CheckRecord:
    """One line of the coverage table: which check ran, and with what outcome."""
    pillar: str
    check: str
    status: str            # ran | unavailable | not_implemented | skipped
    method_status: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalyzerResult:
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
