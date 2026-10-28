"""Finding model and verdict constants."""

from __future__ import annotations

from dataclasses import asdict, dataclass

# Verdicts, ordered by severity for roll-up.
VULNERABLE = "VULNERABLE"
POTENTIAL = "POTENTIALLY_VULNERABLE"
REVIEW = "NEEDS_REVIEW"
PATCHED = "PATCHED"
CLEAN = "NOT_AFFECTED"
SEVERITY = {VULNERABLE: 4, POTENTIAL: 3, REVIEW: 2, PATCHED: 1, CLEAN: 0}


@dataclass
class Finding:
    layer: str
    component: str
    location: str
    verdict: str
    confidence: str          # high | medium | low
    version: str = ""
    evidence: str = ""
    note: str = ""

    def as_dict(self):
        return asdict(self)
