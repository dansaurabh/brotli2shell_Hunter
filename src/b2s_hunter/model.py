"""Finding model and verdict constants."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

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
    # --- enrichment (filled by reachability / mitigation stages; all optional) ---
    purl: str = ""
    reach: str = "unknown"       # reachable-untrusted | config-gated | trusted-only | unknown
    direction: str = ""          # inbound | outbound | file | ""
    input_trust: str = ""        # untrusted | trusted | ""
    gate: str = ""               # config gate description, e.g. "only if brotli pkg installed"
    internet_facing: bool = False
    impact: str = ""             # realistic-impact note (DoS + limited disclosure; RCE situational)
    priority: int = 0            # composite 0-100, higher = fix first
    fix: str = ""                # exact per-component fix
    restart: str = ""            # "install != fixed" rebuild/restart instruction
    controls: list = field(default_factory=list)      # compensating controls
    not_covered: str = ""        # what the controls do NOT cover
    verify: str = ""             # post-fix re-check instruction
    vex_status: str = ""         # affected | not_affected | under_investigation | fixed
    vex_justification: str = ""

    def as_dict(self):
        return asdict(self)
