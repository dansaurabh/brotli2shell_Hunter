"""CI/CD policy gate: map findings to a pass/warn/fail status and exit code."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import CLEAN, PATCHED, POTENTIAL, REVIEW, VULNERABLE

# Exit codes (compatible with cli.main): 0 clean, 1 vulnerable, 2 review-only.
EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_REVIEW = 2
EXIT_CODES = {"pass": EXIT_CLEAN, "fail": EXIT_VULNERABLE, "warn": EXIT_REVIEW}

FAIL_POLICIES = ("any-vulnerable", "reachable-vulnerable", "never")
WARN_POLICIES = ("present", "never")


@dataclass
class PolicyResult:
    exit_code: int
    status: str                      # fail | warn | pass
    reasons: list = field(default_factory=list)

    def as_dict(self):
        return {"exit_code": self.exit_code, "status": self.status,
                "reasons": list(self.reasons)}


def _label(f) -> str:
    return f"{f.component} at {f.location} ({f.verdict}, reach={f.reach})"


def evaluate_policy(findings, fail_on="reachable-vulnerable", warn_on="present"):
    """Evaluate findings against a policy.

    fail_on:
      any-vulnerable        every VULNERABLE finding fails the build.
      reachable-vulnerable  (default) VULNERABLE fails unless reach is
                            "trusted-only". reachable-untrusted, config-gated and
                            unknown all count as reachable: unknown must not be
                            silently waved through (fail closed).
      never                 never fail; findings can still warn.
    warn_on:
      present  warn on POTENTIALLY_VULNERABLE / NEEDS_REVIEW findings and on
               VULNERABLE findings that did not fail (e.g. trusted-only).
      never    no warnings.
    Result: fail -> exit 1, warn -> exit 2, pass -> exit 0.
    """
    if fail_on not in FAIL_POLICIES:
        raise ValueError(f"fail_on must be one of {FAIL_POLICIES}")
    if warn_on not in WARN_POLICIES:
        raise ValueError(f"warn_on must be one of {WARN_POLICIES}")

    fails, warns = [], []
    for f in findings:
        if f.verdict == VULNERABLE:
            fatal = fail_on == "any-vulnerable" or (
                fail_on == "reachable-vulnerable" and f.reach != "trusted-only")
            (fails if fatal else warns).append(f)
        elif f.verdict in (POTENTIAL, REVIEW):
            warns.append(f)
        elif f.verdict not in (PATCHED, CLEAN):
            warns.append(f)          # unknown verdict: surface, don't hide

    if fails:
        status = "fail"
        reasons = [f"fail: {_label(f)}" for f in fails]
    elif warns and warn_on == "present":
        status = "warn"
        reasons = [f"warn: {_label(f)}" for f in warns]
    else:
        status, reasons = "pass", []
    return PolicyResult(EXIT_CODES[status], status, reasons)
