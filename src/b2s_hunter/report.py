"""Reporting: roll-up, text rendering, JSON payload."""

from __future__ import annotations

from . import ruledata as rd
from .model import CLEAN, PATCHED, POTENTIAL, REVIEW, SEVERITY, VULNERABLE


def rollup(findings):
    counts = {VULNERABLE: 0, POTENTIAL: 0, REVIEW: 0, PATCHED: 0, CLEAN: 0}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    return counts


def render_text(findings, counts, host):
    order = sorted(findings, key=lambda f: (-SEVERITY.get(f.verdict, 0), f.layer, f.location))
    lines = []
    lines.append("=" * 78)
    lines.append(" Brotli2Shell / HTTP2Shell (CVE-2026-111497) exposure report")
    lines.append(f" host: {host['hostname']}   os: {host['os']}   time: {host['time']}")
    lines.append("=" * 78)
    lines.append(f" VULNERABLE: {counts[VULNERABLE]}   POTENTIAL: {counts[POTENTIAL]}   "
                 f"REVIEW: {counts[REVIEW]}   PATCHED: {counts[PATCHED]}   CLEAN: {counts[CLEAN]}")
    lines.append("-" * 78)
    if not findings:
        lines.append(" No Brotli decoder copies or decode paths found in scanned scope.")
    for f in order:
        if f.verdict in (PATCHED, CLEAN):
            continue
        lines.append(f"[{f.verdict}] ({f.confidence}) {f.layer}")
        lines.append(f"    component : {f.component}" + (f"  {f.version}" if f.version else ""))
        lines.append(f"    location  : {f.location}")
        lines.append(f"    evidence  : {f.evidence}")
        if f.note:
            lines.append(f"    note      : {f.note}")
    shown_patched = [f for f in order if f.verdict in (PATCHED, CLEAN)]
    if shown_patched:
        lines.append("-" * 78)
        lines.append(f" {len(shown_patched)} copy/copies verified patched or not-affected (hidden; see JSON).")
    lines.append("-" * 78)
    lines.append(" Remediation: " + rd.FIX_HINT)
    lines.append("=" * 78)
    return "\n".join(lines)


def build_payload(findings, counts, host):
    return {
        "cve": rd.CVE_ID,
        "aka": rd.CVE_ALIASES,
        "host": host,
        "summary": counts,
        "remediation": rd.FIX_HINT,
        "findings": [f.as_dict() for f in findings],
    }
