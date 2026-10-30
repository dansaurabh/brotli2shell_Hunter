"""Backport reconciliation: cross-check package-version findings against marker findings.

Distro packages are judged by version, which backports defeat (old version carrying the
fix) and stale installs defeat (new version, old binary). The binary-marker layer is
version-independent, so when both speak about the same library the marker wins.
Findings are never deleted; contradicted package findings are copied with annotations.
"""

from __future__ import annotations

import os
from dataclasses import replace

from .model import PATCHED, REVIEW, VULNERABLE

BACKPORT_NOTE = "backport-patched: marker confirms fix"
BACKPORT_FIX = "no action - backport-patched"
_MARKER_LAYER = "binary-marker"
_SYSTEM = ("package:dpkg", "package:rpm", "package:apk")


def _scope(path):
    """Which package ecosystem owns a marker-bearing file, judged from its path."""
    p = (path or "").replace("\\", "/").lower()
    if "/site-packages/" in p or "/dist-packages/" in p:
        return "package:pip"
    if "/node_modules/" in p:
        return "package:npm"
    if "brotli" in os.path.basename(p):
        return "system"
    return ""            # embedded in an unrelated binary (node, python, ...): no owner


def _owns(pkg_layer, scope):
    return (scope == "system" and pkg_layer in _SYSTEM) or scope == pkg_layer


def _join(*parts):
    return "; ".join(x for x in parts if x)


def reconcile_backports(findings):
    """Return a new list; package findings contradicted by marker evidence are annotated."""
    markers = [f for f in findings if f.layer == _MARKER_LAYER
               and f.verdict in (PATCHED, VULNERABLE)]
    out = []
    for f in findings:
        if not f.layer.startswith("package:"):
            out.append(f)
            continue
        related = [m for m in markers if _owns(f.layer, _scope(m.location))]
        if not related:
            out.append(f)
            continue
        bad = [m for m in related if m.verdict == VULNERABLE]
        prov = f"owning package: {f.component} {f.version}".rstrip()
        ev = _join(f.evidence, "marker scan overrides version")
        if bad:
            if f.verdict == VULNERABLE:
                out.append(f)
                continue
            files = ", ".join(sorted(m.location for m in bad))
            out.append(replace(
                f, verdict=VULNERABLE, confidence="high", evidence=ev,
                note=_join(f.note, f"unpatched despite version: fix marker absent in {files}",
                           prov)))
        elif f.verdict in (VULNERABLE, REVIEW):
            files = ", ".join(sorted(m.location for m in related))
            out.append(replace(
                f, verdict=PATCHED, confidence="high", fix=BACKPORT_FIX, evidence=ev,
                note=_join(f.note, f"{BACKPORT_NOTE} in {files}", prov)))
        else:
            out.append(f)     # PATCHED/CLEAN and markers agree
    return out
