"""Version parsing and verdict math. Thresholds come from ruledata."""

from __future__ import annotations

import re

from . import ruledata as rd
from .model import CLEAN, PATCHED, REVIEW, VULNERABLE


def parse_ver(s: str):
    """'1.0.9-2+deb12u1' -> (1,0,9). Keeps leading numeric dotted parts only."""
    if not s:
        return None
    s = s.strip().lstrip("vV=")
    m = re.match(r"(\d+(?:\.\d+)*)", s)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def brotli_lib_verdict(v):
    if v is None:
        return REVIEW, "unparseable version"
    if len(v) < 2:
        return REVIEW, "incomplete version"
    if v < rd.BROTLI_MIN_AFFECTED:
        return CLEAN, "pre-1.0.3, before the flaw was introduced"
    line = (v[0], v[1])
    fixed = rd.BROTLI_LINES.get(line)
    if fixed is None:
        return REVIEW, "version line not in known affected set; verify manually"
    return (PATCHED, "at/above line fix") if v >= fixed else (VULNERABLE, "below line fix")


def node_verdict(v):
    if v is None:
        return REVIEW, "unparseable"
    major = v[0]
    if major in rd.NODE_FIXED:
        return (PATCHED, "patched line") if v >= rd.NODE_FIXED[major] else (VULNERABLE, "below line fix")
    if major < 22 or major in rd.NODE_EOL_NO_FIX:
        return VULNERABLE, ("EOL/unsupported line, no fix will ship (e.g. Node 20 EOL Apr-2026); "
                            "exploitability depends on whether untrusted Brotli input reaches this runtime")
    return REVIEW, "non-LTS/newer line; confirm it carries the Oct-2026 fix"


def simple_verdict(v, fixed):
    if v is None:
        return REVIEW, "unparseable"
    return (PATCHED, "patched") if v >= fixed else (VULNERABLE, "below fix")
