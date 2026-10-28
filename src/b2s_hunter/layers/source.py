"""Layer: source reachability."""

from __future__ import annotations

import os
import re

from .. import ruledata as rd
from ..model import POTENTIAL, Finding

REACH_PATTERNS = {label: re.compile(rx) for label, rx in rd.REACH_PATTERNS.items()}


def layer_source(src_roots, findings):
    for root in src_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if ".git" in dirnames:
                dirnames.remove(".git")
            if "node_modules" in dirnames:
                dirnames.remove("node_modules")
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                low = name.lower()
                if ext not in rd.REACH_EXT and "dockerfile" not in low:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 3 * 1024 * 1024:
                        continue
                    with open(path, "r", errors="ignore") as fh:
                        text = fh.read()
                except Exception:
                    continue
                hits = [label for label, rx in REACH_PATTERNS.items() if rx.search(text)]
                if hits:
                    findings.append(Finding(
                        layer="source-reachability", component=", ".join(hits),
                        location=path, verdict=POTENTIAL, confidence="low",
                        evidence="decode entry point(s) in source; untrusted input may reach a decoder",
                        note="ranking signal only - confirm an affected decoder is actually linked",
                    ))
