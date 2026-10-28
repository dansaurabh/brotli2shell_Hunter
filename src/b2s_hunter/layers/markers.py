"""Layer: binary / marker scan (the core; version-independent)."""

from __future__ import annotations

import os
import sys

from ..markers import classify_markers, looks_binary, scan_markers_in_file, walk_files
from ..model import Finding


def layer_markers(roots, findings, verbose=False):
    seen = set()
    scanned = 0
    for root in roots:
        if not os.path.isdir(root) and not os.path.isfile(root):
            continue
        walk_targets = [root] if os.path.isfile(root) else walk_files(root)
        for path in walk_targets:
            rp = os.path.realpath(path)
            if rp in seen:
                continue
            seen.add(rp)
            if not looks_binary(path):
                continue
            res = scan_markers_in_file(path)
            scanned += 1
            if verbose and scanned % 500 == 0:
                print(f"  [markers] scanned {scanned} binaries...", file=sys.stderr)
            if not res:
                continue
            cls = classify_markers(res)
            if cls is None:
                continue
            verdict, conf, ev = cls
            findings.append(Finding(
                layer="binary-marker", component="brotli-decoder (embedded)",
                location=path, verdict=verdict, confidence=conf, evidence=ev,
                note="version-independent; valid even for backports and vendored copies",
            ))
    return scanned
