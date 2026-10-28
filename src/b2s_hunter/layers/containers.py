"""Layer: containers (read-only rootfs marker scan, no exec)."""

from __future__ import annotations

import json
import os

from ..model import REVIEW, Finding
from ..util import have, run
from .markers import layer_markers


def layer_containers(findings, verbose=False):
    runtimes = [r for r in ("docker", "podman", "nerdctl") if have(r)]
    if not runtimes:
        return
    for rt in runtimes:
        ids = run([rt, "ps", "-q"]).split()
        for cid in ids:
            info = run([rt, "inspect", cid])
            merged = ""
            name = cid[:12]
            try:
                data = json.loads(info)
                if isinstance(data, list) and data:
                    d = data[0]
                    name = (d.get("Name") or name).lstrip("/")
                    merged = (((d.get("GraphDriver") or {}).get("Data") or {}).get("MergedDir") or "")
            except Exception:
                pass
            if merged and os.path.isdir(merged):
                sub = []
                layer_markers([merged], sub, verbose=verbose)
                for f in sub:
                    f.layer = f"container:{rt}"
                    f.note = f"{name}: {f.note}"
                    f.location = f"[{name}] {f.location}"
                    findings.append(f)
            else:
                findings.append(Finding(
                    layer=f"container:{rt}", component=name,
                    location=f"{rt} {cid[:12]}", verdict=REVIEW, confidence="low",
                    evidence="rootfs path not resolvable without elevated access",
                    note="re-run as root, or scan the image filesystem offline",
                ))
