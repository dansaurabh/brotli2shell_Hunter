"""Layer: language runtimes + running processes."""

from __future__ import annotations

import os
import platform
import re
import shutil

from .. import ruledata as rd
from ..model import POTENTIAL, REVIEW, Finding
from ..util import have, run
from ..versions import node_verdict, parse_ver, simple_verdict


def layer_runtimes(findings):
    if have("node"):
        ver = run(["node", "--version"]).strip()
        v = parse_ver(ver)
        verdict, why = node_verdict(v)
        brotli_bundled = run(["node", "-p", "process.versions.brotli"]).strip()
        findings.append(Finding(
            layer="runtime:node", component="Node.js", location=shutil.which("node") or "node",
            version=ver, verdict=verdict, confidence="high",
            evidence=f"{why}; bundled brotli string reports {brotli_bundled or '?'}",
            note="judge Node by the Node version, not process.versions.brotli (fix is cherry-picked)",
        ))
    if have("bun"):
        ver = run(["bun", "--version"]).strip()
        verdict, why = simple_verdict(parse_ver(ver), rd.BUN_FIXED)
        findings.append(Finding(
            layer="runtime:bun", component="Bun", location=shutil.which("bun") or "bun",
            version=ver, verdict=verdict, confidence="high",
            evidence=f"fixed in 1.4.4: {why}",
        ))
    # curl advertises the brotli feature (reachable client path if so)
    if have("curl"):
        out = run(["curl", "--version"])
        if re.search(r"\bbrotli\b", out, re.IGNORECASE):
            findings.append(Finding(
                layer="runtime:curl", component="curl/libcurl", location=shutil.which("curl") or "curl",
                verdict=REVIEW, confidence="low",
                evidence="curl built with brotli feature; check the libbrotlidec it links (ldd/otool)",
                note="client-side decode path; verify the linked lib via the marker layer",
            ))
    # deleted-lib-in-memory detection lives in layers/memres.py
