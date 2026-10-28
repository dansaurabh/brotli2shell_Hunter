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
    # Running processes still mapping a deleted (old) libbrotli  (Linux only)
    if platform.system() == "Linux" and os.path.isdir("/proc"):
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            maps = f"/proc/{pid}/maps"
            try:
                with open(maps, "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            for mline in content.splitlines():
                if "libbrotli" in mline and "(deleted)" in mline:
                    exe = os.path.realpath(f"/proc/{pid}/exe") if os.path.exists(f"/proc/{pid}/exe") else "?"
                    findings.append(Finding(
                        layer="runtime:process", component="process mapping deleted libbrotli",
                        location=f"pid {pid} ({exe})", verdict=POTENTIAL, confidence="medium",
                        evidence="still running an old libbrotli held in memory after on-disk update",
                        note="restart the service to load the patched library",
                    ))
                    break
