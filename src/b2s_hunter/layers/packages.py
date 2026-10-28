"""Layer: OS and language packages."""

from __future__ import annotations

import json
import re

from .. import ruledata as rd
from ..model import REVIEW, Finding
from ..util import have, run
from ..versions import brotli_lib_verdict, parse_ver, simple_verdict


def layer_packages(findings):
    # Debian/Ubuntu
    if have("dpkg-query"):
        out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name, ver = parts[0], parts[1]
            if "brotli" not in name.lower():
                continue
            if len(parts) >= 3 and "installed" not in parts[2]:
                continue
            verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="package:dpkg", component=name, location="dpkg",
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"version check: {why}",
                note="version may be a backport; binary-marker layer is authoritative",
            ))
    # RHEL/Fedora/SUSE
    if have("rpm"):
        out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        for line in out.splitlines():
            name, _, ver = line.partition("\t")
            if "brotli" not in name.lower():
                continue
            verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="package:rpm", component=name, location="rpm",
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"version check: {why}",
                note="version may be a backport; binary-marker layer is authoritative",
            ))
    # Alpine
    if have("apk"):
        out = run(["apk", "info", "-v"])
        for line in out.splitlines():
            if "brotli" not in line.lower():
                continue
            m = re.match(r"(.+?)-(\d.+)$", line.strip())
            name, ver = (m.group(1), m.group(2)) if m else (line.strip(), "")
            verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="package:apk", component=name, location="apk",
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"version check: {why}",
            ))
    # Python wheels (pip)
    _layer_pip(findings)
    # npm global
    if have("npm"):
        out = run(["npm", "ls", "-g", "--depth=0", "--json"], timeout=60)
        try:
            data = json.loads(out) if out.strip() else {}
        except Exception:
            data = {}
        for name, meta in (data.get("dependencies") or {}).items():
            if "brotli" in name.lower():
                ver = (meta or {}).get("version", "")
                findings.append(Finding(
                    layer="package:npm", component=name, location="npm -g",
                    version=ver, verdict=REVIEW, confidence="low",
                    evidence="npm brotli binding; confirm bundled decoder via marker scan",
                ))


def _layer_pip(findings):
    pips = [p for p in ("pip3", "pip") if have(p)]
    if not pips:
        return
    out = run([pips[0], "list", "--format=json"], timeout=60)
    try:
        pkgs = json.loads(out) if out.strip() else []
    except Exception:
        pkgs = []
    for pkg in pkgs:
        name = (pkg.get("name") or "").strip()
        ver = pkg.get("version") or ""
        low = name.lower()
        if low == "brotli":
            verdict, why = simple_verdict(parse_ver(ver), rd.PY_BROTLI_FIXED)
            findings.append(Finding(
                layer="package:pip", component="Brotli (PyPI)", location="pip",
                version=ver, verdict=verdict, confidence="high",
                evidence=f"PYSEC-2026-4322 fixed in 1.2.1: {why}",
                note="auto-used by requests/httpx/aiohttp/urllib3 for 'br' responses",
            ))
        elif low == "brotlicffi":
            verdict, why = simple_verdict(parse_ver(ver), rd.PY_BROTLICFFI_FIXED)
            findings.append(Finding(
                layer="package:pip", component="brotlicffi (PyPI)", location="pip",
                version=ver, verdict=verdict, confidence="high",
                evidence=f"PYSEC-2026-4323 fixed in 1.2.1.0: {why}",
            ))
