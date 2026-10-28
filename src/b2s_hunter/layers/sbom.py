"""Layer: SBOM ingestion (CycloneDX / SPDX JSON)."""

from __future__ import annotations

import json
import os
import re

from .. import ruledata as rd
from ..model import REVIEW, Finding
from ..versions import brotli_lib_verdict, parse_ver, simple_verdict

SBOM_NAME_RE = re.compile(rd.SBOM_NAME_PATTERN, re.IGNORECASE)


def layer_sbom(paths, findings):
    for path in paths:
        try:
            with open(path, "r", errors="ignore") as fh:
                doc = json.load(fh)
        except Exception as e:
            findings.append(Finding(
                layer="sbom", component=path, location=path,
                verdict=REVIEW, confidence="low", evidence=f"could not parse: {e}"))
            continue
        comps = []
        if isinstance(doc, dict) and "components" in doc:          # CycloneDX
            comps = [(c.get("name", ""), c.get("version", ""), c.get("purl", ""))
                     for c in doc.get("components", []) if isinstance(c, dict)]
        elif isinstance(doc, dict) and "packages" in doc:          # SPDX
            comps = [(p.get("name", ""), p.get("versionInfo", ""),
                      _spdx_purl(p)) for p in doc.get("packages", []) if isinstance(p, dict)]
        for name, ver, purl in comps:
            hay = f"{name} {purl}"
            if not SBOM_NAME_RE.search(hay):
                continue
            low = name.lower()
            if "brotlicffi" in low:
                verdict, why = simple_verdict(parse_ver(ver), rd.PY_BROTLICFFI_FIXED)
            elif low in ("brotli",) or "py-brotli" in low:
                verdict, why = simple_verdict(parse_ver(ver), rd.PY_BROTLI_FIXED)
            else:
                verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="sbom", component=name or purl, location=os.path.basename(path),
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"{why} ({purl or 'no purl'})",
                note="SBOM finds declared deps; statically-linked copies still need the marker scan",
            ))


def _spdx_purl(pkg):
    for ref in pkg.get("externalRefs", []) or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator", "")
    return ""
