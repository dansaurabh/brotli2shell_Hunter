"""SARIF 2.1.0 emission for code-scanning / CI gates."""

from __future__ import annotations

import re

from . import ruledata as rd
from .model import POTENTIAL, REVIEW, VULNERABLE

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {VULNERABLE: "error", POTENTIAL: "warning", REVIEW: "note"}


def _uri(loc):
    """Best-effort artifact URI; returns '' when location is not a path/URL."""
    loc = (loc or "").strip()
    if not loc:
        return ""
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]+://", loc):
        return loc
    if re.match(r"^[A-Za-z]:[\\/]", loc):          # Windows drive path
        return "file:///" + loc.replace("\\", "/").replace(" ", "%20")
    if loc.startswith("/") or "/" in loc or "\\" in loc:
        return loc.replace("\\", "/").replace(" ", "%20")
    return ""


def build_sarif(findings, host):
    results = []
    for f in findings:
        if f.verdict not in LEVEL:          # skips PATCHED / NOT_AFFECTED
            continue
        text = f"{f.component} {f.version}".strip() + f" - {f.verdict}"
        if f.evidence:
            text += f": {f.evidence}"
        r = {
            "ruleId": rd.CVE_ID,
            "level": LEVEL[f.verdict],
            "message": {"text": text},
            "properties": {
                "verdict": f.verdict, "confidence": f.confidence, "reach": f.reach,
                "priority": f.priority, "fix": f.fix, "layer": f.layer,
                "component": f.component, "version": f.version, "purl": f.purl,
            },
        }
        uri = _uri(f.location)
        if uri:
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        else:
            r["locations"] = [{"logicalLocations": [
                {"name": f.location or f.component or "unknown"}]}]
        results.append(r)
    results.sort(key=lambda r: (-r["properties"]["priority"], r["properties"]["component"],
                                r["message"]["text"], repr(r["locations"])))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "b2s-hunter",
                "version": rd.RULES_VERSION,
                "informationUri": f"https://nvd.nist.gov/vuln/detail/{rd.CVE_ID}",
                "rules": [{
                    "id": rd.CVE_ID,
                    "name": "BrotliDecoderFlaw",
                    "shortDescription": {"text": f"{rd.CVE_ID} (Brotli2Shell) vulnerable Brotli decoder"},
                    "fullDescription": {"text": rd.FIX_HINT},
                    "help": {"text": rd.FIX_HINT},
                    "defaultConfiguration": {"level": "warning"},
                }],
            }},
            "invocations": [{"executionSuccessful": True,
                             "startTimeUtc": host.get("time", ""),
                             "machine": host.get("hostname", "")}],
            "properties": {"os": host.get("os", ""), "rulesDate": rd.RULES_DATE},
            "results": results,
        }],
    }
