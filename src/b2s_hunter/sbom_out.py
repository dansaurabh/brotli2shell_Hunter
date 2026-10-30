"""CycloneDX SBOM emission (components with purl, bom-ref, verdict properties)."""

from __future__ import annotations

import hashlib
import json
import uuid
from urllib.parse import quote

from . import ruledata as rd


def synth_purl(f):
    """finding.purl, else a generic purl built from component/version."""
    if f.purl:
        return f.purl
    name = quote(f.component or "unknown", safe="")
    ver = "@" + quote(f.version, safe="") if f.version else ""
    return f"pkg:generic/{name}{ver}"


def component_ref(f):
    """Stable bom-ref, unique per (purl, layer, location); shared with vex.py."""
    h = hashlib.sha1(f"{f.layer}|{f.location}".encode("utf-8", "replace")).hexdigest()[:8]
    return f"{synth_purl(f)}#{h}"


def stable_serial(doc):
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, blob))


def build_cyclonedx_sbom(findings, host):
    comps = {}
    for f in findings:
        ref = component_ref(f)
        comps[ref] = {
            "type": "library",
            "bom-ref": ref,
            "name": f.component or "unknown",
            "version": f.version or "",
            "purl": synth_purl(f),
            "properties": [
                {"name": "b2s:verdict", "value": f.verdict},
                {"name": "b2s:confidence", "value": f.confidence},
                {"name": "b2s:layer", "value": f.layer},
                {"name": "b2s:location", "value": f.location},
                {"name": "b2s:reach", "value": f.reach},
            ],
        }
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": host.get("time", ""),
            "tools": {"components": [{"type": "application", "name": "b2s-hunter",
                                      "version": rd.RULES_VERSION}]},
            "component": {"type": "device", "name": host.get("hostname", ""),
                          "bom-ref": "host:" + str(host.get("hostname", "")),
                          "properties": [{"name": "b2s:os", "value": str(host.get("os", ""))}]},
        },
        "components": [comps[k] for k in sorted(comps)],
    }
    doc["serialNumber"] = stable_serial(doc)
    return doc
