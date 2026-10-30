"""VEX emission: CycloneDX 1.5 VEX and OpenVEX v0.2.0."""

from __future__ import annotations

from . import ruledata as rd
from .model import CLEAN, PATCHED, POTENTIAL, VULNERABLE
from .sbom_out import component_ref, stable_serial, synth_purl

NOT_IN_PATH = "vulnerable_code_not_in_execute_path"
NOT_PRESENT = "component_not_present"

_CDX_STATE = {"affected": "exploitable", "not_affected": "not_affected",
              "under_investigation": "in_triage", "fixed": "resolved"}
_CDX_JUST = {NOT_IN_PATH: "code_not_reachable", NOT_PRESENT: "code_not_present"}


def derive_vex(f):
    """Return (status, justification); finding.vex_status wins when set."""
    if f.vex_status:
        return f.vex_status, f.vex_justification
    if f.verdict == PATCHED:
        return "fixed", ""
    if f.verdict == CLEAN:
        return "not_affected", NOT_PRESENT
    if f.reach == "trusted-only":
        return "not_affected", NOT_IN_PATH
    if f.verdict in (VULNERABLE, POTENTIAL):
        return "affected", ""
    return "under_investigation", ""


def build_cyclonedx_vex(findings, host):
    per_ref = {}
    for f in findings:
        status, just = derive_vex(f)
        a = {"state": _CDX_STATE.get(status, "in_triage")}
        if status == "not_affected" and just:
            a["justification"] = _CDX_JUST.get(just, "requires_environment")
        detail = "; ".join(x for x in (f.note, f.gate, f.impact) if x)
        if f.fix and status in ("affected", "under_investigation"):
            detail = "; ".join(x for x in (detail, "fix: " + f.fix) if x)
        if detail:
            a["detail"] = detail
        per_ref[component_ref(f)] = a
    # one vulnerability entry per distinct analysis (the CVE id is shared)
    groups = {}
    for ref in sorted(per_ref):
        a = per_ref[ref]
        groups.setdefault((a["state"], a.get("justification", ""), a.get("detail", "")),
                          []).append(ref)
    vulns = []
    for key in sorted(groups):
        analysis = {"state": key[0]}
        if key[1]:
            analysis["justification"] = key[1]
        if key[2]:
            analysis["detail"] = key[2]
        vulns.append({
            "bom-ref": f"{rd.CVE_ID}:{len(vulns)}",
            "id": rd.CVE_ID,
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{rd.CVE_ID}"},
            "analysis": analysis,
            "affects": [{"ref": r} for r in groups[key]],
        })
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"timestamp": host.get("time", ""),
                     "tools": {"components": [{"type": "application", "name": "b2s-hunter",
                                               "version": rd.RULES_VERSION}]}},
        "vulnerabilities": vulns,
    }
    doc["serialNumber"] = stable_serial(doc)
    return doc


def build_openvex(findings, host):
    stmts = []
    for f in findings:
        status, just = derive_vex(f)
        purl = synth_purl(f)
        s = {
            "vulnerability": {"name": rd.CVE_ID, "aliases": list(rd.CVE_ALIASES)},
            "products": [{"@id": purl, "identifiers": {"purl": purl}}],
            "status": status,
        }
        if status == "not_affected":
            s["justification"] = just or NOT_IN_PATH
        if status == "affected":
            s["action_statement"] = f.fix or rd.FIX_HINT
        stmts.append(s)
    stmts.sort(key=lambda s: (s["products"][0]["@id"], s["status"],
                              s.get("action_statement", "")))
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "author": "b2s-hunter",
        "role": "scanner",
        "timestamp": host.get("time", ""),
        "version": 1,
        "tooling": f"b2s-hunter {rd.RULES_VERSION}",
        "statements": stmts,
    }
    doc["@id"] = "https://openvex.dev/docs/b2s/" + stable_serial(doc)[len("urn:uuid:"):]
    return doc
