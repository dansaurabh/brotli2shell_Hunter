"""CSAF 2.0 VEX emission (csaf_vex profile)."""

from __future__ import annotations

from . import ruledata as rd
from .sbom_out import component_ref, stable_serial, synth_purl
from .vex import NOT_IN_PATH, NOT_PRESENT, derive_vex

_FLAGS = {NOT_IN_PATH, NOT_PRESENT, "inline_mitigations_already_exist",
          "vulnerable_code_cannot_be_controlled_by_adversary"}
_KEY = {"affected": "known_affected", "not_affected": "known_not_affected",
        "fixed": "fixed", "under_investigation": "under_investigation"}


def build_csaf_vex(findings, host):
    now = host.get("time", "")
    hostname = str(host.get("hostname", "")) or "unknown-host"
    products = {}                      # product_id -> (finding, status, justification)
    for f in findings:
        status, just = derive_vex(f)
        products[component_ref(f)] = (f, status, just)
    ids = sorted(products)

    # product_tree: vendor(host) -> product_name -> product_version leaf
    by_name = {}
    for pid in ids:
        by_name.setdefault(products[pid][0].component or "unknown", []).append(pid)
    name_branches = []
    for name in sorted(by_name):
        leaves = []
        for pid in by_name[name]:
            f = products[pid][0]
            leaves.append({
                "category": "product_version",
                "name": f.version or "unknown",
                "product": {"name": f"{name} {f.version}".strip(), "product_id": pid,
                            "product_identification_helper": {"purl": synth_purl(f)}},
            })
        name_branches.append({"category": "product_name", "name": name, "branches": leaves})
    tree = {"branches": [{"category": "vendor", "name": hostname, "branches": name_branches}]}

    status_ids = {"known_affected": [], "known_not_affected": [], "fixed": [],
                  "under_investigation": []}
    flag_groups, fix_groups = {}, {}
    for pid in ids:
        f, status, just = products[pid]
        k = _KEY.get(status, "under_investigation")
        status_ids[k].append(pid)
        if k == "known_not_affected":
            flag_groups.setdefault(just if just in _FLAGS else NOT_IN_PATH, []).append(pid)
        elif k == "known_affected":
            fix_groups.setdefault(f.fix or rd.FIX_HINT, []).append(pid)
    vuln = {
        "cve": rd.CVE_ID,
        "title": " / ".join(rd.CVE_ALIASES),
        "product_status": {k: v for k, v in status_ids.items() if v},
    }
    if flag_groups:
        vuln["flags"] = [{"label": lab, "product_ids": flag_groups[lab]}
                         for lab in sorted(flag_groups)]
    if fix_groups:
        vuln["remediations"] = [{"category": "vendor_fix", "details": d,
                                 "product_ids": fix_groups[d]} for d in sorted(fix_groups)]
    notes = sorted({(products[p][0].note, p) for p in ids if products[p][0].note})
    if notes:
        vuln["notes"] = [{"category": "details", "text": f"{n} [{p}]"} for n, p in notes]

    doc = {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": f"b2s-hunter VEX for {rd.CVE_ID} on {hostname}",
            "publisher": {"category": "tool", "name": "b2s-hunter",
                          "namespace": "https://github.com/dansaurabh/brotli2shell_Hunter"},
            "lang": "en",
            "distribution": {"tlp": {"label": "WHITE"}},
            "tracking": {
                "id": "", "status": "final", "version": "1",
                "initial_release_date": now, "current_release_date": now,
                "generator": {"engine": {"name": "b2s-hunter", "version": rd.RULES_VERSION}},
                "revision_history": [{"date": now, "number": "1", "summary": "Initial scan"}],
            },
        },
        "product_tree": tree,
        "vulnerabilities": [vuln],
    }
    doc["document"]["tracking"]["id"] = "b2s-" + stable_serial(doc)[len("urn:uuid:"):]
    return doc
