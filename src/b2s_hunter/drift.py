"""Baseline save/load and drift diff between scans."""

from __future__ import annotations

import json

from . import __version__, ruledata


def _key(f) -> str:
    return f"{f['layer']}|{f['component']}|{f['location']}"


def _as_dict(f) -> dict:
    return f if isinstance(f, dict) else f.as_dict()


def _slim(f) -> dict:
    d = _as_dict(f)
    return {"layer": d["layer"], "component": d["component"],
            "location": d["location"], "verdict": d["verdict"],
            "version": d.get("version", "")}


def save_baseline(findings, host, path):
    """Write a deterministic JSON baseline of findings for later diffing."""
    items = sorted((_slim(f) for f in findings), key=_key)
    doc = {
        "tool_version": __version__,
        "rules_version": ruledata.RULES_VERSION,
        "rules_date": ruledata.RULES_DATE,
        "host": host,
        "findings": items,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return doc


def load_baseline(path) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or "findings" not in doc:
        raise ValueError(f"{path}: not a b2s-hunter baseline")
    return doc


def diff_findings(baseline, findings) -> dict:
    """Compare a baseline (dict from load_baseline, or list of findings) to now.

    Keyed by (layer, component, location). "changed" means verdict or version
    differs; entries carry before/after.
    """
    old_items = baseline["findings"] if isinstance(baseline, dict) else baseline
    old = {_key(_slim(d)): _slim(d) for d in old_items}
    cur = {_key(_slim(d)): _slim(d) for d in findings}
    new = [cur[k] for k in sorted(cur.keys() - old.keys())]
    resolved = [old[k] for k in sorted(old.keys() - cur.keys())]
    changed, same = [], 0
    for k in sorted(cur.keys() & old.keys()):
        a, b = old[k], cur[k]
        if a["verdict"] != b["verdict"] or a["version"] != b["version"]:
            changed.append({"layer": b["layer"], "component": b["component"],
                            "location": b["location"], "before": a, "after": b})
        else:
            same += 1
    return {"new": new, "resolved": resolved, "changed": changed,
            "unchanged_count": same}
