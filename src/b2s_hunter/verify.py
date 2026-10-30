"""Post-fix verification: compare a pre-fix baseline to a fresh scan."""

from __future__ import annotations

from .drift import _as_dict, _key
from .model import PATCHED, POTENTIAL, VULNERABLE

FIXED = "fixed"
STILL = "still_vulnerable"
MISSING = "missing"
NOT_EFFECTIVE = "installed_not_effective"

_BAD = (VULNERABLE, POTENTIAL)
_MEM_LAYER = "memory-resident"


def verify_fix(baseline, findings) -> dict:
    """Return {"items": [...], "counts": {...}, "passed": bool}.

    Only baseline VULNERABLE/POTENTIAL items are tracked. Statuses: fixed,
    still_vulnerable, missing, installed_not_effective.
    """
    old_items = baseline["findings"] if isinstance(baseline, dict) else baseline
    cur = {}
    for f in findings:
        d = _as_dict(f)
        cur[_key(d)] = d
    # Text of memory-resident findings still open after the fix.
    mem_text = " ".join(
        d.get("evidence", "") + " " + d.get("location", "")
        for d in cur.values() if d["layer"] == _MEM_LAYER and d["verdict"] in _BAD)

    items = []
    for o in old_items:
        o = _as_dict(o)
        if o["verdict"] not in _BAD:
            continue
        n = cur.get(_key(o))
        item = {"layer": o["layer"], "component": o["component"],
                "location": o["location"], "before": o["verdict"],
                "version_before": o.get("version", ""), "after": "",
                "version_after": "", "status": "", "reason": ""}
        if n is None:
            item["status"] = MISSING
            item["reason"] = "component no longer found (removed, or process restarted)"
        else:
            item["after"] = n["verdict"]
            item["version_after"] = n.get("version", "")
            ver_changed = bool(item["version_after"]) and item["version_after"] != item["version_before"]
            if n["verdict"] == PATCHED:
                if o["location"] and o["location"] in mem_text:
                    item["status"] = NOT_EFFECTIVE
                    item["reason"] = ("patched on disk but a running process still maps the "
                                      "deleted old copy; restart it")
                else:
                    item["status"] = FIXED
                    item["reason"] = "now PATCHED: " + (n.get("evidence") or "fix marker present")
            elif n["layer"] == _MEM_LAYER:
                item["status"] = NOT_EFFECTIVE
                item["reason"] = "deleted library still mapped in memory; restart the process"
            elif n["verdict"] in _BAD and ver_changed:
                item["status"] = NOT_EFFECTIVE
                item["reason"] = (f"version changed {item['version_before']} -> "
                                  f"{item['version_after']} but loaded copy/marker is still "
                                  "vulnerable; rebuild/redeploy/restart")
            elif n["verdict"] in _BAD:
                item["status"] = STILL
                item["reason"] = "still " + n["verdict"] + ": " + (n.get("evidence") or "")
            else:
                item["status"] = STILL
                item["reason"] = f"verdict {n['verdict']}, not confirmed PATCHED"
        items.append(item)

    items.sort(key=lambda i: (i["layer"], i["component"], i["location"]))
    counts = {s: 0 for s in (FIXED, STILL, MISSING, NOT_EFFECTIVE)}
    for i in items:
        counts[i["status"]] += 1
    return {"items": items, "counts": counts,
            "passed": counts[STILL] == 0 and counts[NOT_EFFECTIVE] == 0}
