"""Offline rules overlay + optional OSV lookup. Network only when fetch_osv is called.

Overlay JSON schema (all keys optional):
  {
    "version": "2026.11.01-1",                      # str, informational
    "date": "2026-11-01",                           # str
    "node_fixed":  {"22": [22, 23, 5]},             # RAISE only; key = major
    "bun_fixed":   [1, 4, 5],                       # RAISE only
    "py_brotli_fixed": [1, 2, 2],                   # RAISE only
    "py_brotlicffi_fixed": [1, 2, 2, 0],            # RAISE only
    "brotli_lines": {"1.2": [1, 2, 2]},             # RAISE only (existing or new line)
    "components": [ {component dict as in ruledata.COMPONENTS, unique "id"} ]
  }
Thresholds may only increase; markers cannot be changed or removed; existing
components cannot be replaced or deleted (new ids only). Violations raise
ValueError. apply_overlay mutates ruledata and returns an undo() callable.
"""

from __future__ import annotations

import copy
import json
import urllib.request

from . import ruledata as rd

USER_AGENT = "b2s-hunter/rules-update (read-only)"
OSV_URL = "https://api.osv.dev/v1/vulns/"
_KEYS = {"version", "date", "node_fixed", "bun_fixed", "py_brotli_fixed",
         "py_brotlicffi_fixed", "brotli_lines", "components"}
_COMP_REQ = {"id", "name", "ecosystem", "purl", "status", "fixed_in", "fix"}
_STATUS = {"fixed", "no-release", "affected", "not-affected", "verify"}


def _tup(v, what):
    if (not isinstance(v, (list, tuple)) or not v or
            not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in v)):
        raise ValueError("%s must be a non-empty list of non-negative ints" % what)
    return tuple(v)


def _pad(a, b):
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _check_raise(new, old, what):
    a, b = _pad(new, old)
    if a < b:
        raise ValueError("%s would lower threshold %s -> %s" % (what, old, new))


def load_overlay(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            ov = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError("overlay unreadable: %s" % exc)
    if not isinstance(ov, dict):
        raise ValueError("overlay must be a JSON object")
    extra = set(ov) - _KEYS
    if extra:
        raise ValueError("unknown overlay keys: %s (markers/other data cannot be changed)"
                         % ", ".join(sorted(extra)))
    out = {}
    for k in ("version", "date"):
        if k in ov:
            if not isinstance(ov[k], str):
                raise ValueError("%s must be a string" % k)
            out[k] = ov[k]
    for key, cur in (("bun_fixed", rd.BUN_FIXED), ("py_brotli_fixed", rd.PY_BROTLI_FIXED),
                     ("py_brotlicffi_fixed", rd.PY_BROTLICFFI_FIXED)):
        if key in ov:
            t = _tup(ov[key], key)
            _check_raise(t, cur, key)
            out[key] = t
    if "node_fixed" in ov:
        if not isinstance(ov["node_fixed"], dict):
            raise ValueError("node_fixed must be an object")
        nf = {}
        for mj, v in ov["node_fixed"].items():
            if not str(mj).isdigit():
                raise ValueError("node_fixed key must be a major number: %r" % mj)
            t = _tup(v, "node_fixed[%s]" % mj)
            if t[0] != int(mj):
                raise ValueError("node_fixed[%s] major mismatch" % mj)
            if int(mj) in rd.NODE_FIXED:
                _check_raise(t, rd.NODE_FIXED[int(mj)], "node_fixed[%s]" % mj)
            nf[int(mj)] = t
        out["node_fixed"] = nf
    if "brotli_lines" in ov:
        if not isinstance(ov["brotli_lines"], dict):
            raise ValueError("brotli_lines must be an object")
        bl = {}
        for ln, v in ov["brotli_lines"].items():
            parts = str(ln).split(".")
            if len(parts) != 2 or not all(p.isdigit() for p in parts):
                raise ValueError("brotli_lines key must be 'major.minor': %r" % ln)
            key = (int(parts[0]), int(parts[1]))
            t = _tup(v, "brotli_lines[%s]" % ln)
            if t[:2] != key:
                raise ValueError("brotli_lines[%s] line mismatch" % ln)
            if key in rd.BROTLI_LINES:
                _check_raise(t, rd.BROTLI_LINES[key], "brotli_lines[%s]" % ln)
            bl[key] = t
        out["brotli_lines"] = bl
    if "components" in ov:
        if not isinstance(ov["components"], list):
            raise ValueError("components must be a list")
        comps, seen = [], {c["id"] for c in rd.COMPONENTS}
        for c in ov["components"]:
            if not isinstance(c, dict) or not _COMP_REQ <= set(c):
                raise ValueError("component needs keys: %s" % ", ".join(sorted(_COMP_REQ)))
            if c["id"] in seen:
                raise ValueError("component id exists or duplicated: %s" % c["id"])
            if c["status"] not in _STATUS:
                raise ValueError("bad component status: %s" % c["status"])
            if c["fixed_in"] is not None and not (
                    isinstance(c["fixed_in"], list) and all(isinstance(x, str) for x in c["fixed_in"])):
                raise ValueError("fixed_in must be null or list of strings")
            seen.add(c["id"])
            comps.append(dict(c))
        out["components"] = comps
    return out


def apply_overlay(overlay):
    """Mutate ruledata with a validated overlay; returns undo()."""
    names = ("RULES_VERSION", "RULES_DATE", "NODE_FIXED", "BUN_FIXED", "PY_BROTLI_FIXED",
             "PY_BROTLICFFI_FIXED", "BROTLI_LINES", "COMPONENTS")
    saved = {n: copy.deepcopy(getattr(rd, n)) for n in names}
    if "version" in overlay:
        rd.RULES_VERSION = overlay["version"]
    if "date" in overlay:
        rd.RULES_DATE = overlay["date"]
    if "bun_fixed" in overlay:
        rd.BUN_FIXED = overlay["bun_fixed"]
    if "py_brotli_fixed" in overlay:
        rd.PY_BROTLI_FIXED = overlay["py_brotli_fixed"]
    if "py_brotlicffi_fixed" in overlay:
        rd.PY_BROTLICFFI_FIXED = overlay["py_brotlicffi_fixed"]
    if "node_fixed" in overlay:
        rd.NODE_FIXED = {**rd.NODE_FIXED, **overlay["node_fixed"]}
    if "brotli_lines" in overlay:
        rd.BROTLI_LINES = {**rd.BROTLI_LINES, **overlay["brotli_lines"]}
    if "components" in overlay:
        rd.COMPONENTS = list(rd.COMPONENTS) + [dict(c) for c in overlay["components"]]

    def undo():
        for n, v in saved.items():
            setattr(rd, n, v)
    return undo


def fetch_osv(url_opener=None, ids=None, timeout=10):
    """Query OSV for each id -> {id: record}. Any failure returns {} (offline-safe).

    url_opener: callable(request, timeout=...) -> file-like (default urlopen).
    """
    ids = tuple(ids) if ids else (rd.CVE_ID,)
    opener = url_opener or urllib.request.urlopen
    out = {}
    try:
        for vid in ids:
            req = urllib.request.Request(OSV_URL + str(vid), headers={
                "User-Agent": USER_AGENT, "Accept": "application/json"})
            resp = opener(req, timeout=timeout)
            try:
                data = json.loads(resp.read().decode("utf-8"))
            finally:
                close = getattr(resp, "close", None)
                if close:
                    close()
            if not isinstance(data, dict):
                return {}
            out[vid] = data
    except Exception:
        return {}
    return out
