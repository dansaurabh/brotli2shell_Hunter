"""Mitigation enrichment: exact fix, install!=fixed restart, controls, gaps, verify.

Mutates Finding objects in place; only fix/restart/controls/not_covered/verify are set.
"""

from __future__ import annotations

import re

from . import ruledata as rd
from .model import CLEAN, PATCHED

BACKPORT_FIX = "no action - backport-patched"
CHERRY_PICK = f"cherry-pick upstream commit {rd.UPSTREAM_FIX_COMMIT}"

# Ordered (keyword, component id) rules; first hit on the lowercased component wins.
_ID_RULES = [
    ("brotlicffi", "py-brotlicffi"), ("brotli (pypi)", "py-brotli"), ("pypi", "py-brotli"),
    ("node", "nodejs"), ("bun", "bun"), ("deno", "deno"), (".net", "dotnet"), ("dotnet", "dotnet"),
    ("curl", "curl"), ("andybalholm", "go-andybalholm"), ("brotli4j", "java-brotli4j"),
    ("decompressor", "rust-brotli-decompressor"), ("kjdev", "php-kjdev"), ("ruby", "ruby-brotli"),
    ("clickhouse", "clickhouse"), ("pyarrow", "arrow"), ("arrow", "arrow"), ("duckdb", "duckdb"),
    ("ydb", "ydb"), ("libjxl", "libjxl"), ("graaljs", "graaljs"), ("woff2", "woff2"),
    ("mupdf", "mupdf"), ("uefitool", "uefitool"), ("edk2", "edk2"), ("edk ii", "edk2"),
    ("7-zip", "7zip-zstd"), ("p7zip", "7zip-zstd"), ("nanazip", "nanazip"), ("v8-jsi", "v8-jsi"),
    ("envoy", "envoy"), ("istio", "istio"), ("cdxgen", "cdxgen"),
]
_BACKPORT_RE = re.compile(
    r"backport-patched|reconcil\w*[^.;]*(fix|patch)|fix marker[^.;]*(present|found)|"
    r"carries[^.;]*fix", re.I)

INBOUND_CONTROL = "Reject Content-Encoding: br request bodies at proxy / LB / WAF"
INGEST_CONTROL = ("Isolate untrusted file/data ingestion from unpatched engines "
                  "(DuckDB, Arrow, ClickHouse)")
PROXY_CONTROL = "Disable Brotli in Envoy / Istio / nginx where enabled"
PY_CONTROL = "Uninstall Brotli / brotlicffi and drop [brotli] extras (clients fall back to gzip/deflate)"

# Component-specific controls (data table).
COMPONENT_CONTROLS = {
    "envoy": ["Disable the Brotli decompressor filter in Envoy where enabled"],
    "istio": ["Disable Brotli decompression in the Istio/Envoy filter chain where enabled"],
    "py-brotli": [PY_CONTROL],
    "py-brotlicffi": [PY_CONTROL],
    "clickhouse": [INGEST_CONTROL],
    "arrow": [INGEST_CONTROL],
    "duckdb": [INGEST_CONTROL],
}
GENERIC_CONTROLS = [PROXY_CONTROL, PY_CONTROL, INGEST_CONTROL]

NOT_COVERED = ("Outbound/client-side fetches cannot be WAF'd: a malicious server still "
               "sends Brotli responses your app decodes. Only a library/runtime upgrade "
               "closes that path; stripping br from Accept-Encoding helps little.")

RESTART = ("Install != fixed: rebuild image -> redeploy -> restart process -> re-pin "
           "lockfile. A deleted/replaced library still mapped in memory keeps running the "
           "old decoder until the process restarts (look for '(deleted)' in /proc/<pid>/maps).")

VERIFY = (f"Rescan after restart and confirm the loaded copy carries the fix marker "
          f"{rd.MARK_FIXED.decode()}, not just that a new version is installed.")

MINIMAL_PATCHED = "no action - already patched"
MINIMAL_CLEAN = "no action - not affected"

_SKIP = {PATCHED, CLEAN}


def _component_id(f):
    name = (f.component or "").lower()
    for kw, cid in _ID_RULES:
        if kw in name:
            return cid
    if "brotli" in name:
        return "brotli-c"
    return ""


def _entry(cid):
    return next((c for c in rd.COMPONENTS if c["id"] == cid), None)


def _fix_text(cid):
    ent = _entry(cid)
    if ent is None:
        return f"Upgrade the Brotli decoder to a fixed build ({rd.FIX_HINT}) or {CHERRY_PICK}"
    if ent["status"] == "not-affected":
        return f"{ent['name']}: no action - component not affected"
    fixed = ent.get("fixed_in")
    if fixed:
        text = f"{ent['name']}: upgrade to {' / '.join(fixed)}"
        if cid == "brotli-c":
            text += f" (vendored/static source with no release: {CHERRY_PICK})"
        return text
    if ent["status"] in ("no-release", "affected"):
        return f"{ent['name']}: no fixed release; {CHERRY_PICK} (vendored build); {ent['fix']}"
    return f"{ent['name']}: {ent['fix']}"


def _controls(f, cid):
    out = [INBOUND_CONTROL]
    out += COMPONENT_CONTROLS.get(cid) or GENERIC_CONTROLS
    if "nginx" in (f.component or "").lower():
        out.append("Disable Brotli modules/decompression in nginx")
    return list(dict.fromkeys(out))


def enrich_mitigation(findings) -> None:
    """Fill fix/restart/controls/not_covered/verify on each Finding in place."""
    for f in findings:
        if f.verdict == PATCHED:
            f.fix, f.restart, f.controls, f.not_covered, f.verify = MINIMAL_PATCHED, "", [], "", ""
        elif f.verdict == CLEAN:
            f.fix, f.restart, f.controls, f.not_covered, f.verify = MINIMAL_CLEAN, "", [], "", ""
        elif _BACKPORT_RE.search(f"{f.evidence} {f.note}"):
            f.fix, f.restart, f.controls, f.not_covered = BACKPORT_FIX, "", [], ""
            f.verify = VERIFY
        else:
            cid = _component_id(f)
            f.fix = _fix_text(cid)
            f.restart = RESTART
            f.controls = _controls(f, cid)
            f.not_covered = NOT_COVERED
            f.verify = VERIFY


def remediation_plan(findings) -> list:
    """Group actionable findings by component with deduplicated steps."""
    groups = {}
    for f in findings:
        if f.verdict in _SKIP or f.fix in ("", BACKPORT_FIX):
            continue
        g = groups.setdefault(f.component, {
            "component": f.component, "verdicts": [], "locations": [], "fix": [],
            "restart": [], "controls": [], "not_covered": [], "verify": []})
        for key, val in (("verdicts", f.verdict), ("locations", f.location), ("fix", f.fix),
                         ("restart", f.restart), ("not_covered", f.not_covered),
                         ("verify", f.verify)):
            if val and val not in g[key]:
                g[key].append(val)
        for c in f.controls:
            if c not in g["controls"]:
                g["controls"].append(c)
    return list(groups.values())
