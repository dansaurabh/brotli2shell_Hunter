"""Reachability enrichment: reach / direction / input trust / priority (spec 2.1-2.4)."""

from __future__ import annotations

import re

from .model import CLEAN, PATCHED, POTENTIAL, REVIEW, SEVERITY, VULNERABLE

# --- heuristic rule table (data). First match wins; matched against the lowercased
# "layer component location evidence note" string of a finding. -------------------
# keys: rx, reach, direction, trust, gate, inet (internet-facing), why
RULES = [
    # V8 bundled decoder only decodes its own startup snapshot: trusted, down-rank.
    {"rx": r"v8.*(snapshot|startup)|startup.?snapshot|snapshot.*v8",
     "reach": "trusted-only", "direction": "file", "trust": "trusted", "gate": "",
     "inet": False, "why": "bundled decoder only reads the build-time startup snapshot"},
    # Config-gated infra: only exposed when Brotli decompression is switched on.
    {"rx": r"envoy|istio",
     "reach": "config-gated", "direction": "inbound", "trust": "untrusted",
     "gate": "only if Brotli (de)compression is enabled in the proxy/filter config",
     "inet": True, "why": "proxy decode path exists only when the Brotli filter is configured"},
    # Python clients auto-use Brotli only when a Brotli package is installed.
    {"rx": r"\b(requests|httpx|aiohttp|urllib3)\b|brotlicffi|brotli \(pypi\)|package:pip",
     "reach": "config-gated", "direction": "outbound", "trust": "untrusted",
     "gate": "only if the Brotli/brotlicffi package is installed (clients then auto-decode br)",
     "inet": False, "why": "malicious server response decoded by an HTTP client"},
    # 2.1 server-side inbound
    {"rx": r"express|body-?parser|asp\.?net|kestrel|clickhouse|nginx|haproxy|traefik|caddy|"
           r"reverse.?proxy|load.?balancer|request.?decompress|content-encoding",
     "reach": "reachable-untrusted", "direction": "inbound", "trust": "untrusted", "gate": "",
     "inet": True, "why": "request-body / proxy Brotli decode on a network-facing service"},
    # 2.1 client-side outbound
    {"rx": r"fetch|undici|curl|wget|crawler|spider|scrap|browsing|headless|puppeteer|playwright|"
           r"chromedriver|ci runner|runner|cdxgen|sbom generator|http client|runtime:node|runtime:bun|"
           r"\bnode\.?js\b|\bbun\b",
     "reach": "reachable-untrusted", "direction": "outbound", "trust": "untrusted", "gate": "",
     "inet": False, "why": "a malicious server can attack a client that auto-decodes responses"},
    # 2.1 file / data path
    {"rx": r"libjxl|jpeg ?xl|\bjxl\b|brob|ffmpeg|parquet|arrow|duckdb|woff2|\bwoff\b|font|"
           r"firmware|archive|queue",
     "reach": "reachable-untrusted", "direction": "file", "trust": "untrusted", "gate": "",
     "inet": False, "why": "crafted file/data (image, Parquet page, font) decoded without HTTP"},
]
_RULES = [(re.compile(r["rx"]), r) for r in RULES]

# Verdict -> base weight (0-100 scale), reach / trust multipliers.
VERDICT_WEIGHT = {VULNERABLE: 100, POTENTIAL: 75, REVIEW: 45, PATCHED: 8, CLEAN: 0}
REACH_FACTOR = {"reachable-untrusted": 1.0, "config-gated": 0.7, "unknown": 0.6, "trusted-only": 0.25}
TRUST_FACTOR = {"untrusted": 1.0, "": 0.8, "trusted": 0.4}
INTERNET_FACTOR = 0.8     # applied when NOT internet-facing (keeps max at 100)

IMPACT = ("Default outcome is DoS (crash/memory exhaustion) plus limited memory disclosure; "
          "RCE is situational (build hardening, allocator, platform), so do not rate on the CVSS 9.2 headline alone.")


def _hay(f):
    return " ".join((f.layer, f.component, f.location, f.evidence, f.note)).lower()


def _classify(f):
    hay = _hay(f)
    for rx, rule in _RULES:
        if rx.search(hay):
            return rule
    return None


def _priority(f):
    base = VERDICT_WEIGHT.get(f.verdict, 0)
    score = base * REACH_FACTOR.get(f.reach, 0.6) * TRUST_FACTOR.get(f.input_trust, 0.8)
    if not f.internet_facing:
        score *= INTERNET_FACTOR
    if f.verdict in (PATCHED, CLEAN):
        score = min(score, 10)       # already fixed / unaffected: never urgent
    return max(0, min(100, int(round(score))))


def enrich_reachability(findings, source_hits=None) -> None:
    """Set reach/direction/input_trust/gate/internet_facing/impact/priority in place.

    source_hits: optional iterable of source-reachability labels or Finding objects;
    when present they promote otherwise-unclassified findings to reachable-untrusted.
    """
    have_hits = bool(list(source_hits or []))
    for f in findings:
        rule = _classify(f)
        if rule is not None:
            f.reach, f.direction, f.input_trust = rule["reach"], rule["direction"], rule["trust"]
            f.gate, f.internet_facing = rule["gate"], rule["inet"]
        elif have_hits and f.layer != "source-reachability" and SEVERITY.get(f.verdict, 0) >= SEVERITY[REVIEW]:
            f.reach, f.input_trust = "reachable-untrusted", "untrusted"
            f.gate = "source shows a decode entry point; confirm this library is the one linked"
        else:
            f.reach = "unknown"
        f.impact = IMPACT
        if f.reach == "trusted-only":
            f.impact += " Input is trusted (startup snapshot), so exploitation needs a separate way to alter it."
        f.priority = _priority(f)
