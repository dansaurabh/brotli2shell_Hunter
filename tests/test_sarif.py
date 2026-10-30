import json

from b2s_hunter import ruledata as rd
from b2s_hunter.model import CLEAN, PATCHED, POTENTIAL, REVIEW, VULNERABLE, Finding
from b2s_hunter.sarif import build_sarif

HOST = {"hostname": "h1", "os": "linux", "time": "2026-10-30T00:00:00Z"}


def F(verdict, loc="/usr/lib/libbrotlidec.so.1", **kw):
    return Finding(layer="binary", component="libbrotlidec", location=loc,
                   verdict=verdict, confidence="high", version="1.0.9", **kw)


def test_top_level_shape():
    s = build_sarif([F(VULNERABLE)], HOST)
    assert s["version"] == "2.1.0" and "$schema" in s
    drv = s["runs"][0]["tool"]["driver"]
    assert drv["version"] == rd.RULES_VERSION
    assert [r["id"] for r in drv["rules"]] == [rd.CVE_ID]


def test_level_mapping():
    res = build_sarif([F(VULNERABLE), F(POTENTIAL, "/b"), F(REVIEW, "/c")], HOST)["runs"][0]["results"]
    assert {r["level"] for r in res} == {"error", "warning", "note"}
    assert all(r["ruleId"] == rd.CVE_ID for r in res)


def test_patched_and_clean_excluded():
    s = build_sarif([F(PATCHED), F(CLEAN)], HOST)
    assert s["runs"][0]["results"] == []


def test_physical_location_and_fallback():
    res = build_sarif([F(VULNERABLE, "/opt/a b/x.so"), F(VULNERABLE, "pip:Brotli")], HOST)["runs"][0]["results"]
    uris = [r["locations"][0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            for r in res]
    assert "/opt/a%20b/x.so" in uris
    fb = [r for r in res if "logicalLocations" in r["locations"][0]]
    assert len(fb) == 1


def test_windows_path_uri():
    r = build_sarif([F(VULNERABLE, "C:\\app\\x.dll")], HOST)["runs"][0]["results"][0]
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "file:///C:/app/x.dll"


def test_properties():
    r = build_sarif([F(VULNERABLE, reach="reachable-untrusted", priority=90, fix="upgrade")],
                    HOST)["runs"][0]["results"][0]
    p = r["properties"]
    assert (p["confidence"], p["reach"], p["priority"], p["fix"]) == (
        "high", "reachable-untrusted", 90, "upgrade")


def test_deterministic_and_json():
    fs = [F(VULNERABLE, "/a", priority=1), F(VULNERABLE, "/b", priority=5)]
    a = json.dumps(build_sarif(fs, HOST), sort_keys=True)
    b = json.dumps(build_sarif(list(reversed(fs)), HOST), sort_keys=True)
    assert a == b
