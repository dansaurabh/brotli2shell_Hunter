import json

from b2s_hunter import ruledata as rd
from b2s_hunter.model import CLEAN, PATCHED, POTENTIAL, REVIEW, VULNERABLE, Finding
from b2s_hunter.sbom_out import build_cyclonedx_sbom
from b2s_hunter.vex import build_cyclonedx_vex, build_openvex, derive_vex

HOST = {"hostname": "h1", "os": "linux", "time": "2026-10-30T00:00:00Z"}


def F(verdict, loc="/x.so", **kw):
    return Finding(layer="binary", component="brotli", location=loc,
                   verdict=verdict, confidence="high", version="1.0.9", **kw)


def test_derive_basic():
    assert derive_vex(F(PATCHED)) == ("fixed", "")
    assert derive_vex(F(VULNERABLE))[0] == "affected"
    assert derive_vex(F(POTENTIAL))[0] == "affected"
    assert derive_vex(F(REVIEW))[0] == "under_investigation"
    assert derive_vex(F(CLEAN))[0] == "not_affected"


def test_derive_trusted_only():
    assert derive_vex(F(VULNERABLE, reach="trusted-only")) == (
        "not_affected", "vulnerable_code_not_in_execute_path")


def test_derive_explicit_wins():
    f = F(VULNERABLE, vex_status="under_investigation", vex_justification="j")
    assert derive_vex(f) == ("under_investigation", "j")


def test_cyclonedx_vex_shape_and_refs():
    fs = [F(VULNERABLE, "/a"), F(VULNERABLE, "/b", reach="trusted-only"), F(PATCHED, "/c")]
    doc = build_cyclonedx_vex(fs, HOST)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    states = {v["analysis"]["state"] for v in doc["vulnerabilities"]}
    assert states == {"exploitable", "not_affected", "resolved"}
    for v in doc["vulnerabilities"]:
        assert v["id"] == rd.CVE_ID and v["affects"]
        if v["analysis"]["state"] == "not_affected":
            assert v["analysis"]["justification"] == "code_not_reachable"


def test_cyclonedx_vex_refs_match_sbom():
    fs = [F(VULNERABLE, "/a"), F(PATCHED, "/c")]
    refs = {c["bom-ref"] for c in build_cyclonedx_sbom(fs, HOST)["components"]}
    vrefs = {a["ref"] for v in build_cyclonedx_vex(fs, HOST)["vulnerabilities"]
             for a in v["affects"]}
    assert vrefs == refs


def test_openvex_shape():
    fs = [F(VULNERABLE, "/a", fix="upgrade to 1.1.1"), F(VULNERABLE, "/b", reach="trusted-only"),
          F(PATCHED, "/c"), F(REVIEW, "/d")]
    doc = build_openvex(fs, HOST)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["@id"] and doc["author"] and doc["timestamp"] and doc["version"] == 1
    by = {}
    for s in doc["statements"]:
        by.setdefault(s["status"], []).append(s)
        assert s["vulnerability"]["name"] == rd.CVE_ID and s["products"]
    assert set(by) == {"affected", "not_affected", "fixed", "under_investigation"}
    assert by["affected"][0]["action_statement"] == "upgrade to 1.1.1"
    assert by["not_affected"][0]["justification"] == "vulnerable_code_not_in_execute_path"


def test_deterministic():
    fs = [F(VULNERABLE, "/a"), F(PATCHED, "/c")]
    for fn in (build_cyclonedx_vex, build_openvex):
        a = json.dumps(fn(fs, HOST), sort_keys=True)
        b = json.dumps(fn(list(reversed(fs)), HOST), sort_keys=True)
        assert a == b
