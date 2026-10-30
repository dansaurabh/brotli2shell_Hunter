import json

from b2s_hunter import ruledata as rd
from b2s_hunter.model import CLEAN, PATCHED, REVIEW, VULNERABLE, Finding
from b2s_hunter.sbom_out import component_ref
from b2s_hunter.vex_csaf import build_csaf_vex

HOST = {"hostname": "h1", "os": "linux", "time": "2026-10-30T00:00:00Z"}


def F(verdict, loc="/x.so", comp="brotli", **kw):
    return Finding(layer="binary", component=comp, location=loc,
                   verdict=verdict, confidence="high", version="1.0.9", **kw)


def test_document_meta():
    d = build_csaf_vex([F(VULNERABLE)], HOST)["document"]
    assert d["category"] == "csaf_vex" and d["csaf_version"] == "2.0"
    assert d["tracking"]["id"].startswith("b2s-")
    assert d["tracking"]["current_release_date"] == HOST["time"]


def test_product_status_buckets():
    fs = [F(VULNERABLE, "/a"), F(CLEAN, "/b"), F(PATCHED, "/c"), F(REVIEW, "/d")]
    ps = build_csaf_vex(fs, HOST)["vulnerabilities"][0]["product_status"]
    assert set(ps) == {"known_affected", "known_not_affected", "fixed", "under_investigation"}
    assert ps["fixed"] == [component_ref(fs[2])]


def test_empty_status_omitted():
    ps = build_csaf_vex([F(PATCHED)], HOST)["vulnerabilities"][0]["product_status"]
    assert list(ps) == ["fixed"]


def test_flags_for_not_in_path():
    v = build_csaf_vex([F(VULNERABLE, reach="trusted-only")], HOST)["vulnerabilities"][0]
    assert v["flags"][0]["label"] == "vulnerable_code_not_in_execute_path"
    assert "known_not_affected" in v["product_status"]


def test_flag_component_not_present():
    v = build_csaf_vex([F(CLEAN)], HOST)["vulnerabilities"][0]
    assert v["flags"][0]["label"] == "component_not_present"


def test_remediation_from_fix_and_default():
    fs = [F(VULNERABLE, "/a", fix="upgrade to 1.2.1"), F(VULNERABLE, "/b")]
    rem = build_csaf_vex(fs, HOST)["vulnerabilities"][0]["remediations"]
    assert {r["details"] for r in rem} == {"upgrade to 1.2.1", rd.FIX_HINT}
    assert all(r["category"] == "vendor_fix" for r in rem)


def test_product_tree_has_every_product_id():
    fs = [F(VULNERABLE, "/a"), F(PATCHED, "/b", comp="node")]
    doc = build_csaf_vex(fs, HOST)

    def leaves(bs):
        for b in bs:
            if "product" in b:
                yield b["product"]["product_id"]
            yield from leaves(b.get("branches", []))
    assert set(leaves(doc["product_tree"]["branches"])) == {component_ref(f) for f in fs}


def test_deterministic_and_json_safe():
    fs = [F(VULNERABLE, "/a"), F(CLEAN, "/b")]
    a = build_csaf_vex(fs, HOST)
    assert a == build_csaf_vex(list(reversed(fs)), HOST)
    json.dumps(a)


def test_cve_in_vulnerability():
    assert build_csaf_vex([], HOST)["vulnerabilities"][0]["cve"] == rd.CVE_ID
