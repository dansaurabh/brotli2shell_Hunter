from b2s_hunter.model import PATCHED, POTENTIAL, VULNERABLE, Finding
from b2s_hunter.verify import verify_fix


def F(layer, loc, verdict, version="", ev="", comp="c"):
    return Finding(layer=layer, component=comp, location=loc, verdict=verdict,
                   confidence="high", version=version, evidence=ev)


def base(*fs):
    return {"findings": [f.as_dict() for f in fs]}


def test_fixed():
    r = verify_fix(base(F("binary-marker", "/a", VULNERABLE, "1")),
                   [F("binary-marker", "/a", PATCHED, "2", "fix marker present")])
    assert r["items"][0]["status"] == "fixed"
    assert "fix marker" in r["items"][0]["reason"]
    assert r["passed"]


def test_still_vulnerable():
    r = verify_fix(base(F("l", "/a", VULNERABLE, "1")), [F("l", "/a", VULNERABLE, "1")])
    assert r["items"][0]["status"] == "still_vulnerable"
    assert not r["passed"]


def test_missing():
    r = verify_fix(base(F("l", "/a", POTENTIAL)), [])
    assert r["items"][0]["status"] == "missing"
    assert r["passed"]


def test_version_new_marker_old():
    r = verify_fix(base(F("l", "/a", VULNERABLE, "1")), [F("l", "/a", VULNERABLE, "2")])
    assert r["items"][0]["status"] == "installed_not_effective"
    assert not r["passed"]


def test_deleted_lib_still_mapped():
    old = F("binary-marker", "/usr/lib/libbrotlidec.so", VULNERABLE)
    mem = F("memory-resident", "pid 5 (/x)", POTENTIAL,
            ev="process maps deleted library: /usr/lib/libbrotlidec.so")
    r = verify_fix(base(old), [F("binary-marker", "/usr/lib/libbrotlidec.so", PATCHED), mem])
    assert r["items"][0]["status"] == "installed_not_effective"
    assert not r["passed"]


def test_memory_item_itself_persists():
    mem = F("memory-resident", "pid 5 (/x)", POTENTIAL)
    r = verify_fix(base(mem), [mem])
    assert r["items"][0]["status"] == "installed_not_effective"


def test_non_bad_baseline_ignored_and_counts():
    r = verify_fix(base(F("l", "/ok", PATCHED), F("l", "/a", VULNERABLE)),
                   [F("l", "/a", PATCHED)])
    assert len(r["items"]) == 1
    assert r["counts"]["fixed"] == 1


def test_accepts_dict_findings_and_list_baseline():
    d = F("l", "/a", VULNERABLE).as_dict()
    r = verify_fix([d], [dict(d, verdict=PATCHED)])
    assert r["passed"]
