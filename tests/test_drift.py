import json

from b2s_hunter.drift import diff_findings, load_baseline, save_baseline
from b2s_hunter.model import Finding


def F(comp, verdict="VULNERABLE", version="1.0.5", loc="/a"):
    return Finding("packages", comp, loc, verdict, "high", version=version)


def test_roundtrip_and_metadata(tmp_path):
    p = tmp_path / "b.json"
    save_baseline([F("a"), F("b")], "host1", str(p))
    doc = load_baseline(str(p))
    assert doc["host"] == "host1"
    assert doc["rules_version"] and doc["rules_date"]
    assert len(doc["findings"]) == 2


def test_deterministic_output(tmp_path):
    p1, p2 = tmp_path / "1.json", tmp_path / "2.json"
    save_baseline([F("a"), F("b")], "h", str(p1))
    save_baseline([F("b"), F("a")], "h", str(p2))
    assert p1.read_text() == p2.read_text()
    json.loads(p1.read_text())


def test_new_and_resolved(tmp_path):
    p = tmp_path / "b.json"
    save_baseline([F("a"), F("b")], "h", str(p))
    d = diff_findings(load_baseline(str(p)), [F("b"), F("c")])
    assert [x["component"] for x in d["new"]] == ["c"]
    assert [x["component"] for x in d["resolved"]] == ["a"]
    assert d["unchanged_count"] == 1


def test_changed_verdict_and_version(tmp_path):
    p = tmp_path / "b.json"
    save_baseline([F("a"), F("b")], "h", str(p))
    d = diff_findings(load_baseline(str(p)),
                      [F("a", "PATCHED"), F("b", version="1.2.1")])
    assert len(d["changed"]) == 2
    assert d["changed"][0]["before"]["verdict"] == "VULNERABLE"
    assert d["unchanged_count"] == 0


def test_key_includes_location():
    d = diff_findings([F("a", loc="/x").as_dict()], [F("a", loc="/y")])
    assert len(d["new"]) == 1 and len(d["resolved"]) == 1


def test_empty_diff():
    d = diff_findings([], [])
    assert d == {"new": [], "resolved": [], "changed": [], "unchanged_count": 0}
