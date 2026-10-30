import json

from b2s_hunter import rulesig
from b2s_hunter import ruledata as rd


def test_digest_deterministic():
    assert rulesig.rules_digest() == rulesig.rules_digest()
    assert len(rulesig.rules_digest()) == 64


def test_digest_changes_with_data(monkeypatch):
    d = rulesig.rules_digest()
    monkeypatch.setattr(rd, "BUN_FIXED", (9, 9, 9))
    assert rulesig.rules_digest() != d


def test_digest_changes_with_marker(monkeypatch):
    d = rulesig.rules_digest()
    monkeypatch.setattr(rd, "MARK_FIXED", b"x")
    assert rulesig.rules_digest() != d


def test_manifest_roundtrip(tmp_path):
    p = tmp_path / "m.json"
    m = rulesig.write_manifest(p)
    assert m["rules_version"] == rd.RULES_VERSION
    ok, why = rulesig.verify_manifest(p)
    assert ok and "unsigned" in why


def test_tamper_detected(tmp_path, monkeypatch):
    p = tmp_path / "m.json"
    rulesig.write_manifest(p)
    monkeypatch.setattr(rd, "NODE_FIXED", {22: (22, 0, 0)})
    ok, why = rulesig.verify_manifest(p)
    assert not ok and "digest" in why


def test_version_mismatch(tmp_path):
    p = tmp_path / "m.json"
    rulesig.write_manifest(p)
    m = json.loads(p.read_text())
    m["rules_version"] = "old"
    p.write_text(json.dumps(m))
    assert not rulesig.verify_manifest(p)[0]


def test_pinned_digest_and_bad_file(tmp_path):
    p = tmp_path / "m.json"
    rulesig.write_manifest(p)
    assert not rulesig.verify_manifest(p, pinned_digest="0" * 64)[0]
    assert not rulesig.verify_manifest(tmp_path / "none.json")[0]


def test_signature_unavailable_fails_closed(tmp_path, monkeypatch):
    p = tmp_path / "m.json"
    rulesig.write_manifest(p)
    (tmp_path / "m.json.sig").write_text("00")
    monkeypatch.setattr(rulesig, "_verify_signature",
                        lambda *a: (False, "signature check unavailable (cryptography not installed)"))
    ok, why = rulesig.verify_manifest(p, pubkey="00" * 32)
    assert not ok and "unavailable" in why


def test_signature_missing_file(tmp_path):
    p = tmp_path / "m.json"
    rulesig.write_manifest(p)
    ok, why = rulesig.verify_manifest(p, pubkey="00" * 32)
    assert not ok and "missing" in why
