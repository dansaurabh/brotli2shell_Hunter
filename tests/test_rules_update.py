import io
import json

import pytest

from b2s_hunter import ruledata as rd
from b2s_hunter import rules_update as ru


def W(tmp_path, obj):
    p = tmp_path / "o.json"
    p.write_text(json.dumps(obj))
    return p


NEWC = {"id": "x-new", "name": "X", "ecosystem": "npm", "purl": "pkg:npm/x",
        "status": "affected", "fixed_in": None, "fix": "none"}


def test_raise_threshold_and_undo(tmp_path):
    ov = ru.load_overlay(W(tmp_path, {"node_fixed": {"22": [22, 23, 5]}, "bun_fixed": [1, 4, 5]}))
    old_node, old_bun = dict(rd.NODE_FIXED), rd.BUN_FIXED
    undo = ru.apply_overlay(ov)
    assert rd.NODE_FIXED[22] == (22, 23, 5) and rd.BUN_FIXED == (1, 4, 5)
    undo()
    assert rd.NODE_FIXED == old_node and rd.BUN_FIXED == old_bun


def test_lowering_rejected(tmp_path):
    with pytest.raises(ValueError):
        ru.load_overlay(W(tmp_path, {"node_fixed": {"22": [22, 0, 1]}}))
    with pytest.raises(ValueError):
        ru.load_overlay(W(tmp_path, {"py_brotli_fixed": [1, 0, 0]}))


def test_marker_and_unknown_keys_rejected(tmp_path):
    with pytest.raises(ValueError):
        ru.load_overlay(W(tmp_path, {"MARK_FIXED": "x"}))


def test_add_component_and_undo(tmp_path):
    ov = ru.load_overlay(W(tmp_path, {"components": [NEWC]}))
    n = len(rd.COMPONENTS)
    undo = ru.apply_overlay(ov)
    assert len(rd.COMPONENTS) == n + 1
    undo()
    assert len(rd.COMPONENTS) == n and all(c["id"] != "x-new" for c in rd.COMPONENTS)


def test_component_validation(tmp_path):
    with pytest.raises(ValueError):
        ru.load_overlay(W(tmp_path, {"components": [dict(NEWC, id="nodejs")]}))
    with pytest.raises(ValueError):
        ru.load_overlay(W(tmp_path, {"components": [dict(NEWC, status="bogus")]}))
    with pytest.raises(ValueError):
        ru.load_overlay(W(tmp_path, {"components": [{"id": "z"}]}))


def test_bad_file(tmp_path):
    with pytest.raises(ValueError):
        ru.load_overlay(tmp_path / "nope.json")
    with pytest.raises(ValueError):
        ru.load_overlay(W(tmp_path, [1]))


def test_fetch_osv_ok():
    seen = []

    def opener(req, timeout=None):
        seen.append((req.full_url, timeout))
        return io.BytesIO(b'{"id": "CVE-2026-111497"}')
    out = ru.fetch_osv(opener)
    assert out == {rd.CVE_ID: {"id": "CVE-2026-111497"}}
    assert seen[0][0] == "https://api.osv.dev/v1/vulns/" + rd.CVE_ID and seen[0][1]


def test_fetch_osv_network_error_returns_empty():
    def opener(req, timeout=None):
        raise OSError("offline")
    assert ru.fetch_osv(opener) == {}


def test_fetch_osv_bad_json_returns_empty():
    assert ru.fetch_osv(lambda r, timeout=None: io.BytesIO(b"<html>")) == {}
