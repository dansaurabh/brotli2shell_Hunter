from b2s_hunter import ruledata as rd
from b2s_hunter.mitigation import BACKPORT_FIX, enrich_mitigation, remediation_plan
from b2s_hunter.model import CLEAN, PATCHED, VULNERABLE, Finding


def _f(component, verdict=VULNERABLE, **kw):
    return Finding(layer="t", component=component, location=kw.pop("location", "/x"),
                   verdict=verdict, confidence="high", **kw)


def _run(f):
    enrich_mitigation([f])
    return f


def test_pypi_brotli_exact_fix():
    assert "1.2.1" in _run(_f("Brotli (PyPI)", version="1.2.0")).fix


def test_brotlicffi_fix_and_control():
    f = _run(_f("brotlicffi (PyPI)"))
    assert "1.2.1.0" in f.fix
    assert any("brotlicffi" in c for c in f.controls)


def test_node_fix_lists_lines():
    f = _run(_f("Node.js"))
    assert "22.23.4" in f.fix and "24.22.1" in f.fix and "26.12.1" in f.fix


def test_vendored_embedded_cherry_pick():
    assert rd.UPSTREAM_FIX_COMMIT in _run(_f("brotli-decoder (embedded)")).fix


def test_no_release_component_cherry_pick():
    f = _run(_f("ClickHouse"))
    assert "0ed4268" in f.fix
    assert any("Isolate" in c for c in f.controls)


def test_restart_and_verify_content():
    f = _run(_f("Brotli (PyPI)"))
    assert "rebuild image" in f.restart and "deleted" in f.restart
    assert rd.MARK_FIXED.decode() in f.verify


def test_controls_and_not_covered():
    f = _run(_f("Envoy"))
    assert any("Content-Encoding: br" in c for c in f.controls)
    assert any("Envoy" in c for c in f.controls)
    assert "WAF" in f.not_covered and "Accept-Encoding" in f.not_covered


def test_backport_aware():
    f = _run(_f("brotli-decoder (embedded)", version="1.0.9",
                evidence="marker reconciliation: fix marker present despite old version"))
    assert f.fix == BACKPORT_FIX
    assert not f.controls and not f.restart


def test_generic_backport_note_does_not_suppress():
    f = _run(_f("libbrotli1", note="version may be a backport; binary-marker layer is authoritative"))
    assert f.fix != BACKPORT_FIX


def test_patched_and_clean_minimal():
    p, c = _f("Brotli (PyPI)", PATCHED), _f("Rust", CLEAN)
    enrich_mitigation([p, c])
    for f in (p, c):
        assert f.fix.startswith("no action") and not f.controls and not f.restart


def test_plan_groups_and_dedupes():
    fs = [_f("Brotli (PyPI)", location="/a"), _f("Brotli (PyPI)", location="/b"),
          _f("Node.js", PATCHED)]
    enrich_mitigation(fs)
    plan = remediation_plan(fs)
    assert len(plan) == 1 and plan[0]["component"] == "Brotli (PyPI)"
    assert plan[0]["locations"] == ["/a", "/b"] and len(plan[0]["fix"]) == 1
