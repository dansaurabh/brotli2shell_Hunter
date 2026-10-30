from b2s_hunter.mitigation import _BACKPORT_RE
from b2s_hunter.model import CLEAN, PATCHED, REVIEW, VULNERABLE, Finding
from b2s_hunter.reconcile import reconcile_backports

LIB = "/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1"


def pkg(verdict, layer="package:dpkg", comp="libbrotli1", ver="1.0.9-2+deb12u1"):
    return Finding(layer=layer, component=comp, location="dpkg", verdict=verdict,
                   confidence="medium", version=ver, note="version may be a backport")


def mk(verdict, loc=LIB):
    return Finding(layer="binary-marker", component="brotli-decoder (embedded)",
                   location=loc, verdict=verdict, confidence="high")


def test_backport_downgrades_to_patched():
    p = reconcile_backports([pkg(VULNERABLE), mk(PATCHED)])[0]
    assert p.verdict == PATCHED and p.confidence == "high"
    assert "backport-patched: marker confirms fix" in p.note
    assert p.fix == "no action - backport-patched"


def test_provenance_in_note():
    p = reconcile_backports([pkg(VULNERABLE), mk(PATCHED)])[0]
    assert "owning package: libbrotli1 1.0.9-2+deb12u1" in p.note and LIB in p.note


def test_stale_binary_upgrades_to_vulnerable():
    p = reconcile_backports([pkg(PATCHED, ver="1.1.1"), mk(VULNERABLE)])[0]
    assert p.verdict == VULNERABLE and p.confidence == "high"
    assert "unpatched despite version" in p.note


def test_clean_package_upgraded_too():
    assert reconcile_backports([pkg(CLEAN), mk(VULNERABLE)])[0].verdict == VULNERABLE


def test_no_findings_deleted_and_markers_untouched():
    fs = [pkg(VULNERABLE), mk(PATCHED)]
    out = reconcile_backports(fs)
    assert len(out) == 2 and out[1] is fs[1]


def test_input_not_mutated():
    p = pkg(VULNERABLE)
    reconcile_backports([p, mk(PATCHED)])
    assert p.verdict == VULNERABLE and p.fix == ""


def test_agreement_unchanged():
    p = pkg(PATCHED)
    assert reconcile_backports([p, mk(PATCHED)])[0] is p


def test_any_vulnerable_marker_wins():
    out = reconcile_backports([pkg(PATCHED), mk(PATCHED),
                               mk(VULNERABLE, "/lib/libbrotlienc.so.1")])
    assert out[0].verdict == VULNERABLE


def test_unrelated_embedded_binary_ignored():
    p = pkg(VULNERABLE)
    assert reconcile_backports([p, mk(PATCHED, "/usr/bin/node")])[0] is p


def test_pip_scoped_to_site_packages():
    pip = pkg(VULNERABLE, layer="package:pip", comp="Brotli (PyPI)", ver="1.1.0")
    sp = mk(PATCHED, "/venv/lib/python3.12/site-packages/_brotli.cpython-312.so")
    assert reconcile_backports([pip, sp])[0].verdict == PATCHED
    dpkg = pkg(VULNERABLE)
    assert reconcile_backports([dpkg, sp])[0] is dpkg


def test_review_package_adopts_marker():
    assert reconcile_backports([pkg(REVIEW), mk(PATCHED)])[0].verdict == PATCHED


def test_mitigation_recognises_note():
    assert _BACKPORT_RE.search(reconcile_backports([pkg(VULNERABLE), mk(PATCHED)])[0].note)
