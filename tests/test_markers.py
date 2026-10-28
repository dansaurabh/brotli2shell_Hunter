import pytest

from b2s_hunter import ruledata as rd
from b2s_hunter.layers.markers import layer_markers
from b2s_hunter.markers import classify_markers, looks_binary, scan_markers_in_file
from b2s_hunter.model import PATCHED, REVIEW, VULNERABLE


def test_decoder_only_is_vulnerable(make_bin):
    res = scan_markers_in_file(make_bin("a.so", decoder=True))
    assert classify_markers(res)[0] == VULNERABLE


def test_both_markers_is_patched(make_bin):
    res = scan_markers_in_file(make_bin("a.so", decoder=True, fixed=True))
    assert classify_markers(res)[0] == PATCHED


def test_neither_is_ignored(make_bin):
    assert classify_markers(scan_markers_in_file(make_bin("a.so"))) is None


def test_symbol_only_is_low_confidence_review(make_bin):
    verdict, conf, _ = classify_markers(scan_markers_in_file(make_bin("a.so", symbol=True)))
    assert (verdict, conf) == (REVIEW, "low")


@pytest.mark.parametrize("magic", [b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"])
def test_all_binary_formats_scanned(make_bin, magic):
    assert looks_binary(make_bin("x.bin", decoder=True, magic=magic))


def test_non_binary_with_marker_ignored(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(rd.MARK_DECODER)
    assert not looks_binary(str(p))


def test_marker_spanning_chunk_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(rd, "CHUNK", 32)
    for offset in range(20, 40):
        p = tmp_path / f"b{offset}.so"
        p.write_bytes(b"\x7fELF" + b"\x00" * (offset - 4) + rd.MARK_DECODER)
        assert scan_markers_in_file(str(p))["decoder"], offset


def test_size_cap_skips_file(make_bin, monkeypatch):
    monkeypatch.setattr(rd, "MAX_FILE_BYTES", 8)
    assert scan_markers_in_file(make_bin("big.so", decoder=True)) is None


def test_layer_markers_walk(tmp_path, make_bin):
    make_bin("vuln.so", decoder=True)
    make_bin("ok.so", decoder=True, fixed=True)
    make_bin("none.so")
    (tmp_path / "readme.txt").write_text("x")
    findings = []
    n = layer_markers([str(tmp_path)], findings)
    by_name = {f.location.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]: f.verdict for f in findings}
    assert n == 3
    assert by_name == {"vuln.so": VULNERABLE, "ok.so": PATCHED}


def test_scanner_does_not_modify_target(make_bin):
    p = make_bin("vuln.so", decoder=True)
    import os
    before = (open(p, "rb").read(), os.stat(p).st_mtime_ns)
    scan_markers_in_file(p)
    assert (open(p, "rb").read(), os.stat(p).st_mtime_ns) == before
