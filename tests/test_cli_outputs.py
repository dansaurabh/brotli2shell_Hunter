import json

from b2s_hunter.cli import main


def _run(capsys, *args):
    code = main(["--only", "markers", "--only-paths", *args])
    return code, capsys.readouterr().out


def test_sarif_and_vex_formats(capsys, tmp_path, make_bin):
    make_bin("v.so", decoder=True)
    for fmt, key in (("sarif", "runs"), ("vex-cdx", "vulnerabilities"),
                     ("openvex", "statements"), ("sbom-cdx", "components")):
        _, out = _run(capsys, "--path", str(tmp_path), "--format", fmt)
        assert key in json.loads(out)


def test_json_has_enrichment(capsys, tmp_path, make_bin):
    make_bin("v.so", decoder=True)
    _, out = _run(capsys, "--path", str(tmp_path), "--format", "json")
    d = json.loads(out)
    assert d["blind_spots"] and d["provenance"] and d["policy"]["status"]
    assert d["findings"][0]["fix"] and d["findings"][0]["impact"]


def test_fail_on_never(capsys, tmp_path, make_bin):
    make_bin("v.so", decoder=True)
    code, _ = _run(capsys, "--path", str(tmp_path), "--fail-on", "never", "--format", "json")
    assert code != 1


def test_baseline_drift(capsys, tmp_path, make_bin):
    make_bin("v.so", decoder=True)
    base = tmp_path / "base.json"
    _run(capsys, "--path", str(tmp_path), "--save-baseline", str(base), "--format", "json")
    make_bin("w.so", decoder=True)
    _, out = _run(capsys, "--path", str(tmp_path), "--baseline", str(base), "--format", "json")
    assert len(json.loads(out)["drift"]["new"]) == 1
