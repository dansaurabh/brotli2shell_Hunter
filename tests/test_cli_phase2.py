import json

from b2s_hunter.cli import main


def _run(capsys, *args):
    code = main(["--only", "markers,lockfiles", "--only-paths", "--format", "json", *args])
    return code, capsys.readouterr().out


def test_lockfiles_run_under_source(capsys, tmp_path):
    (tmp_path / "requirements.txt").write_text("Brotli==1.0.9\n")
    code, out = _run(capsys, "--source", str(tmp_path))
    assert any(f["layer"] == "lockfile" for f in json.loads(out)["findings"])


def test_probe_requires_authorized(capsys):
    assert main(["--probe", "http://127.0.0.1:1/"]) == 3


def test_verify_flow(capsys, tmp_path, make_bin):
    v = make_bin("v.so", decoder=True)
    base = tmp_path / "b.json"
    _run(capsys, "--path", str(tmp_path), "--save-baseline", str(base))
    make_bin("v.so", decoder=True, fixed=True)
    code, out = _run(capsys, "--path", str(tmp_path), "--verify", str(base))
    assert code == 0 and json.loads(out)["verification"]["passed"]


def test_rules_manifest_roundtrip(capsys, tmp_path):
    m = tmp_path / "m.json"
    assert main(["--write-rules-manifest", str(m)]) == 0
    code, _ = _run(capsys, "--verify-rules", str(m), "--path", str(tmp_path))
    assert code in (0, 1, 2)


def test_csaf_format(capsys, tmp_path, make_bin):
    make_bin("v.so", decoder=True)
    code = main(["--only", "markers", "--only-paths", "--path", str(tmp_path), "--format", "csaf-vex"])
    assert "vulnerabilities" in json.loads(capsys.readouterr().out)
