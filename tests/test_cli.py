import json
import os

from b2s_hunter import ruledata as rd
from b2s_hunter.cli import main

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(capsys, *args):
    code = main(["--only", "markers", "--only-paths", "--format", "json", *args])
    return code, json.loads(capsys.readouterr().out)


def test_exit_1_on_vulnerable(capsys, tmp_path, make_bin):
    make_bin("v.so", decoder=True)
    code, data = _run(capsys, "--path", str(tmp_path))
    assert code == 1 and data["summary"]["VULNERABLE"] == 1


def test_exit_0_when_only_patched(capsys, tmp_path, make_bin):
    make_bin("p.so", decoder=True, fixed=True)
    code, data = _run(capsys, "--path", str(tmp_path))
    assert code == 0 and data["summary"]["PATCHED"] == 1


def test_exit_2_on_review_only(capsys, tmp_path, make_bin):
    make_bin("s.so", symbol=True)
    code, _ = _run(capsys, "--path", str(tmp_path))
    assert code == 2


def test_exit_0_empty(capsys, tmp_path):
    code, data = _run(capsys, "--path", str(tmp_path))
    assert code == 0 and data["findings"] == []


def test_json_payload_shape(capsys, tmp_path):
    _, data = _run(capsys, "--path", str(tmp_path))
    assert data["cve"] == rd.CVE_ID and {"summary", "findings", "host", "remediation"} <= set(data)


def test_self_scan_smoke(capsys):
    """Scan this repo itself: source files carry the marker strings but are not
    binaries, so they must NOT be flagged; the run must complete cleanly."""
    code, data = _run(capsys, "--path", REPO)
    assert code == 0
    assert not [f for f in data["findings"] if f["verdict"] == "VULNERABLE"]


def test_self_scan_other_layers_do_not_crash(capsys):
    code = main(["--only", "packages,runtimes", "--format", "json"])
    assert code in (0, 1, 2)
    json.loads(capsys.readouterr().out)
