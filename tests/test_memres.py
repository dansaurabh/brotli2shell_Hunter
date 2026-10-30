import os

from b2s_hunter.layers.memres import layer_memres


def mk(root, pid, maps, exe=None):
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "maps").write_text(maps)
    if exe:
        try:
            os.symlink(exe, d / "exe")
        except (OSError, NotImplementedError):
            pass


DEL = "7f00-7f01 r-xp 0 08:01 12 /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1 (deleted)\n"
OK = "7f00-7f01 r-xp 0 08:01 12 /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1\n"


def test_detects_deleted_lib(tmp_path):
    mk(tmp_path, 100, DEL, "/usr/bin/nginx")
    out = []
    layer_memres(out, proc_root=str(tmp_path))
    assert len(out) == 1
    f = out[0]
    assert f.layer == "memory-resident" and "pid 100" in f.location
    assert "libbrotlidec" in f.evidence and "restarted" in f.note


def test_ignores_non_deleted(tmp_path):
    mk(tmp_path, 100, OK)
    out = []
    layer_memres(out, proc_root=str(tmp_path))
    assert out == []


def test_ignores_unrelated_deleted(tmp_path):
    mk(tmp_path, 100, "1-2 r-xp 0 0:0 5 /tmp/foo.so (deleted)\n")
    out = []
    layer_memres(out, proc_root=str(tmp_path))
    assert out == []


def test_skips_non_pid_dirs(tmp_path):
    mk(tmp_path, "self", DEL)
    out = []
    layer_memres(out, proc_root=str(tmp_path))
    assert out == []


def test_missing_root_noop(tmp_path):
    out = []
    layer_memres(out, proc_root=str(tmp_path / "nope"))
    assert out == []


def test_multiple_pids_one_finding_each(tmp_path):
    mk(tmp_path, 1, DEL + DEL)
    mk(tmp_path, 2, DEL)
    mk(tmp_path, 3, OK)
    out = []
    layer_memres(out, proc_root=str(tmp_path))
    assert [f.location.split()[1] for f in out] == ["1", "2"]


def test_unreadable_maps_skipped(tmp_path):
    (tmp_path / "7").mkdir()
    out = []
    layer_memres(out, proc_root=str(tmp_path))
    assert out == []


def test_default_proc_noop_off_linux(monkeypatch):
    import platform
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    out = []
    layer_memres(out)
    assert out == []
