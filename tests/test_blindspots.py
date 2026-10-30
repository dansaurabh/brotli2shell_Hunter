from b2s_hunter import __version__, ruledata
from b2s_hunter.blindspots import compute_blind_spots, provenance

ALL = ["packages", "markers", "runtimes", "containers", "sbom", "source"]
FULL = {"containers": True, "source": ["s"], "sbom": ["b"]}


def text(*a):
    return "\n".join(compute_blind_spots(*a)).lower()


def test_always_reports_static_and_archive_and_scope():
    t = text(ALL, FULL, "linux")
    assert "statically linked" in t and "archives" in t and "scanned scope" in t


def test_container_blind_spot():
    assert "containers/images were not scanned" in text(ALL, {}, "linux")
    assert "containers/images" not in text(ALL, FULL, "linux")


def test_memory_check_non_linux():
    assert "memory-resident" in text(ALL, {}, "win32")
    assert "memory-resident" not in text(ALL, {}, "linux")


def test_no_source_no_sbom():
    t = text(ALL, {}, "linux")
    assert "no source tree" in t and "no sbom" in t


def test_disabled_layers_reported():
    t = text(["packages"], {}, "linux")
    assert "marker layer disabled" in t and "runtime layer disabled" in t


def test_only_paths_scope():
    assert "limited to the supplied path roots" in text(
        ALL, {"only_paths": True, "path": ["/opt"]}, "linux")


def test_provenance():
    p = provenance("h1")
    assert p["tool_version"] == __version__
    assert p["rules_version"] == ruledata.RULES_VERSION
    assert p["rules_date"] == ruledata.RULES_DATE
    assert p["sources"] == ruledata.RULE_SOURCES and p["host"] == "h1"
