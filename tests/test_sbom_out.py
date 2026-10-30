import json

from b2s_hunter.model import PATCHED, VULNERABLE, Finding
from b2s_hunter.sbom_out import build_cyclonedx_sbom, synth_purl

HOST = {"hostname": "h1", "os": "linux", "time": "2026-10-30T00:00:00Z"}


def F(verdict=VULNERABLE, loc="/x.so", **kw):
    return Finding(layer="binary", component="libbrotlidec", location=loc,
                   verdict=verdict, confidence="high", version="1.0.9", **kw)


def test_top_level():
    d = build_cyclonedx_sbom([F()], HOST)
    assert d["bomFormat"] == "CycloneDX" and d["specVersion"] == "1.5"
    assert d["serialNumber"].startswith("urn:uuid:")
    assert d["metadata"]["timestamp"] == HOST["time"]


def test_component_fields():
    c = build_cyclonedx_sbom([F()], HOST)["components"][0]
    assert {"type", "bom-ref", "name", "version", "purl", "properties"} <= set(c)
    props = {p["name"]: p["value"] for p in c["properties"]}
    assert props["b2s:verdict"] == VULNERABLE and props["b2s:location"] == "/x.so"


def test_uses_finding_purl():
    c = build_cyclonedx_sbom([F(purl="pkg:pypi/brotli@1.0.9")], HOST)["components"][0]
    assert c["purl"] == "pkg:pypi/brotli@1.0.9"
    assert c["bom-ref"].startswith("pkg:pypi/brotli@1.0.9")


def test_synthesized_purl():
    assert synth_purl(F()) == "pkg:generic/libbrotlidec@1.0.9"
    assert synth_purl(Finding("l", "a b", "/p", VULNERABLE, "low")) == "pkg:generic/a%20b"


def test_unique_bom_refs_same_component():
    d = build_cyclonedx_sbom([F(loc="/a"), F(loc="/b")], HOST)
    refs = [c["bom-ref"] for c in d["components"]]
    assert len(set(refs)) == 2 and refs == sorted(refs)


def test_deterministic_serial():
    fs = [F(loc="/a"), F(PATCHED, loc="/b")]
    a = build_cyclonedx_sbom(fs, HOST)
    b = build_cyclonedx_sbom(list(reversed(fs)), HOST)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["serialNumber"] != build_cyclonedx_sbom([F(loc="/z")], HOST)["serialNumber"]
