"""Tests for reachability enrichment."""

from b2s_hunter.model import CLEAN, PATCHED, POTENTIAL, VULNERABLE, Finding
from b2s_hunter.reachability import enrich_reachability


def mk(component, verdict=VULNERABLE, layer="binary-marker", location="/x", evidence=""):
    f = Finding(layer=layer, component=component, location=location, verdict=verdict,
                confidence="high", evidence=evidence)
    enrich_reachability([f])
    return f


def test_inbound_express_is_top_priority():
    f = mk("express body-parser", layer="source-reachability")
    assert (f.reach, f.direction, f.input_trust) == ("reachable-untrusted", "inbound", "untrusted")
    assert f.internet_facing and f.priority == 100


def test_outbound_fetch_client():
    f = mk("Node.js fetch", layer="runtime:node")
    assert f.direction == "outbound" and f.reach == "reachable-untrusted"
    assert not f.internet_facing


def test_file_path_libjxl():
    f = mk("libjxl", evidence="brob box decoder")
    assert f.direction == "file" and f.reach == "reachable-untrusted"


def test_v8_snapshot_trusted_down_ranked():
    f = mk("brotli-decoder (embedded)", location="/opt/v8/snapshot_blob.bin",
           evidence="V8 startup snapshot")
    assert f.reach == "trusted-only" and f.input_trust == "trusted"
    assert f.priority < 30
    assert "trusted" in f.impact


def test_envoy_config_gated():
    f = mk("Envoy")
    assert f.reach == "config-gated" and "enabled" in f.gate


def test_python_client_gate():
    f = mk("Brotli (PyPI)", layer="package:pip")
    assert f.reach == "config-gated" and "installed" in f.gate


def test_patched_low_priority_reach_kept():
    f = mk("express body-parser", verdict=PATCHED)
    assert f.reach == "reachable-untrusted" and f.priority <= 10
    assert mk("express", verdict=CLEAN).priority == 0


def test_impact_states_dos_and_situational_rce():
    f = mk("clickhouse")
    assert "DoS" in f.impact and "memory disclosure" in f.impact and "situational" in f.impact


def test_unknown_and_source_hits_promotion():
    f = Finding(layer="binary-marker", component="brotli-decoder (embedded)", location="/opt/app/lib.so",
                verdict=POTENTIAL, confidence="low")
    enrich_reachability([f])
    assert f.reach == "unknown"
    enrich_reachability([f], source_hits=["decompress"])
    assert f.reach == "reachable-untrusted" and f.gate


def test_priority_ordering():
    a = mk("nginx")                      # inbound internet-facing
    b = mk("woff2 font")                 # file
    c = mk("Envoy")                      # gated
    assert a.priority > b.priority > c.priority
