import pytest

from b2s_hunter import ruledata as rd
from b2s_hunter.model import CLEAN, PATCHED, REVIEW, VULNERABLE
from b2s_hunter.versions import brotli_lib_verdict, node_verdict, parse_ver, simple_verdict


@pytest.mark.parametrize("ver,expected", [
    ("1.0.9", VULNERABLE), ("1.0.10", PATCHED),
    ("1.1.0", VULNERABLE), ("1.1.1", PATCHED),
    ("1.2.0", VULNERABLE), ("1.2.1", PATCHED),
    ("1.0.2", CLEAN),
])
def test_brotli_lib(ver, expected):
    assert brotli_lib_verdict(parse_ver(ver))[0] == expected


@pytest.mark.parametrize("ver,expected", [
    ("24.22.0", VULNERABLE), ("24.22.1", PATCHED),
    ("22.23.4", PATCHED), ("22.23.3", VULNERABLE),
    ("26.12.1", PATCHED), ("26.12.0", VULNERABLE),
    ("20.11.0", VULNERABLE),
    ("23.1.0", VULNERABLE), ("25.0.0", VULNERABLE),   # EOL, no fix (step 1 decision)
    ("27.0.0", REVIEW),
])
def test_node(ver, expected):
    assert node_verdict(parse_ver(ver))[0] == expected


def test_node_eol_note_mentions_reachability():
    assert "reach" in node_verdict((23, 1, 0))[1]


def test_pypi_and_bun():
    assert simple_verdict(parse_ver("1.2.0"), rd.PY_BROTLI_FIXED)[0] == VULNERABLE
    assert simple_verdict(parse_ver("1.2.1"), rd.PY_BROTLI_FIXED)[0] == PATCHED
    assert simple_verdict(parse_ver("1.2.1.0"), rd.PY_BROTLICFFI_FIXED)[0] == PATCHED
    assert simple_verdict(parse_ver("1.4.3"), rd.BUN_FIXED)[0] == VULNERABLE
    assert simple_verdict(parse_ver("1.4.4"), rd.BUN_FIXED)[0] == PATCHED


def test_parse_ver():
    assert parse_ver("1.0.9-2+deb12u1") == (1, 0, 9)
    assert parse_ver("v24.22.0") == (24, 22, 0)
    assert parse_ver("") is None
    assert parse_ver("abc") is None


def test_unparseable_and_unknown_line():
    assert brotli_lib_verdict(None)[0] == REVIEW
    assert brotli_lib_verdict((1,))[0] == REVIEW
    assert brotli_lib_verdict((1, 3, 0))[0] == REVIEW
