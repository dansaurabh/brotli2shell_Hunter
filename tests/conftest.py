import pytest

from b2s_hunter import ruledata as rd


def _elf(*parts):
    return b"\x7fELF" + b"\x00" * 16 + b"\x00".join(parts) + b"\x00" * 16


@pytest.fixture
def make_bin(tmp_path):
    """Write a fake binary: magic + optional marker strings. Returns its path."""
    def _make(name, decoder=False, fixed=False, symbol=False, magic=b"\x7fELF"):
        parts = []
        if decoder:
            parts.append(rd.MARK_DECODER)
        if fixed:
            parts.append(rd.MARK_FIXED)
        if symbol:
            parts.append(rd.SYM_DECODE)
        p = tmp_path / name
        p.write_bytes(magic + b"\x00" * 16 + b"\x00".join(parts) + b"\x00" * 16)
        return str(p)
    return _make
