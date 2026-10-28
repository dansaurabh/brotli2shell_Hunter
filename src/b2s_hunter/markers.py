"""Version-independent marker detection (the core)."""

from __future__ import annotations

import os

from . import ruledata as rd
from .model import PATCHED, REVIEW, VULNERABLE


def looks_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except Exception:
        return False
    # only files whose magic matches are scanned
    return any(head.startswith(m) for m in rd.BIN_MAGICS)


def scan_markers_in_file(path: str):
    """Return dict(decoder=bool, fixed=bool, symbol=bool) or None if unreadable."""
    found = {"decoder": False, "fixed": False, "symbol": False}
    try:
        if os.path.getsize(path) > rd.MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            tail = b""
            while True:
                chunk = fh.read(rd.CHUNK)
                if not chunk:
                    break
                buf = tail + chunk
                if rd.MARK_DECODER in buf:
                    found["decoder"] = True
                if rd.MARK_FIXED in buf:
                    found["fixed"] = True
                if rd.SYM_DECODE in buf:
                    found["symbol"] = True
                if all(found.values()):
                    break
                tail = buf[-rd.OVERLAP:]
    except Exception:
        return None
    return found


def classify_markers(found: dict):
    if found["decoder"] and found["fixed"]:
        return PATCHED, "high", "decoder marker + fix marker present"
    if found["decoder"] and not found["fixed"]:
        return VULNERABLE, "high", "decoder marker present, fix marker absent"
    if found["symbol"] and not found["decoder"]:
        # linked decoder with stripped error strings: can't prove patch state
        return REVIEW, "low", "decoder symbol present but error-string markers stripped"
    return None  # no decoder here


def walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if any(dirpath == s or dirpath.startswith(s + "/") for s in rd.SKIP_DIRS):
            dirnames[:] = []
            continue
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext and ext not in rd.BIN_EXT_HINT:
                # cheap filter: still allow extensionless (libs) and known bin ext
                if ext not in (".node",):
                    continue
            yield os.path.join(dirpath, name)
