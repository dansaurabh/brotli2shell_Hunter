"""Small helpers."""

from __future__ import annotations

import shutil
import subprocess


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd, timeout=60):
    """Run a command read-only; return stdout or '' on any failure."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""
