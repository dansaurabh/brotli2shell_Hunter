"""Layer: memory-resident check (deleted libraries still mapped by live processes).

Read-only, Linux-only. A library replaced on disk stays vulnerable in RAM until
the owning process is restarted ("install != fixed").
"""

from __future__ import annotations

import os
import platform

from ..model import POTENTIAL, Finding

# Library name fragments that can carry a Brotli decoder.
LIB_HINTS = ("brotli", "libnode", "libcurl", "libarrow", "libduckdb",
             "libclickhouse", "libpython", "libnghttp")


def _mapped_deleted(maps_text):
    """Yield the path of each deleted, brotli-relevant mapped library (deduped)."""
    seen = set()
    for line in maps_text.splitlines():
        if "(deleted)" not in line:
            continue
        low = line.lower()
        if not any(h in low for h in LIB_HINTS):
            continue
        idx = line.find("/")
        path = line[idx:].replace("(deleted)", "").strip() if idx >= 0 else "?"
        if path not in seen:
            seen.add(path)
            yield path


def layer_memres(findings, proc_root="/proc"):
    """Append memory-resident findings; no-op off Linux with the default /proc."""
    if proc_root == "/proc" and platform.system() != "Linux":
        return
    if not os.path.isdir(proc_root):
        return
    try:
        entries = sorted(os.listdir(proc_root))
    except OSError:
        return
    for pid in entries:
        if not pid.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, pid, "maps"), "r", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            continue
        libs = list(_mapped_deleted(content))
        if not libs:
            continue
        try:
            exe = os.readlink(os.path.join(proc_root, pid, "exe"))
        except OSError:
            exe = "?"
        findings.append(Finding(
            layer="memory-resident", component="deleted library mapped in memory",
            location=f"pid {pid} ({exe})", verdict=POTENTIAL, confidence="medium",
            evidence="process maps deleted library: " + ", ".join(libs),
            note="library was replaced on disk but the old copy is still loaded; "
                 "the process must be restarted to load the patched library",
        ))
