"""Default scan roots per OS."""

from __future__ import annotations

import os
import platform
import sys

from ..util import have, run


def default_roots():
    sysname = platform.system()
    roots = []
    if sysname == "Linux":
        roots += ["/usr/lib", "/usr/local/lib", "/usr/lib64", "/lib", "/lib64",
                  "/opt", "/usr/bin", "/usr/local/bin"]
    elif sysname == "Darwin":
        roots += ["/usr/lib", "/usr/local/lib", "/opt/homebrew", "/Applications",
                  "/System/Library/Frameworks"]
    elif sysname == "Windows":
        for env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "SystemRoot"):
            p = os.environ.get(env)
            if p:
                roots.append(p)
    # python site-packages (covers installed Brotli/brotlicffi wheels, incl. .so)
    for p in sys.path:
        if p and ("site-packages" in p or "dist-packages" in p) and os.path.isdir(p):
            roots.append(p)
    # node global modules
    if have("npm"):
        prefix = run(["npm", "prefix", "-g"]).strip()
        if prefix:
            roots.append(os.path.join(prefix, "lib", "node_modules"))
    return [r for r in dict.fromkeys(roots) if os.path.exists(r)]
