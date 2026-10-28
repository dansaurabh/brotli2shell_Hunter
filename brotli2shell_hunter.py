#!/usr/bin/env python3
"""Back-compat shim: `python brotli2shell_hunter.py ...` == `b2s-hunt ...`."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from b2s_hunter.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
