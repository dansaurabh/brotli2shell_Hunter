"""Command-line interface.

Exit codes:  0 = nothing vulnerable   1 = vulnerable finding(s)
             2 = only needs-review/unknowns   3 = runtime error
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone

from .layers.containers import layer_containers
from .layers.markers import layer_markers
from .layers.packages import layer_packages
from .layers.roots import default_roots
from .layers.runtimes import layer_runtimes
from .layers.sbom import layer_sbom
from .layers.source import layer_source
from .model import POTENTIAL, REVIEW, VULNERABLE
from .report import build_payload, render_text, rollup

ALL_LAYERS = ["packages", "markers", "runtimes", "containers", "sbom", "source"]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Locate vulnerable Brotli decoder copies (CVE-2026-111497).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", action="append", default=[],
                    help="extra filesystem root(s) for the binary-marker scan")
    ap.add_argument("--only-paths", action="store_true",
                    help="scan ONLY --path roots (skip OS default library dirs)")
    ap.add_argument("--containers", action="store_true",
                    help="also scan running container rootfs (read-only, no exec)")
    ap.add_argument("--source", action="append", default=[],
                    help="source tree(s) for reachability grep")
    ap.add_argument("--sbom", action="append", default=[],
                    help="CycloneDX/SPDX JSON SBOM file(s) to ingest")
    ap.add_argument("--only", default="",
                    help="comma list of layers to run: " + ",".join(ALL_LAYERS))
    ap.add_argument("--skip", default="",
                    help="comma list of layers to skip")
    ap.add_argument("--format", choices=["text", "json", "both"], default="text")
    ap.add_argument("-o", "--output", default="", help="write report to file")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    enabled = set(args.only.split(",")) if args.only else set(ALL_LAYERS)
    enabled -= set(x for x in args.skip.split(",") if x)
    # presence-based auto-activation: these only run if asked / inputs given
    if not args.containers:
        enabled.discard("containers")
    if not args.source:
        enabled.discard("source")
    if not args.sbom:
        enabled.discard("sbom")

    findings = []
    host = {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    try:
        if "packages" in enabled:
            if args.verbose: print("[*] scanning OS packages / pip / npm ...", file=sys.stderr)
            layer_packages(findings)
        if "runtimes" in enabled:
            if args.verbose: print("[*] checking runtimes & processes ...", file=sys.stderr)
            layer_runtimes(findings)
        if "markers" in enabled:
            roots = list(args.path)
            if not args.only_paths:
                roots = default_roots() + roots
            roots = [r for r in dict.fromkeys(roots) if os.path.exists(r)]
            if args.verbose: print(f"[*] binary-marker scan over {len(roots)} root(s) ...", file=sys.stderr)
            n = layer_markers(roots, findings, verbose=args.verbose)
            if args.verbose: print(f"[*] marker scan examined {n} binaries", file=sys.stderr)
        if "containers" in enabled:
            if args.verbose: print("[*] scanning containers ...", file=sys.stderr)
            layer_containers(findings, verbose=args.verbose)
        if "sbom" in enabled:
            if args.verbose: print("[*] ingesting SBOM(s) ...", file=sys.stderr)
            layer_sbom(args.sbom, findings)
        if "source" in enabled:
            if args.verbose: print("[*] source reachability grep ...", file=sys.stderr)
            layer_source(args.source, findings)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    counts = rollup(findings)
    text = render_text(findings, counts, host)
    payload = build_payload(findings, counts, host)

    out_text = text if args.format == "text" else (
        json.dumps(payload, indent=2) if args.format == "json"
        else text + "\n\n" + json.dumps(payload, indent=2))

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out_text + "\n")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(out_text)

    if counts[VULNERABLE]:
        return 1
    if counts[POTENTIAL] or counts[REVIEW]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
