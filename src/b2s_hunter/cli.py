"""Command-line interface.

Exit codes:  0 = nothing vulnerable   1 = vulnerable finding(s)
             2 = only needs-review/unknowns   3 = runtime error
(exit 1/2 follow --fail-on / --warn-on policy; trusted-only copies don't fail by default)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone

from .layers.containers import layer_containers
from .layers.lockfiles import layer_lockfiles
from .layers.markers import layer_markers
from .layers.memres import layer_memres
from .layers.packages import layer_packages
from .layers.roots import default_roots
from .layers.runtimes import layer_runtimes
from .layers.sbom import layer_sbom
from .layers.source import layer_source
from . import drift
from .blindspots import compute_blind_spots, provenance
from .mitigation import enrich_mitigation, remediation_plan
from . import probe as probe_mod, rules_update, rulesig
from .policy import evaluate_policy
from .reconcile import reconcile_backports
from .reachability import enrich_reachability
from .report import build_payload, render_text, rollup
from .sarif import build_sarif
from .sbom_out import build_cyclonedx_sbom
from .verify import verify_fix
from .vex import build_cyclonedx_vex, build_openvex
from .vex_csaf import build_csaf_vex

ALL_LAYERS = ["packages", "markers", "runtimes", "memres", "containers", "sbom", "source", "lockfiles"]


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
    ap.add_argument("--format", choices=["text", "json", "both", "sarif", "vex-cdx", "openvex", "csaf-vex", "sbom-cdx"],
                    default="text")
    ap.add_argument("--fail-on", choices=["reachable-vulnerable", "any-vulnerable", "never"],
                    default="reachable-vulnerable", help="CI policy: what makes the run exit 1")
    ap.add_argument("--warn-on", choices=["present", "never"], default="present")
    ap.add_argument("--save-baseline", default="", help="write findings baseline JSON for drift tracking")
    ap.add_argument("--verify", default="",
                    help="post-fix check: compare this scan to a pre-fix baseline; exit 1 if any fix is ineffective")
    ap.add_argument("--rules-overlay", default="", help="offline rules overlay JSON (can only raise thresholds)")
    ap.add_argument("--verify-rules", default="", help="check the rules manifest (digest/version) before scanning")
    ap.add_argument("--write-rules-manifest", default="", help="write a rules manifest for pinning and exit")
    ap.add_argument("--probe", action="append", default=[],
                    help="ACTIVE: http(s) URL to probe for Brotli request-body handling (needs --authorized)")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you are authorized to actively test the --probe targets")
    ap.add_argument("--probe-rate", type=float, default=1.0, help="active probe requests per second")
    ap.add_argument("--baseline", default="", help="diff this scan against a saved baseline")
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
    if not args.source:
        enabled.discard("lockfiles")     # lockfiles are parsed under the --source roots

    if args.write_rules_manifest:
        rulesig.write_manifest(args.write_rules_manifest)
        print(f"rules manifest written to {args.write_rules_manifest}", file=sys.stderr)
        return 0
    if args.verify_rules:
        ok, reason = rulesig.verify_manifest(args.verify_rules)
        print(f"[rules] {'ok' if ok else 'FAILED'}: {reason}", file=sys.stderr)
        if not ok:
            return 3
    if args.rules_overlay:
        try:
            rules_update.apply_overlay(rules_update.load_overlay(args.rules_overlay))
        except ValueError as e:
            print(f"rules overlay rejected: {e}", file=sys.stderr)
            return 3
    if args.probe and not args.authorized:
        print("--probe sends live requests; re-run with --authorized to confirm you may test these targets",
              file=sys.stderr)
        return 3

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
        if "memres" in enabled:
            layer_memres(findings)
        if "containers" in enabled:
            if args.verbose: print("[*] scanning containers ...", file=sys.stderr)
            layer_containers(findings, verbose=args.verbose)
        if "sbom" in enabled:
            if args.verbose: print("[*] ingesting SBOM(s) ...", file=sys.stderr)
            layer_sbom(args.sbom, findings)
        if "source" in enabled:
            if args.verbose: print("[*] source reachability grep ...", file=sys.stderr)
            layer_source(args.source, findings)
        if "lockfiles" in enabled:
            if args.verbose: print("[*] parsing lockfiles/manifests ...", file=sys.stderr)
            layer_lockfiles(args.source, findings)
        if args.probe:
            if args.verbose: print("[*] ACTIVE probe of %d target(s) ..." % len(args.probe), file=sys.stderr)
            findings.extend(probe_mod.probe_targets(args.probe, authorized=True, rate_per_sec=args.probe_rate))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    findings = reconcile_backports(findings)
    enrich_reachability(findings)
    enrich_mitigation(findings)
    counts = rollup(findings)
    text = render_text(findings, counts, host)
    payload = build_payload(findings, counts, host)
    payload["remediation_plan"] = remediation_plan(findings)
    payload["blind_spots"] = compute_blind_spots(
        enabled, {"path": args.path, "only_paths": args.only_paths, "containers": args.containers,
                  "source": args.source, "sbom": args.sbom}, platform.system())
    payload["provenance"] = provenance(host)
    policy = evaluate_policy(findings, fail_on=args.fail_on, warn_on=args.warn_on)
    payload["policy"] = policy.as_dict()
    verification = None
    if args.verify:
        verification = verify_fix(drift.load_baseline(args.verify), findings)
        payload["verification"] = verification
    if args.baseline:
        payload["drift"] = drift.diff_findings(drift.load_baseline(args.baseline), findings)
    if args.save_baseline:
        drift.save_baseline(findings, host, args.save_baseline)

    docs = {"sarif": build_sarif, "vex-cdx": build_cyclonedx_vex,
            "openvex": build_openvex, "csaf-vex": build_csaf_vex, "sbom-cdx": build_cyclonedx_sbom}
    if args.format in docs:
        out_text = json.dumps(docs[args.format](findings, host), indent=2)
    else:
        text += "\n BLIND SPOTS:\n" + "\n".join("  - " + b for b in payload["blind_spots"])
        out_text = text if args.format == "text" else (
            json.dumps(payload, indent=2) if args.format == "json"
            else text + "\n\n" + json.dumps(payload, indent=2))

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out_text + "\n")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(out_text)

    if verification is not None:
        return 0 if verification["passed"] else 1
    return policy.exit_code


if __name__ == "__main__":
    sys.exit(main())
