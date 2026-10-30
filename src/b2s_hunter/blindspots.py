"""Honest scope / blind-spot reporting (CAPABILITY_SPEC.md section 1.4)."""

from __future__ import annotations

from . import __version__, ruledata


def compute_blind_spots(enabled_layers, args_summary, platform_name) -> list:
    """List what this run could not see.

    args_summary keys (truthy = supplied): path, only_paths, containers,
    source, sbom. platform_name is e.g. "linux", "win32", "darwin".
    """
    layers = set(enabled_layers)
    a = args_summary or {}
    out = []

    if not (a.get("containers") and "containers" in layers):
        out.append("Containers/images were not scanned (use --containers); "
                   "decoders inside images and running containers are unseen.")
    if not str(platform_name).lower().startswith("linux"):
        out.append(f"Memory-resident check unavailable on {platform_name}: "
                   "loaded/mapped vulnerable libraries in running processes "
                   "are not inspected.")
    if "source" not in layers or not a.get("source"):
        out.append("No source tree supplied: reachability from source is not "
                   "assessed; reach is 'unknown' unless inferred elsewhere.")
    if "sbom" not in layers or not a.get("sbom"):
        out.append("No SBOM supplied: prebuilt wheels/binaries and vendored "
                   "components are not cross-checked against SBOM data.")
    if "packages" not in layers:
        out.append("Package-manager layer disabled: installed package "
                   "versions were not enumerated.")
    if "markers" not in layers:
        out.append("Binary marker layer disabled: bundled/static decoders "
                   "are not detected.")
    if "runtimes" not in layers:
        out.append("Runtime layer disabled: Node/Bun/Python runtime versions "
                   "were not checked.")
    if a.get("only_paths") or a.get("path"):
        out.append("Marker scan limited to the supplied path roots"
                   + (" only" if a.get("only_paths") else " plus defaults")
                   + "; files elsewhere are not scanned.")
    out.append("Statically linked, stripped, obfuscated or packed binaries may "
               "hide decoder markers; absence of a marker is not proof of absence.")
    out.append("Compressed archives (zip, tar.gz, jar, wheel, asar, UPX) are "
               "not unpacked; embedded binaries inside them are unseen.")
    out.append(f"Files above {ruledata.MAX_FILE_BYTES // (1024 * 1024)} MiB are "
               "skipped, as are unreadable paths (insufficient privilege).")
    out.append("A clean result means clean within the scanned scope only, "
               "not an unqualified 'not vulnerable'.")
    return out


def provenance(host) -> dict:
    return {
        "tool": "b2s-hunter",
        "tool_version": __version__,
        "rules_version": ruledata.RULES_VERSION,
        "rules_date": ruledata.RULES_DATE,
        "cve": ruledata.CVE_ID,
        "sources": list(ruledata.RULE_SOURCES),
        "host": host,
    }
