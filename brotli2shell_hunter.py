#!/usr/bin/env python3
"""
brotli2shell_hunter.py  -  CVE-2026-111497 (HTTP2Shell / Node2Shell / Brotli2Shell)
================================================================================
Locates vulnerable copies of Google's Brotli decoder across a host, its
installed packages, language runtimes, running processes, containers, SBOMs,
and (optionally) source trees.

Why this instead of a version-only scanner
------------------------------------------
Two gaps break ordinary scanners for this CVE:

  1. BACKPORT FALSE-POSITIVES. Distros backport the fix but keep the old
     upstream version string (e.g. Debian's fixed 1.0.9-2+deb12u1 still
     reports "1.0.9"). Version matching flags it as vulnerable; it isn't.

  2. VENDORED / STATICALLY-LINKED COPIES. Node.js, Bun, .NET, FFmpeg (via
     libjxl), pyarrow and others ship their own private copy of the decoder.
     No package manager knows about these, so SBOM-by-package and distro
     scanners never see them.

Both are solved by MARKER-STRING detection, which is version-independent:

  * Every Brotli C decoder embeds its error-string table. The literal
    "_ERROR_FORMAT_EXUBERANT_NIBBLE" proves a decoder is present.
  * The upstream fix (commit 0ed4268, shipped in 1.0.10 / 1.1.1 / 1.2.1)
    adds a NEW error code whose string is "_ERROR_FORMAT_BLOCK_SWITCH".
    Its presence marks a PATCHED copy - even when the version string lies.

  decoder marker present  +  fix marker ABSENT   -> VULNERABLE decoder
  decoder marker present  +  fix marker PRESENT  -> PATCHED decoder

Everything here is READ-ONLY and non-invasive: no exploit payloads, no
network traffic, no code execution inside targets, no writes to scanned paths.

Layers activate based on what's present on the box ("depends on its presence"):
each layer silently skips if its prerequisite (a tool, a path, an OS) is absent.

Usage
-----
  python3 brotli2shell_hunter.py                 # auto: scan this host
  python3 brotli2shell_hunter.py --path /opt/app # add/extra filesystem roots
  python3 brotli2shell_hunter.py --containers    # include container rootfs
  python3 brotli2shell_hunter.py --source ./repo # source reachability grep
  python3 brotli2shell_hunter.py --sbom bom.json # ingest CycloneDX/SPDX SBOM
  python3 brotli2shell_hunter.py --format json -o report.json
  python3 brotli2shell_hunter.py --only markers,packages   # restrict layers

Exit codes:  0 = nothing vulnerable   1 = vulnerable finding(s)
             2 = only needs-review/unknowns   3 = runtime error

Requires Python 3.8+, standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Reference data (sources: Google CVE record, Node.js Oct-2026 advisory,
# PYSEC-2026-4322/4323, Bun/Brotli release notes). Edit here if ranges change.
# --------------------------------------------------------------------------- #

MARK_DECODER = b"_ERROR_FORMAT_EXUBERANT_NIBBLE"   # any Brotli decoder
MARK_FIXED   = b"_ERROR_FORMAT_BLOCK_SWITCH"       # patched (fix adds this code)
SYM_DECODE   = b"BrotliDecoderDecompress"          # secondary decoder evidence

# Fixed thresholds. A build is PATCHED at or above the threshold for its line.
BROTLI_LINES = {(1, 0): (1, 0, 10), (1, 1): (1, 1, 1), (1, 2): (1, 2, 1)}
PY_BROTLI_FIXED     = (1, 2, 1)       # PyPI "Brotli"
PY_BROTLICFFI_FIXED = (1, 2, 1, 0)    # PyPI "brotlicffi"
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
BUN_FIXED  = (1, 4, 4)

# Binary magic numbers -> only these files get a marker scan.
BIN_MAGICS = (
    b"\x7fELF",                                   # ELF (Linux/BSD)
    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",      # Mach-O 64 / 32 (LE)
    b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",      # Mach-O 64 / 32 (BE)
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",      # Mach-O universal (fat)
    b"MZ",                                         # PE (Windows .exe/.dll)
)

MAX_FILE_BYTES = 300 * 1024 * 1024    # skip binaries larger than this
CHUNK = 4 * 1024 * 1024
OVERLAP = max(len(MARK_DECODER), len(MARK_FIXED), len(SYM_DECODE)) - 1

SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp/.X11-unix"}
BIN_EXT_HINT = {".so", ".dylib", ".dll", ".exe", ".node", ".bin", ".o", ".a", ""}

# Source-reachability entry points: a match means untrusted input *may* reach
# the decoder (ranking signal, not proof).
REACH_PATTERNS = {
    "js-fetch/DecompressionStream": re.compile(r"\b(fetch\s*\(|DecompressionStream|createBrotliDecompress|zlib\.brotliDecompress)"),
    "js-body-parser/express":       re.compile(r"\b(body-parser|express\.json|compression\(\)|inflate\s*:\s*true)"),
    "py-brotli-direct":             re.compile(r"\b(import\s+brotli|import\s+brotlicffi|brotli\.decompress|brotlicffi\.decompress)"),
    "py-http-clients":              re.compile(r"\b(requests\.|httpx\.|aiohttp|urllib3)"),
    "dotnet-brotli":                re.compile(r"\b(BrotliStream|BrotliDecoder|System\.IO\.Compression\.Brotli)"),
    "arrow/parquet":                re.compile(r"\b(pyarrow|parquet\.read|BufferReader|ipc\.open)"),
    "native-decode-call":           re.compile(r"\bBrotliDecoderDecompress(Stream)?\b"),
    "brotli-cli-decompress":        re.compile(r"\bbrotli\b.*(\s-d\b|--decompress)"),
}
REACH_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".cs", ".go", ".rb",
             ".php", ".java", ".sh", ".dockerfile", ".yaml", ".yml", ".toml",
             ".json", ".lock", ".txt"}

SBOM_NAME_RE = re.compile(r"(^|[^a-z])brotli", re.IGNORECASE)

FIX_HINT = ("Brotli C lib -> 1.0.10 / 1.1.1 / 1.2.1 | Node -> 22.23.4 / 24.22.1 / "
            "26.12.1 | Bun -> 1.4.4 | PyPI Brotli -> 1.2.1 | brotlicffi -> 1.2.1.0")

# Verdicts, ordered by severity for roll-up.
VULNERABLE = "VULNERABLE"
POTENTIAL  = "POTENTIALLY_VULNERABLE"
REVIEW     = "NEEDS_REVIEW"
PATCHED    = "PATCHED"
CLEAN      = "NOT_AFFECTED"
SEVERITY = {VULNERABLE: 4, POTENTIAL: 3, REVIEW: 2, PATCHED: 1, CLEAN: 0}


# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    layer: str
    component: str
    location: str
    verdict: str
    confidence: str          # high | medium | low
    version: str = ""
    evidence: str = ""
    note: str = ""

    def as_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd, timeout=60):
    """Run a command read-only; return stdout or '' on any failure."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


def parse_ver(s: str):
    """'1.0.9-2+deb12u1' -> (1,0,9). Keeps leading numeric dotted parts only."""
    if not s:
        return None
    s = s.strip().lstrip("vV=")
    m = re.match(r"(\d+(?:\.\d+)*)", s)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def brotli_lib_verdict(v):
    if v is None:
        return REVIEW, "unparseable version"
    if len(v) < 2:
        return REVIEW, "incomplete version"
    if v < (1, 0, 3):
        return CLEAN, "pre-1.0.3, before the flaw was introduced"
    line = (v[0], v[1])
    fixed = BROTLI_LINES.get(line)
    if fixed is None:
        return REVIEW, "version line not in known affected set; verify manually"
    return (PATCHED, "at/above line fix") if v >= fixed else (VULNERABLE, "below line fix")


def node_verdict(v):
    if v is None:
        return REVIEW, "unparseable"
    major = v[0]
    if major in NODE_FIXED:
        return (PATCHED, "patched line") if v >= NODE_FIXED[major] else (VULNERABLE, "below line fix")
    if major < 22:
        return VULNERABLE, "EOL/unsupported line (no fix; e.g. Node 20 EOL Apr-2026)"
    return REVIEW, "non-LTS/newer line; confirm it carries the Oct-2026 fix"


def simple_verdict(v, fixed):
    if v is None:
        return REVIEW, "unparseable"
    return (PATCHED, "patched") if v >= fixed else (VULNERABLE, "below fix")


# --------------------------------------------------------------------------- #
# Layer: binary / marker scan  (the core; version-independent)
# --------------------------------------------------------------------------- #

def looks_binary(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except Exception:
        return False
    if any(head.startswith(m) for m in BIN_MAGICS):
        return True
    # catch extensionless shared objects etc. only if magic matched above
    return False


def scan_markers_in_file(path: str):
    """Return dict(decoder=bool, fixed=bool, symbol=bool) or None if unreadable."""
    found = {"decoder": False, "fixed": False, "symbol": False}
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            tail = b""
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                buf = tail + chunk
                if MARK_DECODER in buf:
                    found["decoder"] = True
                if MARK_FIXED in buf:
                    found["fixed"] = True
                if SYM_DECODE in buf:
                    found["symbol"] = True
                if all(found.values()):
                    break
                tail = buf[-OVERLAP:]
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


def layer_markers(roots, findings, verbose=False):
    seen = set()
    scanned = 0
    for root in roots:
        if not os.path.isdir(root) and not os.path.isfile(root):
            continue
        walk_targets = [root] if os.path.isfile(root) else _walk_files(root)
        for path in walk_targets:
            rp = os.path.realpath(path)
            if rp in seen:
                continue
            seen.add(rp)
            if not looks_binary(path):
                continue
            res = scan_markers_in_file(path)
            scanned += 1
            if verbose and scanned % 500 == 0:
                print(f"  [markers] scanned {scanned} binaries...", file=sys.stderr)
            if not res:
                continue
            cls = classify_markers(res)
            if cls is None:
                continue
            verdict, conf, ev = cls
            findings.append(Finding(
                layer="binary-marker", component="brotli-decoder (embedded)",
                location=path, verdict=verdict, confidence=conf, evidence=ev,
                note="version-independent; valid even for backports and vendored copies",
            ))
    return scanned


def _walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if any(dirpath == s or dirpath.startswith(s + "/") for s in SKIP_DIRS):
            dirnames[:] = []
            continue
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext and ext not in BIN_EXT_HINT:
                # cheap filter: still allow extensionless (libs) and known bin ext
                if ext not in (".node",):
                    continue
            yield os.path.join(dirpath, name)


# --------------------------------------------------------------------------- #
# Layer: OS packages
# --------------------------------------------------------------------------- #

def layer_packages(findings):
    sysname = platform.system()
    # Debian/Ubuntu
    if have("dpkg-query"):
        out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name, ver = parts[0], parts[1]
            if "brotli" not in name.lower():
                continue
            if len(parts) >= 3 and "installed" not in parts[2]:
                continue
            verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="package:dpkg", component=name, location="dpkg",
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"version check: {why}",
                note="version may be a backport; binary-marker layer is authoritative",
            ))
    # RHEL/Fedora/SUSE
    if have("rpm"):
        out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        for line in out.splitlines():
            name, _, ver = line.partition("\t")
            if "brotli" not in name.lower():
                continue
            verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="package:rpm", component=name, location="rpm",
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"version check: {why}",
                note="version may be a backport; binary-marker layer is authoritative",
            ))
    # Alpine
    if have("apk"):
        out = run(["apk", "info", "-v"])
        for line in out.splitlines():
            if "brotli" not in line.lower():
                continue
            m = re.match(r"(.+?)-(\d.+)$", line.strip())
            name, ver = (m.group(1), m.group(2)) if m else (line.strip(), "")
            verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="package:apk", component=name, location="apk",
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"version check: {why}",
            ))
    # Python wheels (pip)
    _layer_pip(findings)
    # npm global
    if have("npm"):
        out = run(["npm", "ls", "-g", "--depth=0", "--json"], timeout=60)
        try:
            data = json.loads(out) if out.strip() else {}
        except Exception:
            data = {}
        for name, meta in (data.get("dependencies") or {}).items():
            if "brotli" in name.lower():
                ver = (meta or {}).get("version", "")
                findings.append(Finding(
                    layer="package:npm", component=name, location="npm -g",
                    version=ver, verdict=REVIEW, confidence="low",
                    evidence="npm brotli binding; confirm bundled decoder via marker scan",
                ))
    _ = sysname


def _layer_pip(findings):
    pips = [p for p in ("pip3", "pip") if have(p)]
    if not pips:
        return
    out = run([pips[0], "list", "--format=json"], timeout=60)
    try:
        pkgs = json.loads(out) if out.strip() else []
    except Exception:
        pkgs = []
    for pkg in pkgs:
        name = (pkg.get("name") or "").strip()
        ver = pkg.get("version") or ""
        low = name.lower()
        if low == "brotli":
            verdict, why = simple_verdict(parse_ver(ver), PY_BROTLI_FIXED)
            findings.append(Finding(
                layer="package:pip", component="Brotli (PyPI)", location="pip",
                version=ver, verdict=verdict, confidence="high",
                evidence=f"PYSEC-2026-4322 fixed in 1.2.1: {why}",
                note="auto-used by requests/httpx/aiohttp/urllib3 for 'br' responses",
            ))
        elif low == "brotlicffi":
            verdict, why = simple_verdict(parse_ver(ver), PY_BROTLICFFI_FIXED)
            findings.append(Finding(
                layer="package:pip", component="brotlicffi (PyPI)", location="pip",
                version=ver, verdict=verdict, confidence="high",
                evidence=f"PYSEC-2026-4323 fixed in 1.2.1.0: {why}",
            ))


# --------------------------------------------------------------------------- #
# Layer: language runtimes + running processes
# --------------------------------------------------------------------------- #

def layer_runtimes(findings):
    if have("node"):
        ver = run(["node", "--version"]).strip()
        v = parse_ver(ver)
        verdict, why = node_verdict(v)
        brotli_bundled = run(["node", "-p", "process.versions.brotli"]).strip()
        findings.append(Finding(
            layer="runtime:node", component="Node.js", location=shutil.which("node") or "node",
            version=ver, verdict=verdict, confidence="high",
            evidence=f"{why}; bundled brotli string reports {brotli_bundled or '?'}",
            note="judge Node by the Node version, not process.versions.brotli (fix is cherry-picked)",
        ))
    if have("bun"):
        ver = run(["bun", "--version"]).strip()
        verdict, why = simple_verdict(parse_ver(ver), BUN_FIXED)
        findings.append(Finding(
            layer="runtime:bun", component="Bun", location=shutil.which("bun") or "bun",
            version=ver, verdict=verdict, confidence="high",
            evidence=f"fixed in 1.4.4: {why}",
        ))
    # curl advertises the brotli feature (reachable client path if so)
    if have("curl"):
        out = run(["curl", "--version"])
        if re.search(r"\bbrotli\b", out, re.IGNORECASE):
            findings.append(Finding(
                layer="runtime:curl", component="curl/libcurl", location=shutil.which("curl") or "curl",
                verdict=REVIEW, confidence="low",
                evidence="curl built with brotli feature; check the libbrotlidec it links (ldd/otool)",
                note="client-side decode path; verify the linked lib via the marker layer",
            ))
    # Running processes still mapping a deleted (old) libbrotli  (Linux only)
    if platform.system() == "Linux" and os.path.isdir("/proc"):
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            maps = f"/proc/{pid}/maps"
            try:
                with open(maps, "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            for mline in content.splitlines():
                if "libbrotli" in mline and "(deleted)" in mline:
                    exe = os.path.realpath(f"/proc/{pid}/exe") if os.path.exists(f"/proc/{pid}/exe") else "?"
                    findings.append(Finding(
                        layer="runtime:process", component="process mapping deleted libbrotli",
                        location=f"pid {pid} ({exe})", verdict=POTENTIAL, confidence="medium",
                        evidence="still running an old libbrotli held in memory after on-disk update",
                        note="restart the service to load the patched library",
                    ))
                    break


# --------------------------------------------------------------------------- #
# Layer: containers (read-only rootfs marker scan, no exec)
# --------------------------------------------------------------------------- #

def layer_containers(findings, verbose=False):
    runtimes = [r for r in ("docker", "podman", "nerdctl") if have(r)]
    if not runtimes:
        return
    for rt in runtimes:
        ids = run([rt, "ps", "-q"]).split()
        for cid in ids:
            info = run([rt, "inspect", cid])
            merged = ""
            name = cid[:12]
            try:
                data = json.loads(info)
                if isinstance(data, list) and data:
                    d = data[0]
                    name = (d.get("Name") or name).lstrip("/")
                    merged = (((d.get("GraphDriver") or {}).get("Data") or {}).get("MergedDir") or "")
            except Exception:
                pass
            if merged and os.path.isdir(merged):
                sub = []
                layer_markers([merged], sub, verbose=verbose)
                for f in sub:
                    f.layer = f"container:{rt}"
                    f.note = f"{name}: {f.note}"
                    f.location = f"[{name}] {f.location}"
                    findings.append(f)
            else:
                findings.append(Finding(
                    layer=f"container:{rt}", component=name,
                    location=f"{rt} {cid[:12]}", verdict=REVIEW, confidence="low",
                    evidence="rootfs path not resolvable without elevated access",
                    note="re-run as root, or scan the image filesystem offline",
                ))


# --------------------------------------------------------------------------- #
# Layer: SBOM ingestion (CycloneDX / SPDX JSON)
# --------------------------------------------------------------------------- #

def layer_sbom(paths, findings):
    for path in paths:
        try:
            with open(path, "r", errors="ignore") as fh:
                doc = json.load(fh)
        except Exception as e:
            findings.append(Finding(
                layer="sbom", component=path, location=path,
                verdict=REVIEW, confidence="low", evidence=f"could not parse: {e}"))
            continue
        comps = []
        if isinstance(doc, dict) and "components" in doc:          # CycloneDX
            comps = [(c.get("name", ""), c.get("version", ""), c.get("purl", ""))
                     for c in doc.get("components", []) if isinstance(c, dict)]
        elif isinstance(doc, dict) and "packages" in doc:          # SPDX
            comps = [(p.get("name", ""), p.get("versionInfo", ""),
                      _spdx_purl(p)) for p in doc.get("packages", []) if isinstance(p, dict)]
        for name, ver, purl in comps:
            hay = f"{name} {purl}"
            if not SBOM_NAME_RE.search(hay):
                continue
            low = name.lower()
            if "brotlicffi" in low:
                verdict, why = simple_verdict(parse_ver(ver), PY_BROTLICFFI_FIXED)
            elif low in ("brotli",) or "py-brotli" in low:
                verdict, why = simple_verdict(parse_ver(ver), PY_BROTLI_FIXED)
            else:
                verdict, why = brotli_lib_verdict(parse_ver(ver))
            findings.append(Finding(
                layer="sbom", component=name or purl, location=os.path.basename(path),
                version=ver, verdict=verdict, confidence="medium",
                evidence=f"{why} ({purl or 'no purl'})",
                note="SBOM finds declared deps; statically-linked copies still need the marker scan",
            ))


def _spdx_purl(pkg):
    for ref in pkg.get("externalRefs", []) or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator", "")
    return ""


# --------------------------------------------------------------------------- #
# Layer: source reachability
# --------------------------------------------------------------------------- #

def layer_source(src_roots, findings):
    for root in src_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if ".git" in dirnames:
                dirnames.remove(".git")
            if "node_modules" in dirnames:
                dirnames.remove("node_modules")
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                low = name.lower()
                if ext not in REACH_EXT and "dockerfile" not in low:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 3 * 1024 * 1024:
                        continue
                    with open(path, "r", errors="ignore") as fh:
                        text = fh.read()
                except Exception:
                    continue
                hits = [label for label, rx in REACH_PATTERNS.items() if rx.search(text)]
                if hits:
                    findings.append(Finding(
                        layer="source-reachability", component=", ".join(hits),
                        location=path, verdict=POTENTIAL, confidence="low",
                        evidence="decode entry point(s) in source; untrusted input may reach a decoder",
                        note="ranking signal only - confirm an affected decoder is actually linked",
                    ))


# --------------------------------------------------------------------------- #
# Default scan roots
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def rollup(findings):
    counts = {VULNERABLE: 0, POTENTIAL: 0, REVIEW: 0, PATCHED: 0, CLEAN: 0}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    return counts


def render_text(findings, counts, host):
    order = sorted(findings, key=lambda f: (-SEVERITY.get(f.verdict, 0), f.layer, f.location))
    lines = []
    lines.append("=" * 78)
    lines.append(f" Brotli2Shell / HTTP2Shell (CVE-2026-111497) exposure report")
    lines.append(f" host: {host['hostname']}   os: {host['os']}   time: {host['time']}")
    lines.append("=" * 78)
    lines.append(f" VULNERABLE: {counts[VULNERABLE]}   POTENTIAL: {counts[POTENTIAL]}   "
                 f"REVIEW: {counts[REVIEW]}   PATCHED: {counts[PATCHED]}   CLEAN: {counts[CLEAN]}")
    lines.append("-" * 78)
    if not findings:
        lines.append(" No Brotli decoder copies or decode paths found in scanned scope.")
    for f in order:
        if f.verdict in (PATCHED, CLEAN):
            continue
        lines.append(f"[{f.verdict}] ({f.confidence}) {f.layer}")
        lines.append(f"    component : {f.component}" + (f"  {f.version}" if f.version else ""))
        lines.append(f"    location  : {f.location}")
        lines.append(f"    evidence  : {f.evidence}")
        if f.note:
            lines.append(f"    note      : {f.note}")
    shown_patched = [f for f in order if f.verdict in (PATCHED, CLEAN)]
    if shown_patched:
        lines.append("-" * 78)
        lines.append(f" {len(shown_patched)} copy/copies verified patched or not-affected (hidden; see JSON).")
    lines.append("-" * 78)
    lines.append(" Remediation: " + FIX_HINT)
    lines.append("=" * 78)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

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
    payload = {
        "cve": "CVE-2026-111497",
        "aka": ["HTTP2Shell", "Node2Shell", "Python2Shell", "Brotli2Shell"],
        "host": host,
        "summary": counts,
        "remediation": FIX_HINT,
        "findings": [f.as_dict() for f in findings],
    }

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
