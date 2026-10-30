"""Layer: dependency manifests / lockfiles (static parse only, nothing is executed)."""

from __future__ import annotations

import json
import os
import re

from .. import ruledata as rd
from ..model import CLEAN, PATCHED, REVIEW, VULNERABLE, Finding
from ..versions import node_verdict, parse_ver, simple_verdict

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", ".tox", "site-packages",
             "__pycache__", ".mypy_cache"}
REQ_RE = re.compile(r"^requirements.*\.txt$", re.I)
DOCKER_RE = re.compile(r"(^Dockerfile(\..*)?$)|(\.Dockerfile$)", re.I)
NODE_VERSION_FILES = {".nvmrc", ".node-version"}
# Python packages whose [extras] pull in a Brotli package automatically.
PY_BROTLI_EXTRAS = {"urllib3": {"brotli"}, "httpx": {"brotli"}, "requests": {"brotli"},
                    "aiohttp": {"speedups"}, "scrapy": {"brotli"}}
DOTNET_FIXED = {8: (8, 0, 33), 9: (9, 0, 22), 10: (10, 0, 14)}

_NPM = {"brotli", "brotli-wasm", "iltorb", "brotli-dec-wasm", "brotli-size", "@cyclonedx/cdxgen"}
_PY_OTHER = {"pyarrow", "duckdb"}
_GO = {"github.com/andybalholm/brotli", "github.com/google/brotli/go/cbrotli",
       "github.com/google/brotli"}
_CARGO = {"brotli-decompressor", "brotli-sys", "brotli"}


def _norm_py(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _purl(eco, name, ver):
    v = f"@{ver}" if ver else ""
    if eco == "npm":
        return f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}{v}"
    t = {"pypi": "pypi", "go": "golang", "cargo": "cargo", "gem": "gem", "nuget": "nuget"}.get(eco)
    return f"pkg:{t}/{name}{v}" if t else f"pkg:generic/{name}{v}"


def _is_exact(ver):
    return bool(ver) and re.fullmatch(r"v?\d+(\.\d+)*([.\-+][0-9A-Za-z.\-+]*)?", ver.strip()) is not None


def _verdict(eco, name, ver):
    """Return (verdict, why) for a tracked dependency, or None if not relevant."""
    low = name.lower()
    exact = _is_exact(ver)
    v = parse_ver(ver) if exact else None
    if eco == "pypi":
        if low == "brotli":
            fixed = rd.PY_BROTLI_FIXED
        elif low == "brotlicffi":
            fixed = rd.PY_BROTLICFFI_FIXED
        elif low in _PY_OTHER:
            return REVIEW, f"{low} affected/unfixed upstream; isolate untrusted Parquet/data"
        else:
            return None
        if not exact:
            return REVIEW, f"unpinned/range spec '{ver}'"
        return simple_verdict(v, fixed)
    if eco == "npm":
        if low not in _NPM:
            return None
        return REVIEW, ("npm brotli binding; confirm bundled decoder via marker scan"
                        + ("" if exact else f" (range spec '{ver}')"))
    if eco == "go":
        if low not in _GO:
            return None
        return REVIEW, "Go brotli: andybalholm fixed 23 Oct 2026 (crash-only); cgo bindings bundle C"
    if eco == "cargo":
        if low == "brotli-decompressor":
            return CLEAN, "brotli-decompressor returns an error instead of corrupting memory"
        if low in _CARGO:
            return REVIEW, "Rust brotli crate; verify it does not link the C decoder"
        return None
    if eco == "gem":
        if low != "brotli":
            return None
        if not exact:
            return REVIEW, f"unpinned spec '{ver}'"
        return simple_verdict(v, (0, 9, 1))
    if eco == "nuget":
        if low.startswith("microsoft.netcore.app.runtime"):
            if not exact:
                return REVIEW, f"range spec '{ver}'"
            fx = DOTNET_FIXED.get(v[0]) if v else None
            if fx is None:
                return REVIEW, ".NET line not in known fixed set"
            return (PATCHED, "at/above line fix") if v >= fx else (VULNERABLE, "below line fix")
        if "brotli" in low:
            return REVIEW, "NuGet brotli package; confirm whether it wraps the native C decoder"
        return None
    return None


def _emit(findings, path, eco, name, ver, transitive=None):
    r = _verdict(eco, name, ver or "")
    if r is None:
        return
    verdict, why = r
    note = {True: "transitive dependency", False: "direct dependency"}.get(transitive, "")
    findings.append(Finding(
        layer="lockfile", component=name, location=path, version=ver or "",
        verdict=verdict, confidence="high" if _is_exact(ver or "") and verdict != REVIEW else "medium",
        evidence=f"{os.path.basename(path)}: {why}", note=note,
        purl=_purl(eco, name, ver if _is_exact(ver or "") else "")))


def _emit_extras(findings, path, name, extras, spec):
    """urllib3[brotli] etc: the extra auto-installs a Brotli package."""
    wanted = PY_BROTLI_EXTRAS.get(_norm_py(name), set())
    hit = [e for e in extras if e.lower() in wanted or "brotli" in e.lower()]
    if not hit:
        return
    findings.append(Finding(
        layer="lockfile", component=f"{name}[{','.join(hit)}]", location=path, version=spec or "",
        verdict=REVIEW, confidence="medium",
        evidence=f"{os.path.basename(path)}: extra [{','.join(hit)}] auto-enables a Brotli package",
        note="auto-enabled extra: pulls Brotli/brotlicffi transitively; resolved version unknown "
             "here, check the lock/installed version",
        purl=_purl("pypi", _norm_py(name), ""),
        gate="only if the Brotli package is installed"))


def _read(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def _p_package_lock(path, f):
    doc = json.loads(_read(path))
    directs = set()
    pj = os.path.join(os.path.dirname(path), "package.json")
    if os.path.isfile(pj):
        try:
            d = json.loads(_read(pj))
            for k in ("dependencies", "devDependencies", "optionalDependencies"):
                directs |= set((d.get(k) or {}).keys())
        except Exception:
            pass
    pk = doc.get("packages")
    if isinstance(pk, dict):
        root = pk.get("") or {}
        for k in ("dependencies", "devDependencies", "optionalDependencies"):
            directs |= set((root.get(k) or {}).keys())
        for key, meta in pk.items():
            if not key or not isinstance(meta, dict):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            nested = key.count("node_modules/") > 1
            _emit(f, path, "npm", name, meta.get("version", ""),
                  transitive=nested or name not in directs)
    else:
        def walk(deps, depth):
            for name, meta in (deps or {}).items():
                if not isinstance(meta, dict):
                    continue
                _emit(f, path, "npm", name, meta.get("version", ""),
                      transitive=depth > 0 or (bool(directs) and name not in directs))
                walk(meta.get("dependencies"), depth + 1)
        walk(doc.get("dependencies"), 0)


def _p_yarn_lock(path, f):
    name = None
    for line in _read(path).splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if not line.startswith(" "):
            first = line.rstrip(":").split(",")[0].strip().strip('"')
            name = first.rsplit("@", 1)[0]
        else:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            if m and name:
                _emit(f, path, "npm", name, m.group(1))


def _p_pnpm_lock(path, f):
    seen = set()
    for line in _read(path).splitlines():
        if not line.rstrip().endswith(":") and not line.rstrip().endswith("':"):
            continue
        m = (re.match(r"^\s{2}'?/?((?:@[^/@\s']+/)?[^@/\s']+)@(\d[^:'()_\s]*)", line)
             or re.match(r"^\s{2}'?/?((?:@[^/@\s']+/)?[^@/\s']+)/(\d[^:'()_\s]*)", line))
        if m and m.groups() not in seen:
            seen.add(m.groups())
            _emit(f, path, "npm", m.group(1), m.group(2))


def _p_requirements(path, f):
    for raw in _read(path).splitlines():
        line = raw.split(" #")[0].split(";")[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name, extras, spec = m.group(1), m.group(2) or "", m.group(3).strip()
        pin = re.match(r"^===?\s*([^\s,]+)$", spec)
        _emit(f, path, "pypi", _norm_py(name), pin.group(1) if pin else spec, transitive=False)
        if extras:
            _emit_extras(f, path, name, [e.strip() for e in extras.strip("[]").split(",")], spec)


def _p_pipfile_lock(path, f):
    doc = json.loads(_read(path))
    for sect in ("default", "develop"):
        for name, meta in (doc.get(sect) or {}).items():
            _emit(f, path, "pypi", _norm_py(name), (meta or {}).get("version", "").lstrip("="))


def _name_version_toml(eco):
    def parse(path, f):
        name = None
        for line in _read(path).splitlines():
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                name = m.group(1)
                continue
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m and name:
                _emit(f, path, eco, _norm_py(name) if eco == "pypi" else name, m.group(1))
                name = None
    return parse


def _p_go_mod(path, f):
    for line in _read(path).splitlines():
        m = re.match(r"^\s*(?:require\s+)?(\S+)\s+(v\d\S*)(.*)$", line)
        if m and "." in m.group(1) and not line.strip().startswith(("module", "go ", "//")):
            _emit(f, path, "go", m.group(1), m.group(2), transitive="// indirect" in m.group(3))


def _p_go_sum(path, f):
    seen = set()
    for line in _read(path).splitlines():
        p = line.split()
        if len(p) >= 2:
            ver = p[1].replace("/go.mod", "")
            if (p[0], ver) not in seen:
                seen.add((p[0], ver))
                _emit(f, path, "go", p[0], ver)


def _p_gemfile_lock(path, f):
    for line in _read(path).splitlines():
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
        if m:
            _emit(f, path, "gem", m.group(1), m.group(2).split("-")[0])


def _p_nuget_lock(path, f):
    doc = json.loads(_read(path))
    for deps in (doc.get("dependencies") or {}).values():
        for name, meta in (deps or {}).items():
            _emit(f, path, "nuget", name, (meta or {}).get("resolved", ""),
                  transitive=(meta or {}).get("type") == "Transitive")


def _p_csproj(path, f):
    for tag in re.findall(r"<PackageReference\b[^>]*>", _read(path), re.I):
        inc = re.search(r'Include="([^"]+)"', tag, re.I)
        ver = re.search(r'Version="([^"]*)"', tag, re.I)
        if inc:
            _emit(f, path, "nuget", inc.group(1), ver.group(1) if ver else "", transitive=False)


def _node_finding(f, path, ver, evidence, note="", force_review=False):
    v = parse_ver(ver) if re.match(r"^v?\d", ver or "") else None
    verdict, why = node_verdict(v)
    if force_review:
        verdict = REVIEW
    f.append(Finding(layer="lockfile", component="Node.js", location=path, version=ver or "",
                     verdict=verdict, confidence="medium" if v and not force_review else "low",
                     evidence=f"{evidence}: {why}", note=note,
                     purl=f"pkg:generic/node@{ver}" if v and not force_review else "pkg:generic/node"))


def _p_node_version_file(path, f):
    txt = _read(path).strip()
    ver = txt.splitlines()[0].strip() if txt else ""
    if re.match(r"^v?\d+(\.\d+){2}$", ver):
        _node_finding(f, path, ver, os.path.basename(path))
    else:
        _node_finding(f, path, ver, f"{os.path.basename(path)} floating/partial spec",
                      "resolved Node version unknown", force_review=True)


def _p_package_json(path, f):
    eng = (json.loads(_read(path)).get("engines") or {}).get("node")
    if eng:
        _node_finding(f, path, eng, "package.json engines.node (range)", "range-only spec",
                      force_review=True)


def _p_dockerfile(path, f):
    for line in _read(path).splitlines():
        m = re.match(r"^\s*FROM\s+(?:--\S+\s+)*(node|python)(?::(\S+))?(?:\s|$)", line, re.I)
        if not m:
            continue
        img, tag = m.group(1).lower(), m.group(2) or "latest"
        if img == "node":
            exact = re.match(r"^(\d+(?:\.\d+){2})(?:[-_].*)?$", tag)
            partial = re.match(r"^(\d+(?:\.\d+)?)(?:[-_].*)?$", tag)
            if exact:
                _node_finding(f, path, exact.group(1), f"FROM node:{tag}")
            elif partial:
                ver = partial.group(1)
                _node_finding(f, path, ver, f"FROM node:{tag} (floating tag)",
                              "tag not pinned to a patch version; image may or may not carry the fix",
                              force_review=node_verdict(parse_ver(ver))[0] != VULNERABLE)
            else:
                _node_finding(f, path, tag, f"FROM node:{tag}", "non-numeric tag", force_review=True)
        else:
            f.append(Finding(
                layer="lockfile", component="python base image", location=path, version=tag,
                verdict=REVIEW, confidence="low", evidence=f"FROM python:{tag}",
                note="python image is not itself the Brotli carrier; check pip Brotli/brotlicffi "
                     "and bundled libbrotli in the image",
                purl="pkg:docker/python"))


_TABLE = {"package-lock.json": _p_package_lock, "npm-shrinkwrap.json": _p_package_lock,
          "yarn.lock": _p_yarn_lock, "pnpm-lock.yaml": _p_pnpm_lock,
          "pipfile.lock": _p_pipfile_lock, "poetry.lock": _name_version_toml("pypi"),
          "go.mod": _p_go_mod, "cargo.lock": _name_version_toml("cargo"),
          "gemfile.lock": _p_gemfile_lock, "packages.lock.json": _p_nuget_lock,
          "package.json": _p_package_json}


def _dispatch(name):
    low = name.lower()
    if low in _TABLE:
        return _TABLE[low]
    if REQ_RE.match(name):
        return _p_requirements
    if low.endswith((".csproj", ".fsproj", ".vbproj")):
        return _p_csproj
    if name in NODE_VERSION_FILES:
        return _p_node_version_file
    if DOCKER_RE.search(name):
        return _p_dockerfile
    return None


def layer_lockfiles(roots, findings):
    for root in roots:
        if os.path.isfile(root):
            _process(root, findings, set())
            continue
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if "pyvenv.cfg" in files:
                dirs[:] = []
                continue
            for fn in files:
                _process(os.path.join(dirpath, fn), findings, set(files))


def _process(path, findings, siblings):
    name = os.path.basename(path)
    if name.lower() == "go.sum":
        if "go.mod" in siblings:
            return
        parser = _p_go_sum
    else:
        parser = _dispatch(name)
    if parser is None:
        return
    try:
        parser(path, findings)
    except Exception as e:
        findings.append(Finding(layer="lockfile", component=name, location=path,
                                verdict=REVIEW, confidence="low",
                                evidence=f"could not parse: {e}"))
