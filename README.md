# Brotli2Shell Hunter

Read-only, version-independent detector for **CVE-2026-111497** (aliases: Brotli2Shell, HTTP2Shell, Node2Shell, Python2Shell). It finds vulnerable Brotli decoder copies on a host and says whether each one is reachable from untrusted input.

## What it detects

- Brotli C library copies below the fixed lines (1.0.10 / 1.1.1 / 1.2.1).
- Node.js, Bun, and other runtimes with bundled Brotli below their fixed releases.
- PyPI `Brotli` and `brotlicffi`, plus other language bindings and native libraries listed in `ruledata.py`.
- Decoders embedded in binaries, detected by marker strings rather than version strings.

## Install

```
pip install -e .
```

This installs the `b2s-hunt` entry point (`b2s_hunter.cli:main`). The core scan uses only the standard library. Python 3.8+.

## Usage

```
b2s-hunt                                   # default scan: packages, runtimes, default library roots
b2s-hunt --path /opt/app --only-paths      # scan only the given root
b2s-hunt --containers                      # also read running container rootfs (no exec)
b2s-hunt --source ./repo                   # reachability grep over a source tree
b2s-hunt --sbom bom.cdx.json               # ingest a CycloneDX/SPDX JSON SBOM
b2s-hunt --only packages,markers           # run selected layers
b2s-hunt --skip source                     # skip selected layers
b2s-hunt --format json -o report.json      # machine-readable report
```

## Layers (`src/b2s_hunter/layers/`)

| Layer | Source | Runs when |
|---|---|---|
| `packages` | dpkg/rpm/apk, pip, global npm | default |
| `markers` | binary marker scan over default or `--path` roots | default |
| `runtimes` | Node, Bun, curl version and bundled Brotli | default |
| `containers` | running container rootfs, read-only | `--containers` |
| `sbom` | CycloneDX / SPDX JSON | `--sbom FILE` |
| `source` | source reachability patterns | `--source DIR` |

Each layer skips silently if its prerequisite tool is missing.

## Verdicts (`src/b2s_hunter/model.py`)

Every finding carries one of five verdicts, ordered by severity:

- `VULNERABLE`: affected version or marker present.
- `POTENTIALLY_VULNERABLE`: indirect evidence, such as a runtime that may bundle Brotli.
- `NEEDS_REVIEW`: unknown or unparseable version, or a verify-only component.
- `PATCHED`: at or above the fixed version, or fixed marker present.
- `NOT_AFFECTED`: no evidence of the component.

Enrichment adds `reach` (`reachable-untrusted`, `config-gated`, `trusted-only`, `unknown`), priority (0-100), fix, restart, controls, and verify fields.

## Output formats (`--format`)

- `text` (default), `json`, `both` (text followed by JSON).
- `sarif`: SARIF 2.1.0 for code-scanning upload.
- `vex-cdx`: CycloneDX VEX.
- `openvex`: OpenVEX.
- `sbom-cdx`: CycloneDX SBOM of the findings.

Use `-o FILE` to write to a file instead of stdout.

## CI policy

- `--fail-on reachable-vulnerable` (default): `VULNERABLE` fails unless `reach` is `trusted-only`. Unknown reach fails closed.
- `--fail-on any-vulnerable`: every `VULNERABLE` fails.
- `--fail-on never`: never fail.
- `--warn-on present` (default): warn on `POTENTIALLY_VULNERABLE`, `NEEDS_REVIEW`, and non-failing `VULNERABLE`.
- `--warn-on never`: no warnings.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | pass: nothing vulnerable or to review |
| 1 | fail: policy failure |
| 2 | warn: only needs-review or potential findings |
| 3 | runtime error (returned on keyboard interrupt) |

## Drift

```
b2s-hunt --save-baseline base.json         # record current findings
b2s-hunt --baseline base.json              # diff this scan against the baseline
```

The JSON payload then includes a `drift` section with `new`, `resolved`, and `changed` findings.

## Reachability and mitigation

- **Reachability** (`reachability.py`): heuristic rules that match each finding's layer, component, location, and evidence. Rules set reach, direction, input trust, and whether the component is internet-facing. These are ranking signals, not proof. `--source` supplies the grep evidence.
- **Mitigation** (`mitigation.py`): per-component exact fix, the "install is not fixed" restart instruction, compensating controls, what those controls do not cover, and a post-fix verify step. Output includes a `remediation_plan`.

## Rule data

All advisory-specific data lives in `src/b2s_hunter/ruledata.py`: marker strings, fixed-version thresholds, the component list, reachability patterns, and `RULES_VERSION`/`RULES_DATE`. Updating an advisory means editing that one file and bumping `RULES_VERSION`. Verdict logic is in `versions.py` and reads these values.

## Read-only guarantee

The tool does not modify scanned files, install packages, or execute scanned binaries. It queries local package managers and runtimes for version information (for example `dpkg-query`, `npm ls`, `node -p`) and reads files. Only `-o`, `--save-baseline`, and the `sarif`/`vex`/`sbom` outputs write to disk, and only to the path you name.

## Known limitations

These are reported in every run under "BLIND SPOTS" (`blindspots.py`):

- Containers and running containers are not scanned unless `--containers` is given.
- The memory-resident check (loaded libraries in running processes) works only on Linux.
- Without `--source`, reachability is `unknown`. Without `--sbom`, vendored and prebuilt components are not cross-checked.
- Compressed archives (zip, tar.gz, jar, wheel, asar, UPX) are not unpacked.
- Stripped, statically linked, obfuscated, or packed binaries may hide markers. A missing marker is not proof of absence.
- Files above 300 MiB and unreadable paths are skipped.
- A clean result covers only the scanned scope, not an unqualified "not vulnerable".

## Development

```
pip install -e ".[dev]"
pytest
```

## License

MIT

## Additional options

| Flag | Purpose |
|---|---|
| `--source DIR` | also runs the `lockfiles` layer on DIR (npm/yarn/pnpm, pip/poetry/Pipfile, go, cargo, gem, NuGet, Dockerfile, .nvmrc) |
| `--verify BASELINE` | after patching and restarting, rescan and compare to a pre-fix baseline; exit 1 if any fix is ineffective |
| `--format csaf-vex` | CSAF 2.0 VEX output |
| `--rules-overlay FILE` | offline rules update (may only raise thresholds or add components) |
| `--write-rules-manifest FILE` / `--verify-rules FILE` | pin and verify the rule data digest |
| `--probe URL --authorized` | ACTIVE, opt-in: sends one harmless valid Brotli request body per target (rate-limited, attributable User-Agent). Only use on systems you are authorized to test |

Backport reconciliation runs automatically: a distro package with an old version whose binary carries the fix marker is reported as patched. The `memres` layer (Linux) flags processes still mapping a deleted, pre-patch library; restart them.
