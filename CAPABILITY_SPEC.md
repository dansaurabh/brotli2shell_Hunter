# Capability Specification — Brotli2Shell Hunter
### What a high-quality detector for CVE-2026-111497 must deliver

**CVE:** CVE-2026-111497 — out-of-bounds write in Google's Brotli decoder (CWE-787).
Aliases: HTTP2Shell / Node2Shell / Python2Shell / Brotli2Shell / Broccoli2Shell.
**Severity:** CVSS v4.0 **9.2 (Critical)**. Affected Brotli C decoder **1.0.3–1.2.0**; fixed **1.0.10 / 1.1.1 / 1.2.1** (upstream commit `0ed4268`).
**Threat context (as of 26 Oct 2026):** Not in CISA KEV. No confirmed exploitation in the wild (as of 22 Oct). Public PoCs reach full RCE only on deliberately weakened builds; on standard builds the realistic outcome is a crash (DoS) plus a limited memory read. Imperva demonstrated RCE on an unmodified Node.js 24.22.0 build but has not released the exploit.

This document is the requirements bar for the tool. It is organized around the
three things you asked for — **miss nothing**, **separate identification from
exploitability**, and **give proper mitigation** — plus what the two consuming
personas (security professional, supply-chain engineer) each need to walk away with.

---

## 0. First principle — four states, never collapsed into one

The single biggest quality failure in CVE scanners is reporting one flat
"VULNERABLE". A trustworthy tool keeps these **four states distinct** on every
finding, because the response differs at each:

| State | Question it answers | How the tool knows |
|---|---|---|
| **PRESENT** | Is a Brotli decoder here at all? | decoder marker / symbol / declared dependency |
| **VULNERABLE** (identification) | Does *this copy* lack the fix? | fix-marker absent, or version below the line fix, reconciled for backports |
| **REACHABLE** (exposure) | Can untrusted input reach the decoder? | decode entry-point + input-source + config analysis |
| **EXPLOITABLE** (risk) | Can reaching it actually corrupt memory / RCE here? | build hardening, mitigations, direction, exposure |

Plus two orthogonal modifiers that drive priority: **internet-facing?** and
**in-the-wild status?**

> The rule: *identification is a property of the code; exploitability is a property
> of the deployment.* The tool must report the first with high confidence and the
> second with explicit, labelled uncertainty — never silently merge them. A
> VULNERABLE verdict on V8's internal snapshot decoder (trusted input only) and a
> VULNERABLE verdict on a public Node.js request-body path must not look the same.

Every finding therefore carries: patch-state verdict • confidence • provenance •
reachability verdict • exposure context • a **composite priority** derived from all
of them • and remediation specific to that component.

---

## 1. Completeness of identification — "miss nothing"

### 1.1 The five places a vulnerable decoder hides (all must be covered)

- **A. Declared dependencies** — OS packages (dpkg/rpm/apk), language packages
  (pip, npm, gem, composer, maven/gradle, nuget, cargo, go modules), lockfiles.
- **B. Bundled / vendored / statically-linked copies** — the hard part; no package
  manager sees these. Requires **version-independent binary marker scanning**.
- **C. Transitive & auto-enabled paths** — a decoder pulled in by another dependency,
  or extras that silently enable it (`httpx[brotli]`, `aiohttp`, urllib3/requests when
  a Brotli package is present, Scrapy).
- **D. Runtime-embedded** — Node.js, Bun, V8/`libv8_*`, Deno, .NET native decoder,
  Electron, GraalJS. Judge Node by the **Node** version, not `process.versions.brotli`
  (the fix is cherry-picked).
- **E. Non-package artifacts** — firmware/UEFI (EDK II), fonts (woff2), media
  (JPEG XL via libjxl), archives (7-Zip forks, NanaZip, p7zip), columnar data
  (Parquet via Arrow/pyarrow, DuckDB, ClickHouse, YDB), container images & layers,
  and CI/CD runners and SBOM generators that ingest untrusted input.

### 1.2 Detection methods required to cover A–E

1. **Marker-based classification (core, version-independent).** `_ERROR_FORMAT_EXUBERANT_NIBBLE` = decoder present; `_ERROR_FORMAT_BLOCK_SWITCH` = patched copy. Beats backport false-positives *and* vendored-copy false-negatives at once.
2. **Symbol scan** — `BrotliDecoderDecompress[Stream]` as secondary evidence when error strings are stripped.
3. **Version + backport reconciliation** — a package version that *reads* vulnerable but whose on-disk library carries the fix marker is **patched** (don't tell people to upgrade a fixed backport).
4. **Archive introspection without installing** — look inside `.whl`, `.jar`, `.deb`, `.rpm`, `.apk`, `.nupkg`, container layers.
5. **Memory-resident check** — processes still mapping a **deleted** old libbrotli (patched on disk, unpatched in RAM until restart).
6. **Cross-platform binaries** — ELF, Mach-O (incl. fat), PE.
7. **SBOM ingestion** — CycloneDX & SPDX, resolved by **purl**, including transitive components.

### 1.3 Component coverage checklist (the "don't miss anything" reference)

Keep this as the tool's rule set; update as advisories land. Status as tracked 26 Oct 2026.

**Core / runtimes**
- Google Brotli C lib — vuln 1.0.3–1.2.0 → fixed 1.0.10 / 1.1.1 / 1.2.1
- Node.js 22/24/26 — fixed 22.23.4 / 24.22.1 / 26.12.1; **20, 23, 25 = EOL, no fix**
- Bun — fixed 1.4.4
- Deno — verify against bundled Brotli (tracker gap)
- .NET runtime — fixed 8.0.33 / 9.0.22 / 10.0.14 / 11.0.0-rc.3 (**GitHub source builds still affected**)
- curl / libcurl — reachable client path if built with brotli; check the linked libbrotlidec

**Python** — `Brotli` → 1.2.1 • `brotlicffi` → 1.2.1.0 • requests/urllib3/httpx[brotli]/aiohttp/Scrapy exposed only when a Brotli package is installed

**Other bindings** — Go `andybalholm/brotli` (crash-only, fixed 23 Oct) • Go cgo bindings (bundled C) • Ruby `brotli` gem → 0.9.1 • PHP `kjdev` ext → 0.21.1 • Java `Brotli4j` (fixed) • Rust `brotli-decompressor` (**not affected** — returns error) • pure Java/JS/C# ports (**not affected**) • Express/body-parser are *paths*, not fix targets

**Data / media / DB** — ClickHouse (master patched; **no release**, backports open) • Apache Arrow/pyarrow (PR #55167 approved, **not merged**) • DuckDB (PR #27791, **affected**) • YDB (main patched 23 Oct, **no release**) • libjxl (PR #5062, **no release**) • GraalJS (merged 22 Oct, **no release**) • FFmpeg (via libjxl — tracker gap)

**Fonts / docs / firmware / archives** — woff2 (PR #208, **affected** on Makefile build) • MuPDF (1.28.x fixed; 1.27.x affected) • UEFITool (fixed A76) • EDK II (**affected**, #13378) • 7-Zip-zstd / p7zip (**affected**) • NanaZip (no release) • v8-jsi (bundles 1.2.0, **affected**)

**Infra (verify separately — tracker gaps):** Envoy (ISTIO/Envoy advisory), Istio (1.31.2/1.30.6/1.29.9 — only if Brotli decompression enabled), cdxgen.

**Already fixed before list:** Chromium, Firefox, ngx_brotli, SumatraPDF, Ghostscript, CatBoost, YTsaurus.

### 1.4 Honest blind-spot reporting (a quality requirement, not optional)

The tool must **declare what it could not see**: stripped/obfuscated binaries,
scopes not scanned (paths, offline hosts), containers it lacked privilege to read,
prebuilt wheels/binaries without SBOM data. A clean result must say *"clean within
scanned scope X"*, never an unqualified "not vulnerable."

---

## 2. Exploitability / reachability analysis — the differentiator

Presence + unpatched ≠ exploitable. The tool must assess reach, separately and
with labelled confidence.

### 2.1 Reach-path detection, by direction

- **Server-side (inbound):** request-body decompression — `Content-Encoding: br` into
  Express/body-parser, ASP.NET Core request decompression, ClickHouse HTTP body,
  proxy/LB Brotli decode. *Highest priority — unauthenticated, network-facing.*
- **Client-side (outbound/bidirectional):** a malicious **server** attacks a client that
  auto-decodes — `fetch()`, HTTP client libs, **browsing agents / crawlers / recon tooling**,
  CI/CD runners, SBOM generators. Cannot be WAF'd.
- **File / data path (no HTTP):** JPEG XL `brob` boxes (libjxl/FFmpeg), Parquet pages
  (Arrow/DuckDB), fonts (woff2), archives, firmware sections, queue messages, caches.

### 2.2 Input-trust & config gating

- Classify the input source as **untrusted** (network, uploads, fetched pages) vs
  **trusted** (build-time snapshots, internal data). V8's bundled decoder used only for
  its own startup snapshot → **trusted → down-rank** despite a VULNERABLE verdict.
- Flag **config-gated** paths (e.g. Envoy/Istio only if Brotli decompression is enabled;
  Python clients only if a Brotli package is installed).

### 2.3 Exploitability realism

Report the *realistic* impact, not just the headline 9.2: default outcome is **DoS +
limited memory disclosure**; full RCE is situational (depends on build hardening /
ASAN / allocator / platform). State this so teams don't over- or under-react.

### 2.4 Required output of this layer

- A **reachability verdict** per finding: `reachable-untrusted` / `config-gated` /
  `trusted-only` / `unknown`, independent of the patch verdict.
- A **composite priority** combining patch-state × reachability × internet-facing ×
  input-trust.
- **VEX emission** (CycloneDX VEX, OpenVEX, CSAF VEX) so each component gets a machine-
  readable exploitability status — `affected` / `not_affected` (with justification, e.g.
  `vulnerable_code_not_in_execute_path`) / `under_investigation` / `fixed`. *This is the
  single most valuable output for suppressing downstream noise.*

---

## 3. Mitigation quality — specific, correct, complete

Every actionable finding must carry remediation that is right for *that* component.

### 3.1 Primary fix
- The **exact fixed version** for the component (from the §1.3 table), not a generic
  "update Brotli." For vendored source with no release, point to **cherry-pick `0ed4268`**.

### 3.2 "Install ≠ fixed" — the step most tools omit
- Instruct **rebuild image → redeploy → restart process → re-pin lockfile**. Surface the
  **deleted-lib-in-memory** case explicitly: the service is still running the old decoder
  until restarted.

### 3.3 Backport-aware
- If marker reconciliation shows a backport already carries the fix, say **"no action —
  backport-patched"** rather than prompting a needless upgrade.

### 3.4 Compensating controls (when patching can't ship now)
- **Inbound:** reject `Content-Encoding: br` request bodies at proxy / LB / WAF
  (Vercel shipped exactly this on disclosure day). No legitimate browser compresses
  request bodies.
- **Proxies:** disable Brotli decompression in Envoy/Istio/nginx where enabled.
- **Python:** uninstall `Brotli` / `brotlicffi` and drop `[brotli]` extras → clients fall
  back to gzip/deflate.
- **File ingestion:** isolate untrusted file/data ingestion away from unpatched engines
  (DuckDB, Arrow, ClickHouse).

### 3.5 State what the control does **not** cover (correctness)
- **Outbound/client-side cannot be WAF'd** — a malicious server still sends Brotli, and a
  WAF doesn't inspect responses your app fetches. Only a **library/runtime upgrade** closes
  that path. Stripping `br` from `Accept-Encoding` helps little. The tool must say this,
  or it gives false comfort.

### 3.6 Verification
- Provide the **re-check**: rescan after restart and confirm the loaded copy now carries
  the fix marker (not just that a new version is installed).

---

## 4. What each persona must be able to get out of it

### 4.1 Security professional (pen test / CTEM / IR)
- **Exposure-ranked** findings — internet-facing + untrusted-reach first.
- **Evidence per finding** for the report: file path, marker/symbol, owning package,
  reach path, config gate.
- Option to **confirm externally** on net-facing services (hand off to an active HTTP
  probe), clearly separated from passive inventory.
- Severity that **separates DoS from RCE**, with the realistic-impact note.
- **Hunt guidance:** anomalous Brotli-compressed request traffic, unexpected process
  crashes, `BLOCK_SWITCH`/error `-17` in logs as probe indicators.
- Report-ready export (contextual score, not just the raw 9.2).

### 4.2 Supply-chain engineer
- **SBOM-native:** ingest **and emit** CycloneDX/SPDX with purl; resolve **transitive**.
- **VEX emission** to suppress non-reachable copies downstream with justifications.
- **SARIF** output → GitHub code scanning / CI gate; meaningful **exit codes**.
- **Policy thresholds:** fail build on `reachable + vulnerable`; warn on `present-only`.
- **Reproducible & offline/air-gapped:** deterministic, pinned rule DB, dated provenance.
- **Provenance:** which artifact bundles the copy, owning package.
- **Fleet drift tracking** over time (what changed between scans).

---

## 5. Engineering quality bars (so the results are trusted)

- **Low false-positive:** marker reconciliation + three-level **confidence** (high/med/low) on every finding.
- **Explicit unknowns:** blind spots reported, never silent (see §1.4).
- **Deterministic & reproducible;** rule data **versioned, dated, signed/pinned**, with the advisory date each rule reflects.
- **Rule DB in one place** — thresholds, markers, component list externalized so adding .NET/DuckDB/Arrow updates is a single-file edit; optional **auto-update from OSV/GHSA** with offline fallback.
- **Read-only & non-invasive** always; active/HTTP mode is opt-in, **rate-limited, and sends an attributable User-Agent** so blue teams can see the scan.
- **Performance** on large fleets, images, and monorepos; concurrency with caps.
- **Cross-platform parity** (ELF/Mach-O/PE; Linux/macOS/Windows collection layers).

---

## 6. Must-have punch list

- [ ] Four-state model (present / vulnerable / reachable / exploitable) on every finding
- [ ] Version-independent **marker** core + symbol fallback
- [ ] Backport reconciliation (version↔marker)
- [ ] Vendored/static + **archive** + **container-layer** + **memory-resident** detection
- [ ] Full ecosystem rule set (§1.3) in an externalized, dated, versioned DB
- [ ] Transitive + auto-enabled-extra awareness
- [ ] Reachability verdict + direction + input-trust + config-gating
- [ ] Realistic-impact labelling (DoS vs RCE), not just CVSS 9.2
- [ ] Per-component exact fix + rebuild/restart + backport-aware + compensating controls + "what it doesn't cover"
- [ ] Post-fix **verification** rescan
- [ ] Outputs: human report • JSON • **SARIF** • **VEX** • SBOM in/out (purl)
- [ ] Confidence + provenance + explicit blind-spot/scope reporting on every run
- [ ] CI exit codes + policy thresholds; offline/deterministic; signed rule data
- [ ] Read-only by default; attributable, rate-limited active mode

---

### Sources
- JFrog Security Research — Brotli2Shell (reachability two-question model, open-source scanner): research.jfrog.com/post/brotli2shell-beyond-node2shell-and-http2shell/
- Broccoli2Shell component tracker: broccoli2shell.com
- Wiz — Broccoli2Shell (exposure prioritization, mitigation): wiz.io/blog/cve-2026-111497-brotli-rce-node-js
- Phoenix Security — expansion & scanner pitfalls: phoenix.security/http2shell-expansion-cve-2026-111497-brotli-bundled-copies/
- Upwind, Tanium, Aikido, Strobes — affected ecosystems, fixed versions, mitigations
- CVE record (Google/CVEProject), Node.js Oct-2026 advisory, PYSEC-2026-4322/4323, GHSA-9v8h-qqgm-4m35
