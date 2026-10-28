"""Rule data for CVE-2026-111497 - THE single file to edit when advisories change.

Everything a CVE/component update touches lives here: marker strings, fixed-version
thresholds, and the component rule set (CAPABILITY_SPEC.md section 1.3). Verdict
*logic* lives in versions.py and only reads the values below.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Rule-set metadata (bump RULES_VERSION / RULES_DATE on every data edit)
# --------------------------------------------------------------------------- #

RULES_VERSION = "2026.10.26-1"
RULES_DATE = "2026-10-26"          # advisory date these rules reflect
CVE_ID = "CVE-2026-111497"
CVE_ALIASES = ["HTTP2Shell", "Node2Shell", "Python2Shell", "Brotli2Shell"]
UPSTREAM_FIX_COMMIT = "0ed4268"
RULE_SOURCES = [
    "Google CVE record", "Node.js Oct-2026 advisory", "PYSEC-2026-4322/4323",
    "GHSA-9v8h-qqgm-4m35", "Bun/Brotli release notes", "broccoli2shell.com tracker",
]

# --------------------------------------------------------------------------- #
# Marker strings (version-independent detection core)
# --------------------------------------------------------------------------- #

MARK_DECODER = b"_ERROR_FORMAT_EXUBERANT_NIBBLE"   # any Brotli decoder
MARK_FIXED = b"_ERROR_FORMAT_BLOCK_SWITCH"         # patched (fix adds this code)
SYM_DECODE = b"BrotliDecoderDecompress"            # secondary decoder evidence

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

# --------------------------------------------------------------------------- #
# Fixed-version thresholds. A build is PATCHED at or above the threshold.
# --------------------------------------------------------------------------- #

BROTLI_MIN_AFFECTED = (1, 0, 3)       # flaw introduced in 1.0.3
BROTLI_LINES = {(1, 0): (1, 0, 10), (1, 1): (1, 1, 1), (1, 2): (1, 2, 1)}
PY_BROTLI_FIXED = (1, 2, 1)           # PyPI "Brotli"
PY_BROTLICFFI_FIXED = (1, 2, 1, 0)    # PyPI "brotlicffi"
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
NODE_EOL_NO_FIX = {23, 25}            # EOL lines, no fix will ship (<22 also EOL)
BUN_FIXED = (1, 4, 4)

FIX_HINT = ("Brotli C lib -> 1.0.10 / 1.1.1 / 1.2.1 | Node -> 22.23.4 / 24.22.1 / "
            "26.12.1 | Bun -> 1.4.4 | PyPI Brotli -> 1.2.1 | brotlicffi -> 1.2.1.0")

# --------------------------------------------------------------------------- #
# Source-reachability entry points (ranking signal, not proof)
# --------------------------------------------------------------------------- #

REACH_PATTERNS = {
    "js-fetch/DecompressionStream": r"\b(fetch\s*\(|DecompressionStream|createBrotliDecompress|zlib\.brotliDecompress)",
    "js-body-parser/express":       r"\b(body-parser|express\.json|compression\(\)|inflate\s*:\s*true)",
    "py-brotli-direct":             r"\b(import\s+brotli|import\s+brotlicffi|brotli\.decompress|brotlicffi\.decompress)",
    "py-http-clients":              r"\b(requests\.|httpx\.|aiohttp|urllib3)",
    "dotnet-brotli":                r"\b(BrotliStream|BrotliDecoder|System\.IO\.Compression\.Brotli)",
    "arrow/parquet":                r"\b(pyarrow|parquet\.read|BufferReader|ipc\.open)",
    "native-decode-call":           r"\bBrotliDecoderDecompress(Stream)?\b",
    "brotli-cli-decompress":        r"\bbrotli\b.*(\s-d\b|--decompress)",
}
REACH_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".cs", ".go", ".rb",
             ".php", ".java", ".sh", ".dockerfile", ".yaml", ".yml", ".toml",
             ".json", ".lock", ".txt"}

SBOM_NAME_PATTERN = r"(^|[^a-z])brotli"

# --------------------------------------------------------------------------- #
# Component rule set (spec section 1.3). Consumed by later steps (reachability,
# mitigation, VEX). status: fixed | no-release | affected | not-affected | verify
# fixed_in: list of fixed versions, or None. fix: human-readable remediation.
# --------------------------------------------------------------------------- #

COMPONENTS = [
    # ---- core / runtimes ----
    {"id": "brotli-c", "name": "Google Brotli C library", "ecosystem": "generic",
     "purl": "pkg:github/google/brotli", "status": "fixed",
     "fixed_in": ["1.0.10", "1.1.1", "1.2.1"], "fix": "Upgrade to 1.0.10 / 1.1.1 / 1.2.1 or cherry-pick 0ed4268"},
    {"id": "nodejs", "name": "Node.js", "ecosystem": "runtime", "purl": "pkg:generic/node",
     "status": "fixed", "fixed_in": ["22.23.4", "24.22.1", "26.12.1"],
     "fix": "Upgrade to 22.23.4 / 24.22.1 / 26.12.1; 20, 23, 25 are EOL with no fix"},
    {"id": "bun", "name": "Bun", "ecosystem": "runtime", "purl": "pkg:generic/bun",
     "status": "fixed", "fixed_in": ["1.4.4"], "fix": "Upgrade to 1.4.4"},
    {"id": "deno", "name": "Deno", "ecosystem": "runtime", "purl": "pkg:generic/deno",
     "status": "verify", "fixed_in": None, "fix": "Verify bundled Brotli (tracker gap)"},
    {"id": "dotnet", "name": ".NET runtime", "ecosystem": "runtime", "purl": "pkg:nuget/Microsoft.NETCore.App.Runtime",
     "status": "fixed", "fixed_in": ["8.0.33", "9.0.22", "10.0.14", "11.0.0-rc.3"],
     "fix": "Upgrade runtime; GitHub source builds remain affected"},
    {"id": "curl", "name": "curl / libcurl", "ecosystem": "native", "purl": "pkg:generic/curl",
     "status": "verify", "fixed_in": None, "fix": "Check the linked libbrotlidec"},
    # ---- python ----
    {"id": "py-brotli", "name": "Brotli (PyPI)", "ecosystem": "pypi", "purl": "pkg:pypi/brotli",
     "status": "fixed", "fixed_in": ["1.2.1"], "fix": "pip install 'Brotli>=1.2.1'"},
    {"id": "py-brotlicffi", "name": "brotlicffi (PyPI)", "ecosystem": "pypi", "purl": "pkg:pypi/brotlicffi",
     "status": "fixed", "fixed_in": ["1.2.1.0"], "fix": "pip install 'brotlicffi>=1.2.1.0'"},
    # ---- other bindings ----
    {"id": "go-andybalholm", "name": "andybalholm/brotli (Go)", "ecosystem": "go",
     "purl": "pkg:golang/github.com/andybalholm/brotli", "status": "fixed", "fixed_in": None,
     "fix": "Update to build fixed 23 Oct 2026 (crash-only)"},
    {"id": "ruby-brotli", "name": "brotli (Ruby gem)", "ecosystem": "gem", "purl": "pkg:gem/brotli",
     "status": "fixed", "fixed_in": ["0.9.1"], "fix": "Upgrade to 0.9.1"},
    {"id": "php-kjdev", "name": "kjdev/brotli (PHP ext)", "ecosystem": "php", "purl": "pkg:github/kjdev/php-ext-brotli",
     "status": "fixed", "fixed_in": ["0.21.1"], "fix": "Upgrade to 0.21.1"},
    {"id": "java-brotli4j", "name": "Brotli4j (Java)", "ecosystem": "maven",
     "purl": "pkg:maven/com.aayushatharva.brotli4j/brotli4j",
     "status": "fixed", "fixed_in": None, "fix": "Upgrade to the fixed release"},
    {"id": "rust-brotli-decompressor", "name": "brotli-decompressor (Rust)", "ecosystem": "cargo",
     "purl": "pkg:cargo/brotli-decompressor", "status": "not-affected", "fixed_in": None,
     "fix": "None - returns an error instead of corrupting memory"},
    # ---- data / media / DB ----
    {"id": "clickhouse", "name": "ClickHouse", "ecosystem": "native", "purl": "pkg:github/ClickHouse/ClickHouse",
     "status": "no-release", "fixed_in": None, "fix": "master patched; no release - isolate or cherry-pick 0ed4268"},
    {"id": "arrow", "name": "Apache Arrow / pyarrow", "ecosystem": "native", "purl": "pkg:pypi/pyarrow",
     "status": "affected", "fixed_in": None, "fix": "PR #55167 not merged - isolate untrusted Parquet"},
    {"id": "duckdb", "name": "DuckDB", "ecosystem": "native", "purl": "pkg:pypi/duckdb",
     "status": "affected", "fixed_in": None, "fix": "PR #27791 pending - isolate untrusted Parquet"},
    {"id": "ydb", "name": "YDB", "ecosystem": "native", "purl": "pkg:github/ydb-platform/ydb",
     "status": "no-release", "fixed_in": None, "fix": "main patched 23 Oct; no release"},
    {"id": "libjxl", "name": "libjxl (JPEG XL)", "ecosystem": "native", "purl": "pkg:github/libjxl/libjxl",
     "status": "no-release", "fixed_in": None, "fix": "PR #5062 - no release; FFmpeg affected via libjxl"},
    {"id": "graaljs", "name": "GraalJS", "ecosystem": "runtime", "purl": "pkg:maven/org.graalvm.js/js",
     "status": "no-release", "fixed_in": None, "fix": "Merged 22 Oct; no release"},
    # ---- fonts / docs / firmware / archives ----
    {"id": "woff2", "name": "woff2", "ecosystem": "native", "purl": "pkg:github/google/woff2",
     "status": "affected", "fixed_in": None, "fix": "PR #208; affected on Makefile build"},
    {"id": "mupdf", "name": "MuPDF", "ecosystem": "native", "purl": "pkg:generic/mupdf",
     "status": "fixed", "fixed_in": ["1.28"], "fix": "Upgrade to 1.28.x; 1.27.x affected"},
    {"id": "uefitool", "name": "UEFITool", "ecosystem": "native", "purl": "pkg:github/LongSoft/UEFITool",
     "status": "fixed", "fixed_in": ["A76"], "fix": "Upgrade to A76"},
    {"id": "edk2", "name": "EDK II", "ecosystem": "firmware", "purl": "pkg:github/tianocore/edk2",
     "status": "affected", "fixed_in": None, "fix": "Tracked in #13378"},
    {"id": "7zip-zstd", "name": "7-Zip-zstd / p7zip", "ecosystem": "native", "purl": "pkg:github/mcmilk/7-Zip-zstd",
     "status": "affected", "fixed_in": None, "fix": "No fix yet"},
    {"id": "nanazip", "name": "NanaZip", "ecosystem": "native", "purl": "pkg:github/M2Team/NanaZip",
     "status": "no-release", "fixed_in": None, "fix": "No release yet"},
    {"id": "v8-jsi", "name": "v8-jsi", "ecosystem": "native", "purl": "pkg:generic/v8-jsi",
     "status": "affected", "fixed_in": None, "fix": "Bundles Brotli 1.2.0"},
    # ---- infra (verify separately) ----
    {"id": "envoy", "name": "Envoy", "ecosystem": "infra", "purl": "pkg:github/envoyproxy/envoy",
     "status": "verify", "fixed_in": None, "fix": "See ISTIO/Envoy advisory; config-gated"},
    {"id": "istio", "name": "Istio", "ecosystem": "infra", "purl": "pkg:github/istio/istio",
     "status": "fixed", "fixed_in": ["1.31.2", "1.30.6", "1.29.9"],
     "fix": "Upgrade; only exposed if Brotli decompression is enabled"},
    {"id": "cdxgen", "name": "cdxgen", "ecosystem": "npm", "purl": "pkg:npm/@cyclonedx/cdxgen",
     "status": "verify", "fixed_in": None, "fix": "Verify separately (tracker gap)"},

    # ---- EXTEND HERE: add new components (.NET variants, DuckDB/Arrow releases, ...) ----
]

# Already fixed before the advisory list.
ALREADY_FIXED = ["Chromium", "Firefox", "ngx_brotli", "SumatraPDF", "Ghostscript",
                 "CatBoost", "YTsaurus"]
