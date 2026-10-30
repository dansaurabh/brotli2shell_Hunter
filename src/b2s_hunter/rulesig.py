"""Rule-data integrity: deterministic digest, manifest, optional Ed25519 signature.

The digest covers every public (UPPER_CASE, non-underscore) constant of ruledata
that is plain data (versions, markers, thresholds, components, ...). Manifest is
JSON: {"rules_version", "rules_date", "digest", "algo"}. A detached signature
(hex Ed25519 over the digest string) lives in ``<manifest>.sig``.

Signature checking needs the optional ``cryptography`` package. If it is missing
the result says "signature check unavailable" - it is never reported as signed.
"""

from __future__ import annotations

import hashlib
import json
import os

from . import ruledata as rd

ALGO = "sha256"
_PLAIN = (bytes, str, int, float, bool, tuple, list, dict, set, frozenset, type(None))


def _canon(v):
    if isinstance(v, bytes):
        return {"b": v.hex()}
    if isinstance(v, (set, frozenset)):
        return {"s": sorted((_canon(x) for x in v), key=lambda x: json.dumps(x, sort_keys=True))}
    if isinstance(v, (tuple, list)):
        return [_canon(x) for x in v]
    if isinstance(v, dict):
        items = [(json.dumps(_canon(k), sort_keys=True), _canon(x)) for k, x in v.items()]
        return {"d": sorted(items, key=lambda kv: kv[0])}
    return v


def public_constants():
    return {n: getattr(rd, n) for n in sorted(dir(rd))
            if n.isupper() and not n.startswith("_") and isinstance(getattr(rd, n), _PLAIN)}


def rules_digest():
    blob = json.dumps({n: _canon(v) for n, v in public_constants().items()},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _manifest():
    return {"rules_version": rd.RULES_VERSION, "rules_date": rd.RULES_DATE,
            "algo": ALGO, "digest": rules_digest()}


def write_manifest(path):
    m = _manifest()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return m


def _verify_signature(digest, sig_path, pubkey_hex):
    """Return (ok, reason). Never True when verification could not run."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return False, "signature check unavailable (cryptography not installed)"
    try:
        with open(sig_path, "r", encoding="utf-8") as fh:
            sig = bytes.fromhex(fh.read().strip())
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex.strip()))
        key.verify(sig, digest.encode("ascii"))
    except InvalidSignature:
        return False, "signature invalid"
    except Exception as exc:
        return False, "signature check failed: %s" % exc
    return True, "signature valid"


def verify_manifest(path, pinned_digest=None, pubkey=None, sig_path=None):
    """Check manifest against live ruledata -> (ok, reason).

    pinned_digest: expected digest the caller trusts (overrides the file's).
    pubkey: hex Ed25519 public key; when given a valid detached signature is
    required (default ``<path>.sig``). Without cryptography this fails closed.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            m = json.load(fh)
        if not isinstance(m, dict):
            raise ValueError("not an object")
    except (OSError, ValueError) as exc:
        return False, "manifest unreadable: %s" % exc
    if m.get("rules_version") != rd.RULES_VERSION:
        return False, "RULES_VERSION mismatch (%s != %s)" % (m.get("rules_version"), rd.RULES_VERSION)
    if m.get("rules_date") != rd.RULES_DATE:
        return False, "RULES_DATE mismatch (%s != %s)" % (m.get("rules_date"), rd.RULES_DATE)
    live = rules_digest()
    expected = pinned_digest or m.get("digest")
    if expected != live:
        return False, "digest mismatch: rule data modified"
    if pubkey is None:
        return True, "digest ok; unsigned (no signature check requested)"
    sp = sig_path or (str(path) + ".sig")
    if not os.path.exists(sp):
        return False, "signature file missing: %s" % sp
    ok, why = _verify_signature(live, sp, pubkey)
    return (True, "digest ok; " + why) if ok else (False, why)
