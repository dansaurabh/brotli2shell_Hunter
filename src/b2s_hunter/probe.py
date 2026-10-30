"""Opt-in active probe: does an HTTP endpoint accept Brotli request bodies?

FOR SYSTEMS YOU ARE AUTHORIZED TO TEST ONLY. Disabled unless the caller passes
authorized=True. Per target it sends ONE POST whose body is a tiny, valid,
harmless Brotli stream (an uncompressed meta-block holding 12 ASCII bytes) and
ONE GET to read Accept-Encoding / Content-Encoding support. It never sends
malformed, oversized or exploit-shaped data: it only measures whether the
Brotli request-decode path is reachable. Requests are rate-limited, carry an
attributable User-Agent, send no credentials and never follow redirects.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import __version__
from .model import CLEAN, POTENTIAL, REVIEW, Finding

MAX_TARGETS = 50

# Valid Brotli stream: WBITS=16, one uncompressed meta-block ("b2s-probe-ok"),
# then the final empty meta-block. Verified against a reference decoder.
BENIGN_BROTLI_BODY = bytes.fromhex("b000106232732d70726f62652d6f6b03")


class ProbeNotAuthorized(Exception):
    """Raised when active probing is requested without explicit authorization."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def default_user_agent() -> str:
    return f"b2s-hunter/{__version__} (+active-probe; authorized-scan)"


def _default_opener(req, timeout):
    return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)


def _send(opener, req, timeout):
    """Return (status, headers-dict-lowercase, error-string)."""
    try:
        resp = opener(req, timeout)
        try:
            status = getattr(resp, "status", None) or resp.getcode()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()
        return status, hdrs, ""
    except urllib.error.HTTPError as e:   # 3xx (unfollowed), 4xx, 5xx
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, hdrs, ""
    except Exception as e:                # noqa: BLE001 - network failures
        return None, {}, f"{type(e).__name__}: {e}"


def probe_targets(targets, authorized, rate_per_sec=1.0, timeout=5,
                  user_agent=None, opener=None, sleep=time.sleep,
                  clock=time.monotonic) -> list:
    if authorized is not True:
        raise ProbeNotAuthorized(
            "active probing requires explicit authorization (authorized=True)")
    targets = list(targets)
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"too many targets ({len(targets)} > {MAX_TARGETS})")
    ua = user_agent or default_user_agent()
    opener = opener or _default_opener
    interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
    last = [None]

    def throttle():
        if last[0] is not None and interval:
            wait = interval - (clock() - last[0])
            if wait > 0:
                sleep(wait)
        last[0] = clock()

    findings = []
    for url in targets:
        if urlparse(url).scheme not in ("http", "https") or not urlparse(url).netloc:
            findings.append(Finding(
                layer="active-probe", component="http", location=url,
                verdict=REVIEW, confidence="low",
                note="skipped: not an http(s) URL"))
            continue
        throttle()
        get = urllib.request.Request(url, method="GET", headers={
            "User-Agent": ua, "Accept-Encoding": "br, gzip"})
        g_status, g_hdrs, g_err = _send(opener, get, timeout)
        throttle()
        post = urllib.request.Request(
            url, data=BENIGN_BROTLI_BODY, method="POST", headers={
                "User-Agent": ua, "Content-Encoding": "br",
                "Content-Type": "text/plain"})
        p_status, _p_hdrs, p_err = _send(opener, post, timeout)
        findings.append(_to_finding(url, g_status, g_hdrs, g_err, p_status, p_err))
    return findings


def _to_finding(url, g_status, g_hdrs, g_err, p_status, p_err):
    resp_br = "br" in g_hdrs.get("content-encoding", "").lower().split(",") or \
        g_hdrs.get("content-encoding", "").strip().lower() == "br"
    evidence = (f"POST Content-Encoding: br -> {p_status if p_status else p_err}; "
                f"GET -> {g_status if g_status else g_err}; "
                f"response Content-Encoding={g_hdrs.get('content-encoding', '-')!r}")
    f = Finding(layer="active-probe", component="http", location=url,
                verdict=REVIEW, confidence="medium", evidence=evidence,
                internet_facing=True, direction="inbound")
    if p_status is None:
        f.confidence = "low"
        f.note = "unreachable; no conclusion"
    elif 200 <= p_status < 300:
        f.verdict = POTENTIAL
        f.reach = "reachable-untrusted"
        f.note = ("server accepted a Brotli request body; decode path appears "
                  "reachable (acceptance != vulnerability)")
    elif p_status in (400, 415, 501):
        f.verdict = CLEAN
        f.note = "server rejected Brotli request body; decode path likely not reachable"
    else:
        f.note = "inconclusive response to Brotli request body"
    if resp_br:
        f.note += "; server also emits Brotli responses"
    return f
