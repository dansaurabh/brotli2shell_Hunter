import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from b2s_hunter import __version__
from b2s_hunter.model import CLEAN, POTENTIAL, REVIEW
from b2s_hunter.probe import (BENIGN_BROTLI_BODY, MAX_TARGETS,
                              ProbeNotAuthorized, probe_targets)


class _Resp:
    def __init__(self, status, headers=None):
        self.status = status
        self.headers = headers or {}

    def close(self):
        pass


def make_opener(post_status=200, log=None, get_headers=None):
    def opener(req, timeout):
        if log is not None:
            log.append(req)
        if req.get_method() == "POST":
            return _Resp(post_status)
        return _Resp(200, get_headers or {})
    return opener


def test_refuses_without_authorization():
    with pytest.raises(ProbeNotAuthorized):
        probe_targets(["http://x.test/"], authorized=False, opener=make_opener())
    with pytest.raises(ProbeNotAuthorized):
        probe_targets(["http://x.test/"], authorized=None, opener=make_opener())


def test_accepted_is_potential():
    f = probe_targets(["http://x.test/"], True, rate_per_sec=0,
                      opener=make_opener(200))[0]
    assert f.layer == "active-probe" and f.verdict == POTENTIAL
    assert f.reach == "reachable-untrusted" and f.direction == "inbound"
    assert f.internet_facing and f.confidence == "medium"
    assert "200" in f.evidence


def test_rejected_is_clean():
    for code in (400, 415):
        f = probe_targets(["http://x.test/"], True, rate_per_sec=0,
                          opener=make_opener(code))[0]
        assert f.verdict == CLEAN


def test_other_status_is_review():
    f = probe_targets(["http://x.test/"], True, rate_per_sec=0,
                      opener=make_opener(500))[0]
    assert f.verdict == REVIEW


def test_user_agent_default_and_custom():
    log = []
    probe_targets(["http://x.test/"], True, rate_per_sec=0, opener=make_opener(log=log))
    assert log and all(
        r.get_header("User-agent") == f"b2s-hunter/{__version__} (+active-probe; authorized-scan)"
        for r in log)
    log.clear()
    probe_targets(["http://x.test/"], True, rate_per_sec=0, user_agent="me/1",
                  opener=make_opener(log=log))
    assert all(r.get_header("User-agent") == "me/1" for r in log)


def test_payload_is_small_valid_benign_and_no_auth():
    log = []
    probe_targets(["http://x.test/"], True, rate_per_sec=0, opener=make_opener(log=log))
    post = [r for r in log if r.get_method() == "POST"]
    assert len(post) == 1 and len(log) == 2
    assert post[0].data == BENIGN_BROTLI_BODY and len(post[0].data) < 32
    assert post[0].get_header("Content-encoding") == "br"
    for r in log:
        assert not r.has_header("Authorization") and not r.has_header("Cookie")


def test_rate_limit_uses_injected_sleep_and_clock():
    now = [0.0]
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        now[0] += s

    probe_targets(["http://a.test/", "http://b.test/"], True, rate_per_sec=2.0,
                  opener=make_opener(), sleep=sleep, clock=lambda: now[0])
    # 4 requests -> 3 waits of 0.5s
    assert sleeps == [0.5, 0.5, 0.5]


def test_target_cap_and_non_http_skipped():
    with pytest.raises(ValueError):
        probe_targets(["http://x.test/"] * (MAX_TARGETS + 1), True,
                      opener=make_opener())
    f = probe_targets(["ftp://x.test/"], True, rate_per_sec=0,
                      opener=make_opener())[0]
    assert f.verdict == REVIEW and "not an http" in f.note


def test_network_error_is_low_confidence():
    def boom(req, timeout):
        raise OSError("refused")
    f = probe_targets(["http://x.test/"], True, rate_per_sec=0, opener=boom)[0]
    assert f.verdict == REVIEW and f.confidence == "low"


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_local_server_accepts_and_redirect_not_followed():
    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append(("GET", self.path))
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/evil")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            seen.append(("POST", self.headers.get("Content-Encoding"), body,
                         self.headers.get("User-Agent")))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = _serve(H)
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        ok = probe_targets([base + "/"], True, rate_per_sec=0)[0]
        assert ok.verdict == POTENTIAL
        post = [s for s in seen if s[0] == "POST"][0]
        assert post[1] == "br" and post[2] == BENIGN_BROTLI_BODY
        assert "active-probe" in post[3]
        probe_targets([base + "/redir"], True, rate_per_sec=0)
    finally:
        srv.shutdown()
