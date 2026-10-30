import pytest

from b2s_hunter.model import Finding
from b2s_hunter.policy import evaluate_policy


def F(verdict, reach="unknown"):
    return Finding("packages", "brotli", "/x", verdict, "high", reach=reach)


def test_empty_passes():
    r = evaluate_policy([])
    assert (r.status, r.exit_code, r.reasons) == ("pass", 0, [])


def test_default_fails_on_reachable_untrusted():
    r = evaluate_policy([F("VULNERABLE", "reachable-untrusted")])
    assert (r.status, r.exit_code) == ("fail", 1)
    assert r.reasons


def test_default_unknown_and_config_gated_fail():
    for reach in ("unknown", "config-gated"):
        assert evaluate_policy([F("VULNERABLE", reach)]).exit_code == 1


def test_trusted_only_vulnerable_only_warns_by_default():
    r = evaluate_policy([F("VULNERABLE", "trusted-only")])
    assert (r.status, r.exit_code) == ("warn", 2)


def test_any_vulnerable_fails_trusted_only():
    assert evaluate_policy([F("VULNERABLE", "trusted-only")],
                           fail_on="any-vulnerable").exit_code == 1


def test_never_does_not_fail_and_warn_never_passes():
    fs = [F("VULNERABLE", "reachable-untrusted")]
    assert evaluate_policy(fs, fail_on="never").status == "warn"
    assert evaluate_policy(fs, fail_on="never", warn_on="never").exit_code == 0


def test_review_warns_patched_passes():
    assert evaluate_policy([F("NEEDS_REVIEW")]).exit_code == 2
    assert evaluate_policy([F("POTENTIALLY_VULNERABLE")]).status == "warn"
    assert evaluate_policy([F("PATCHED"), F("NOT_AFFECTED")]).exit_code == 0


def test_invalid_policy_raises():
    with pytest.raises(ValueError):
        evaluate_policy([], fail_on="bogus")
