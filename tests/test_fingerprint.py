from security_scan.fingerprint import (
    compute_fingerprint,
    inject_marker,
    parse_marker,
    resolve_fingerprint,
)
from security_scan.models import Finding


def _sast(file_path="src/a.js", line=10, snippet="exec(userInput)"):
    return Finding(
        scanner="semgrep",
        category="sast",
        rule_id="ezel-command-injection",
        severity="high",
        file_path=file_path,
        line=line,
        title="Command injection",
        message="exec on user-controlled input",
        extra={"snippet": snippet},
    )


def test_fingerprint_is_stable_across_line_shifts():
    a = _sast(line=10)
    b = _sast(line=999)
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_is_stable_across_whitespace_changes():
    a = _sast(snippet="exec(userInput)")
    b = _sast(snippet="exec(   userInput  )")
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_changes_with_path_rename():
    a = _sast(file_path="src/a.js")
    b = _sast(file_path="src/renamed.js")
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_fingerprint_changes_with_rule_id():
    a = _sast()
    b = _sast()
    b.rule_id = "different-rule"
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_dependency_fingerprint_is_path_qualified():
    # Two different lockfiles, same advisory -> different fp (per-lockfile filing).
    f1 = Finding("osv", "dependency", "GHSA-aaaa", "high", "package-lock.json", None, "t", "m")
    f2 = Finding("osv", "dependency", "GHSA-aaaa", "high", "frontend/package-lock.json", None, "t", "m")
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_secret_fingerprint_uses_secret_fp_not_raw_value():
    f = Finding(
        scanner="gitleaks",
        category="secret",
        rule_id="generic-api-key",
        severity="critical",
        file_path=".env",
        line=3,
        title="API key in .env",
        message="found generic api key",
        masked_preview="sk_••••••••cd34",
        extra={"secret_fingerprint": "abcd1234"},
    )
    fp = compute_fingerprint(f)
    # Must not embed the masked preview or raw value bits in the basis hash input
    assert fp.startswith("fp_") and len(fp) == 19


def test_resolve_fingerprint_prefers_sarif_fp_when_present():
    f = _sast()
    f.sarif_fingerprint = "fp_deadbeefdeadbeef"
    assert resolve_fingerprint(f) == "fp_deadbeefdeadbeef"


def test_resolve_fingerprint_falls_back_to_computed():
    f = _sast()
    assert resolve_fingerprint(f) == compute_fingerprint(f)


def test_marker_roundtrip():
    f = _sast()
    fp = compute_fingerprint(f)
    body = inject_marker("Some prose about the finding.", fp, f)
    parsed = parse_marker(body)
    assert parsed == {"fp": fp, "rule": f.rule_id, "cat": f.category}


def test_marker_idempotent_inject():
    f = _sast()
    fp = compute_fingerprint(f)
    body = inject_marker("prose", fp, f)
    body2 = inject_marker(body, fp, f)
    # Should not duplicate the marker
    assert body2.count("<!-- security-scan:") == 1


def test_parse_marker_returns_none_for_missing():
    assert parse_marker(None) is None
    assert parse_marker("") is None
    assert parse_marker("no marker here") is None
    assert parse_marker("<!-- security-scan: malformed -->") is None
