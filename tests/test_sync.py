from unittest.mock import MagicMock

from secscan.fingerprint import inject_marker, resolve_fingerprint
from secscan.models import Finding
from secscan.sync import default_issue, sync


def _f(rule_id="R1", file_path="src/a.js", severity="high", snippet="exec(x)"):
    return Finding(
        scanner="semgrep",
        category="sast",
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line=10,
        title=f"{rule_id} on {file_path}",
        message="msg",
        extra={"snippet": snippet},
    )


def _issue_for(f, state="open"):
    """Build a fake existing GitHub issue dict whose body contains f's marker."""
    fp = resolve_fingerprint(f)
    body = inject_marker("prose", fp, f)
    return {"number": 1, "state": state, "title": "x", "body": body, "id": 1001}


def _gh(existing=None, dry_run=True):
    gh = MagicMock()
    gh.dry_run = dry_run
    gh.list_subissues.return_value = list(existing or [])
    counter = {"n": 100}

    def create(title, body, labels=None):
        counter["n"] += 1
        return {"number": counter["n"], "title": title, "body": body, "id": counter["n"] + 1000, "html_url": "x"}

    gh.create_issue.side_effect = create
    gh.link_subissue.return_value = None
    return gh


def test_creates_when_no_existing():
    findings = [_f("R1"), _f("R2", file_path="src/b.js")]
    gh = _gh(existing=[])
    result = sync(findings, gh, parent_issue=42)
    assert len(result.created) == 2
    assert result.skipped_dup == 0
    assert gh.create_issue.call_count == 2
    assert gh.link_subissue.call_count == 2


def test_skips_when_open_issue_with_same_fp_exists():
    f = _f("R1")
    gh = _gh(existing=[_issue_for(f, state="open")])
    result = sync([f], gh, parent_issue=42)
    assert len(result.created) == 0
    assert result.skipped_dup == 1
    gh.create_issue.assert_not_called()


def test_skips_when_closed_issue_with_same_fp_exists():
    """Spec invariant: closed issue (fixed OR won't-fix) permanently suppresses re-filing."""
    f = _f("R1")
    gh = _gh(existing=[_issue_for(f, state="closed")])
    result = sync([f], gh, parent_issue=42)
    assert len(result.created) == 0
    assert result.skipped_dup == 1


def test_intra_run_dedup_prevents_filing_same_fp_twice():
    f = _f("R1")
    f2 = _f("R1")  # identical fp
    gh = _gh(existing=[])
    result = sync([f, f2], gh, parent_issue=42)
    assert len(result.created) == 1
    assert result.skipped_dup == 1


def test_severity_floor_skips():
    findings = [_f("R1", severity="info"), _f("R2", severity="low"), _f("R3", severity="high")]
    gh = _gh(existing=[])
    result = sync(findings, gh, parent_issue=42, severity_floor="medium")
    assert len(result.created) == 1
    assert result.skipped_floor == 2


def test_marker_is_always_injected_on_created_body():
    f = _f("R1")
    gh = _gh(existing=[])
    sync([f], gh, parent_issue=42)
    body = gh.create_issue.call_args.args[1] if gh.create_issue.call_args.args else gh.create_issue.call_args.kwargs["body"]
    assert "<!-- secscan:" in body
    assert resolve_fingerprint(f) in body


def test_default_issue_omits_raw_secret():
    f = Finding(
        scanner="gitleaks", category="secret", rule_id="generic-api-key", severity="critical",
        file_path=".env", line=3, title="api key", message="found", masked_preview="sk_••••cd34",
        extra={"secret_fingerprint": "abcd"},
    )
    title, body = default_issue(f)
    assert "sk_••••cd34" in body
    assert "sk_realfullvalue" not in body


def test_triage_fuzzy_dup_skips_creation():
    f = _f("R1")
    gh = _gh(existing=[{"number": 5, "state": "open", "title": "old", "body": "no marker", "id": 999}])
    triage = MagicMock()
    triage.enabled = True
    triage.is_duplicate_of_existing.return_value = True
    triage.write_issue.return_value = ("T", "B")
    result = sync([f], gh, parent_issue=42, triage=triage)
    assert len(result.created) == 0
    assert result.skipped_fuzzy_dup == 1
    gh.create_issue.assert_not_called()


def test_triage_failure_falls_back_to_deterministic_path():
    f = _f("R1")
    gh = _gh(existing=[])
    triage = MagicMock()
    triage.enabled = True
    triage.is_duplicate_of_existing.side_effect = RuntimeError("ollama down")
    triage.write_issue.side_effect = RuntimeError("also down")
    result = sync([f], gh, parent_issue=42, triage=triage)
    assert len(result.created) == 1  # deterministic fallback worked


def test_uses_triage_prose_when_available():
    f = _f("R1")
    gh = _gh(existing=[])
    triage = MagicMock()
    triage.enabled = True
    triage.is_duplicate_of_existing.return_value = False
    triage.write_issue.return_value = ("LLM Title", "LLM Body")
    sync([f], gh, parent_issue=42, triage=triage)
    args = gh.create_issue.call_args
    title = args.args[0] if args.args else args.kwargs["title"]
    body = args.args[1] if len(args.args) >= 2 else args.kwargs["body"]
    assert title == "LLM Title"
    assert "LLM Body" in body
    assert "<!-- secscan:" in body  # marker still injected by code
