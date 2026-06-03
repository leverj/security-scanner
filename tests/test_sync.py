from unittest.mock import MagicMock

from security_scan.fingerprint import inject_marker, resolve_fingerprint
from security_scan.github import ProjectContext, ProjectField
from security_scan.models import Finding
from security_scan.sync import default_issue, sync


def _project():
    return ProjectContext(
        id="PVT_x",
        owner="leverj",
        number=5,
        severity=ProjectField(id="SEV", options={
            "critical": "o-c", "high": "o-h", "medium": "o-m", "low": "o-l", "info": "o-i",
        }),
        category=ProjectField(id="CAT", options={
            "dependency": "o-d", "secret": "o-s", "sast": "o-a", "iac": "o-ia", "license": "o-li",
        }),
    )


def _f(rule_id="R1", file_path="src/a.js", severity="high", snippet="exec(x)", category="sast"):
    return Finding(
        scanner="semgrep",
        category=category,
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line=10,
        title=f"{rule_id} on {file_path}",
        message="msg",
        extra={"snippet": snippet},
    )


def _existing_item_for(f, state="OPEN"):
    """Build a fake project-item dict whose body contains f's marker."""
    fp = resolve_fingerprint(f)
    body = inject_marker("prose", fp, f)
    return {"item_id": "old-item", "content_id": "I_old", "number": 1, "state": state,
            "title": "x", "body": body}


def _gh(existing=None, dry_run=True):
    gh = MagicMock()
    gh.dry_run = dry_run
    gh.list_project_items.return_value = list(existing or [])
    counter = {"n": 100}

    def create(title, body, labels=None):
        counter["n"] += 1
        return {"number": counter["n"], "title": title, "body": body,
                "id": counter["n"] + 1000, "node_id": f"I_{counter['n']}", "html_url": "x"}

    gh.create_issue.side_effect = create
    gh.add_to_project.side_effect = lambda pid, nid: f"ITEM_{nid}"
    gh.set_project_field.return_value = None
    return gh


def test_creates_when_no_existing():
    findings = [_f("R1"), _f("R2", file_path="src/b.js")]
    gh = _gh(existing=[])
    result = sync(findings, gh, _project())
    assert len(result.created) == 2
    assert result.skipped_dup == 0
    assert gh.create_issue.call_count == 2
    assert gh.add_to_project.call_count == 2
    # Severity + Category set on each new item.
    assert gh.set_project_field.call_count == 4


def test_skips_when_open_item_with_same_fp_exists():
    f = _f("R1")
    gh = _gh(existing=[_existing_item_for(f, state="OPEN")])
    result = sync([f], gh, _project())
    assert len(result.created) == 0
    assert result.skipped_dup == 1
    gh.create_issue.assert_not_called()
    gh.add_to_project.assert_not_called()


def test_skips_when_closed_item_with_same_fp_exists():
    """Spec invariant: closed item (fixed OR won't-fix) permanently suppresses re-filing."""
    f = _f("R1")
    gh = _gh(existing=[_existing_item_for(f, state="CLOSED")])
    result = sync([f], gh, _project())
    assert len(result.created) == 0
    assert result.skipped_dup == 1


def test_intra_run_dedup_prevents_filing_same_fp_twice():
    f = _f("R1")
    f2 = _f("R1")  # identical fp
    gh = _gh(existing=[])
    result = sync([f, f2], gh, _project())
    assert len(result.created) == 1
    assert result.skipped_dup == 1


def test_severity_floor_skips():
    findings = [_f("R1", severity="info"), _f("R2", severity="low"), _f("R3", severity="high")]
    gh = _gh(existing=[])
    result = sync(findings, gh, _project(), severity_floor="medium")
    assert len(result.created) == 1
    assert result.skipped_floor == 2


def test_marker_is_always_injected_on_created_body():
    f = _f("R1")
    gh = _gh(existing=[])
    sync([f], gh, _project())
    body = gh.create_issue.call_args.args[1] if gh.create_issue.call_args.args else gh.create_issue.call_args.kwargs["body"]
    assert "<!-- security-scan:" in body
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


def test_labels_include_category_and_severity():
    f = _f("R1", severity="high")
    gh = _gh(existing=[])
    sync([f], gh, _project())
    labels = gh.create_issue.call_args.kwargs.get("labels") or gh.create_issue.call_args.args[2]
    assert "security" in labels
    assert "security-scan:sast" in labels
    assert "security-scan:high" in labels


def test_labels_for_supply_chain_category():
    f = Finding(
        scanner="trivy", category="iac", rule_id="AVD-DS-0002", severity="medium",
        file_path="Dockerfile", line=1, title="root user", message="m",
    )
    gh = _gh(existing=[])
    sync([f], gh, _project())
    labels = gh.create_issue.call_args.kwargs.get("labels") or gh.create_issue.call_args.args[2]
    assert "security-scan:iac" in labels
    assert "security-scan:medium" in labels


def test_severity_and_category_fields_set_with_correct_options():
    f = _f("R1", severity="critical", category="sast")
    gh = _gh(existing=[])
    proj = _project()
    sync([f], gh, proj)
    # Two set_project_field calls: one for severity, one for category.
    calls = gh.set_project_field.call_args_list
    assert len(calls) == 2
    # First call: severity
    args = calls[0].args
    assert args[0] == proj.id
    assert args[2] == proj.severity
    assert args[3] == "critical"
    # Second call: category
    args = calls[1].args
    assert args[2] == proj.category
    assert args[3] == "sast"
