"""Tests for the GitHub adapter. All HTTP and subprocess calls are mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from security_scan.github import GitHub, GitHubError, ProjectField

TOKEN = "ghp_supersecrettoken_abcdef123456"


def _resp(status=200, json_body=None, headers=None, text=""):
    r = MagicMock(spec=requests.Response)
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    r.json.return_value = json_body if json_body is not None else {}
    return r


def _gh(dry_run=False):
    return GitHub(TOKEN, "leverj", "ezel", dry_run=dry_run)


# ---- clone ----------------------------------------------------------------


def test_clone_shallow_uses_depth_1(tmp_path):
    gh = _gh()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("security_scan.github.subprocess.run", return_value=completed) as m:
        gh.clone("dev", tmp_path / "repo", shallow=True)
    args = m.call_args.args[0]
    assert args[0] == "git"
    assert "clone" in args
    assert "--depth=1" in args
    assert "--single-branch" in args
    assert "--branch" in args
    assert "dev" in args


def test_clone_full_omits_depth(tmp_path):
    gh = _gh()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("security_scan.github.subprocess.run", return_value=completed) as m:
        gh.clone("dev", tmp_path / "repo", shallow=False)
    args = m.call_args.args[0]
    assert "--depth=1" not in args


def test_clone_url_has_no_credentials(tmp_path):
    """The clone URL must not embed the token — git would persist it into .git/config."""
    gh = _gh()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("security_scan.github.subprocess.run", return_value=completed) as m:
        gh.clone("dev", tmp_path / "repo")
    args = m.call_args.args[0]
    url = next(a for a in args if a.startswith("https://"))
    assert url == "https://github.com/leverj/ezel.git"
    assert TOKEN not in url
    assert "x-access-token" not in url


def test_clone_passes_token_via_one_shot_config(tmp_path):
    import base64

    gh = _gh()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("security_scan.github.subprocess.run", return_value=completed) as m:
        gh.clone("dev", tmp_path / "repo")
    args = m.call_args.args[0]
    assert "-c" in args
    c_idx = args.index("-c")
    extraheader = args[c_idx + 1]
    assert "extraheader" in extraheader
    assert "basic " in extraheader.lower()
    encoded = extraheader.split("basic ", 1)[-1]
    decoded = base64.b64decode(encoded).decode()
    assert decoded == f"x-access-token:{TOKEN}"
    for a in args:
        assert TOKEN not in a, f"raw token leaked into argv: {a!r}"


def test_clone_scrubs_token_from_error(tmp_path):
    gh = _gh()
    leaky = f"fatal: could not read from https://x-access-token:{TOKEN}@github.com/leverj/ezel.git"
    completed = MagicMock(returncode=128, stdout="", stderr=leaky)
    with patch("security_scan.github.subprocess.run", return_value=completed):
        with pytest.raises(GitHubError) as ei:
            gh.clone("dev", tmp_path / "repo")
    assert TOKEN not in str(ei.value)


# ---- create_issue ---------------------------------------------------------


def test_create_issue_posts_correct_payload():
    gh = _gh()
    created = {"id": 9001, "node_id": "I_xxx", "number": 42, "title": "t", "body": "b", "html_url": "u", "state": "open"}
    resp = _resp(201, json_body=created, headers={})
    with patch.object(requests.Session, "request", return_value=resp) as m:
        out = gh.create_issue("t", "b", labels=["security", "security_scan"])
    assert out == created
    call = m.call_args
    method = call.args[0] if call.args else call.kwargs["method"]
    url = call.args[1] if len(call.args) > 1 else call.kwargs["url"]
    assert method == "POST"
    assert url == "https://api.github.com/repos/leverj/ezel/issues"
    assert call.kwargs["json"] == {"title": "t", "body": "b", "labels": ["security", "security_scan"]}
    assert gh.session.headers["Authorization"] == f"Bearer {TOKEN}"
    assert gh.session.headers["Accept"] == "application/vnd.github+json"
    assert gh.session.headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_create_issue_defaults_security_label():
    gh = _gh()
    created = {"id": 1, "node_id": "I_x", "number": 1, "title": "t", "body": "b", "html_url": "u", "state": "open"}
    resp = _resp(201, json_body=created)
    with patch.object(requests.Session, "request", return_value=resp) as m:
        gh.create_issue("t", "b")
    assert m.call_args.kwargs["json"]["labels"] == ["security"]


def test_create_issue_dry_run_includes_node_id(capsys):
    """Dry-run must return a node_id so the downstream project flow doesn't KeyError."""
    gh = _gh(dry_run=True)
    with patch.object(requests.Session, "request") as m:
        out = gh.create_issue("hello", "body")
    assert m.call_count == 0
    assert out["number"] == 0
    assert out["title"] == "hello"
    assert out["html_url"] == "<dry-run>"
    assert "node_id" in out and out["node_id"]
    err = capsys.readouterr().err
    assert "DRY-RUN" in err and "hello" in err


# ---- resolve_project (GraphQL) -------------------------------------------


def _graphql_resp(data: dict | None = None, errors: list | None = None):
    body = {"data": data or {}}
    if errors is not None:
        body["errors"] = errors
    return _resp(200, json_body=body)


def test_resolve_project_org_match_returns_context():
    gh = _gh()
    proj = {
        "id": "PVT_xxx",
        "fields": {"nodes": [
            {"__typename": "ProjectV2SingleSelectField", "id": "SEV", "name": "Severity",
             "options": [{"id": "o-crit", "name": "critical"}, {"id": "o-high", "name": "high"},
                         {"id": "o-med",  "name": "medium"},   {"id": "o-low",  "name": "low"},
                         {"id": "o-info", "name": "info"}]},
            {"__typename": "ProjectV2SingleSelectField", "id": "CAT", "name": "Category",
             "options": [{"id": "o-dep",  "name": "dependency"}, {"id": "o-sec",  "name": "secret"},
                         {"id": "o-sast", "name": "sast"},       {"id": "o-iac",  "name": "iac"},
                         {"id": "o-lic",  "name": "license"}]},
        ]},
    }
    resp = _graphql_resp({"organization": {"projectV2": proj}, "user": None})
    with patch.object(requests.Session, "request", return_value=resp):
        ctx = gh.resolve_project("leverj", 5)
    assert ctx.id == "PVT_xxx"
    assert ctx.owner == "leverj" and ctx.number == 5
    assert ctx.severity.id == "SEV"
    assert ctx.category.id == "CAT"
    assert ctx.severity.options["critical"] == "o-crit"
    assert ctx.category.options["sast"] == "o-sast"


def test_resolve_project_user_match_falls_through():
    gh = _gh()
    proj = {"id": "PVT_user", "fields": {"nodes": [
        {"__typename": "ProjectV2SingleSelectField", "id": "SEV", "name": "Severity",
         "options": [{"id": "o-c", "name": "critical"}, {"id": "o-h", "name": "high"},
                     {"id": "o-m", "name": "medium"},   {"id": "o-l", "name": "low"},
                     {"id": "o-i", "name": "info"}]},
        {"__typename": "ProjectV2SingleSelectField", "id": "CAT", "name": "Category",
         "options": [{"id": "o-d", "name": "dependency"}, {"id": "o-s", "name": "secret"},
                     {"id": "o-a", "name": "sast"},       {"id": "o-ia", "name": "iac"},
                     {"id": "o-li", "name": "license"}]},
    ]}}
    resp = _graphql_resp({"organization": {"projectV2": None}, "user": {"projectV2": proj}})
    with patch.object(requests.Session, "request", return_value=resp):
        ctx = gh.resolve_project("alice", 2)
    assert ctx.id == "PVT_user"


def test_resolve_project_not_found_raises_404():
    gh = _gh()
    resp = _graphql_resp({"organization": None, "user": None})
    with patch.object(requests.Session, "request", return_value=resp):
        with pytest.raises(GitHubError) as ei:
            gh.resolve_project("nope", 99)
    assert ei.value.status == 404
    assert "project" in str(ei.value).lower()


def test_resolve_project_creates_missing_fields():
    """If Severity / Category don't already exist, they are created (one mutation each).
    The resolve query plus two create mutations = 3 HTTP calls total."""
    gh = _gh()
    # First call: lookup returns project with NO custom fields.
    lookup = _graphql_resp({"organization": {"projectV2": {"id": "PVT_x", "fields": {"nodes": []}}}, "user": None})
    # Two creates — return synthetic created field structures.
    created_sev = _graphql_resp({"createProjectV2Field": {"projectV2Field": {
        "id": "SEV_NEW", "options": [
            {"id": "o-c", "name": "critical"}, {"id": "o-h", "name": "high"},
            {"id": "o-m", "name": "medium"},   {"id": "o-l", "name": "low"},
            {"id": "o-i", "name": "info"},
        ],
    }}})
    created_cat = _graphql_resp({"createProjectV2Field": {"projectV2Field": {
        "id": "CAT_NEW", "options": [
            {"id": "o-d", "name": "dependency"}, {"id": "o-s", "name": "secret"},
            {"id": "o-a", "name": "sast"},       {"id": "o-ia", "name": "iac"},
            {"id": "o-li", "name": "license"},
        ],
    }}})
    with patch.object(requests.Session, "request", side_effect=[lookup, created_sev, created_cat]) as m:
        ctx = gh.resolve_project("leverj", 5)
    assert m.call_count == 3
    assert ctx.severity.id == "SEV_NEW"
    assert ctx.category.id == "CAT_NEW"
    # All three must POST to /graphql
    for call in m.call_args_list:
        url = call.args[1] if len(call.args) > 1 else call.kwargs.get("url")
        assert url == "https://api.github.com/graphql"


def test_resolve_project_dry_run_skips_network():
    gh = _gh(dry_run=True)
    with patch.object(requests.Session, "request") as m:
        ctx = gh.resolve_project("leverj", 5)
    assert m.call_count == 0
    assert ctx.id == "DRY_RUN_PROJECT"
    assert "critical" in ctx.severity.options
    assert "sast" in ctx.category.options


# ---- list_project_items --------------------------------------------------


def test_list_project_items_paginates_and_skips_non_issues():
    gh = _gh()
    page1 = _graphql_resp({"node": {"items": {
        "pageInfo": {"hasNextPage": True, "endCursor": "cur1"},
        "nodes": [
            {"id": "ITEM1", "content": {"id": "I1", "number": 11, "state": "OPEN", "title": "t1", "body": "b1"}},
            {"id": "ITEM_DRAFT", "content": {}},  # draft — no number, must skip
        ],
    }}})
    page2 = _graphql_resp({"node": {"items": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [
            {"id": "ITEM2", "content": {"id": "I2", "number": 12, "state": "CLOSED", "title": "t2", "body": "b2"}},
        ],
    }}})
    with patch.object(requests.Session, "request", side_effect=[page1, page2]) as m:
        out = gh.list_project_items("PVT_x")
    assert [it["number"] for it in out] == [11, 12]
    assert m.call_count == 2
    assert out[0]["item_id"] == "ITEM1" and out[1]["item_id"] == "ITEM2"
    assert out[0]["body"] == "b1"


def test_list_project_items_dry_run_returns_empty():
    gh = _gh(dry_run=True)
    with patch.object(requests.Session, "request") as m:
        out = gh.list_project_items("PVT_x")
    assert out == []
    assert m.call_count == 0


# ---- add_to_project / set_project_field ----------------------------------


def test_add_to_project_returns_item_id():
    gh = _gh()
    resp = _graphql_resp({"addProjectV2ItemById": {"item": {"id": "NEW_ITEM"}}})
    with patch.object(requests.Session, "request", return_value=resp) as m:
        out = gh.add_to_project("PVT_x", "I_node")
    assert out == "NEW_ITEM"
    call = m.call_args
    assert (call.args[1] if len(call.args) > 1 else call.kwargs["url"]) == "https://api.github.com/graphql"
    assert "addProjectV2ItemById" in call.kwargs["json"]["query"]
    assert call.kwargs["json"]["variables"] == {"pid": "PVT_x", "cid": "I_node"}


def test_add_to_project_dry_run_returns_synthetic_id():
    gh = _gh(dry_run=True)
    with patch.object(requests.Session, "request") as m:
        out = gh.add_to_project("PVT_x", "I_node")
    assert out.startswith("DRY_RUN_ITEM_")
    assert m.call_count == 0


def test_set_project_field_calls_update_mutation():
    gh = _gh()
    resp = _graphql_resp({"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "ITEM"}}})
    field = ProjectField(id="FID", options={"critical": "o-crit", "high": "o-high"})
    with patch.object(requests.Session, "request", return_value=resp) as m:
        gh.set_project_field("PVT_x", "ITEM", field, "critical")
    assert m.call_count == 1
    call = m.call_args
    assert "updateProjectV2ItemFieldValue" in call.kwargs["json"]["query"]
    vars_ = call.kwargs["json"]["variables"]
    assert vars_["pid"] == "PVT_x"
    assert vars_["iid"] == "ITEM"
    assert vars_["fid"] == "FID"
    assert vars_["oid"] == "o-crit"


def test_set_project_field_unknown_option_is_noop():
    """If the user renamed an option, security_scan must not crash — silently skip."""
    gh = _gh()
    field = ProjectField(id="FID", options={"critical": "o-crit"})
    with patch.object(requests.Session, "request") as m:
        gh.set_project_field("PVT_x", "ITEM", field, "this-option-does-not-exist")
    assert m.call_count == 0


def test_set_project_field_dry_run_is_noop():
    gh = _gh(dry_run=True)
    field = ProjectField(id="FID", options={"critical": "o-crit"})
    with patch.object(requests.Session, "request") as m:
        gh.set_project_field("PVT_x", "ITEM", field, "critical")
    assert m.call_count == 0


# ---- _graphql error surface ---------------------------------------------


def test_graphql_errors_raise_with_scrubbed_message():
    gh = _gh()
    leaky = {"message": f"bad token {TOKEN}"}
    resp = _graphql_resp(errors=[leaky])
    with patch.object(requests.Session, "request", return_value=resp):
        with pytest.raises(GitHubError) as ei:
            gh._graphql("query { foo }")
    assert TOKEN not in str(ei.value)


# ---- retry / rate limit / errors ----------------------------------------


def test_retry_on_500():
    gh = _gh()
    bad = _resp(500, json_body={"message": "boom"})
    good = _resp(201, json_body={"id": 1, "node_id": "I_x", "number": 1, "title": "t", "body": "b", "html_url": "u", "state": "open"})
    with patch("security_scan.github.time.sleep") as sl, \
         patch.object(requests.Session, "request", side_effect=[bad, good]) as m:
        gh.create_issue("t", "b")
    assert m.call_count == 2
    assert sl.call_count >= 1


def test_rate_limit_waits_and_retries():
    gh = _gh()
    import time as _time
    reset_at = int(_time.time()) + 1
    limited = _resp(
        403,
        json_body={"message": "API rate limit exceeded"},
        headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_at)},
    )
    good = _resp(201, json_body={"id": 1, "node_id": "I_x", "number": 1, "title": "t", "body": "b", "html_url": "u", "state": "open"})
    with patch("security_scan.github.time.sleep") as sl, \
         patch.object(requests.Session, "request", side_effect=[limited, good]) as m:
        gh.create_issue("t", "b")
    assert m.call_count == 2
    assert sl.call_count == 1


def test_4xx_raises_githuberror_without_token():
    gh = _gh()
    resp = _resp(401, json_body={"message": f"bad creds {TOKEN}"})
    with patch.object(requests.Session, "request", return_value=resp):
        with pytest.raises(GitHubError) as ei:
            gh.create_issue("t", "b")
    assert ei.value.status == 401
    assert TOKEN not in str(ei.value)
