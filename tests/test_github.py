"""Tests for the GitHub adapter. All HTTP and subprocess calls are mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from secscan.github import GitHub, GitHubError

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
    with patch("secscan.github.subprocess.run", return_value=completed) as m:
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
    with patch("secscan.github.subprocess.run", return_value=completed) as m:
        gh.clone("dev", tmp_path / "repo", shallow=False)
    args = m.call_args.args[0]
    assert "--depth=1" not in args


def test_clone_url_has_no_credentials(tmp_path):
    """The clone URL must not embed the token — git would persist it into .git/config."""
    gh = _gh()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("secscan.github.subprocess.run", return_value=completed) as m:
        gh.clone("dev", tmp_path / "repo")
    args = m.call_args.args[0]
    # The URL is the last-or-second-to-last arg; check no element contains the token URL form.
    url = next(a for a in args if a.startswith("https://"))
    assert url == "https://github.com/leverj/ezel.git"
    assert TOKEN not in url
    assert "x-access-token" not in url


def test_clone_passes_token_via_one_shot_config(tmp_path):
    """The token must arrive via `-c http.<url>.extraheader=AUTHORIZATION: basic <b64>`,
    which is process-scoped and not written into .git/config. (Basic, not Bearer:
    GitHub's smart-HTTP wants Basic for git operations.)"""
    import base64

    gh = _gh()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("secscan.github.subprocess.run", return_value=completed) as m:
        gh.clone("dev", tmp_path / "repo")
    args = m.call_args.args[0]
    # -c <key=val> appears as two consecutive list entries.
    assert "-c" in args
    c_idx = args.index("-c")
    extraheader = args[c_idx + 1]
    assert "extraheader" in extraheader
    assert "basic " in extraheader.lower()
    # The base64-encoded credential must be present and decode back to x-access-token:TOKEN
    encoded = extraheader.split("basic ", 1)[-1]
    decoded = base64.b64decode(encoded).decode()
    assert decoded == f"x-access-token:{TOKEN}"
    # And the raw token must NOT appear unencoded anywhere on argv (only its base64 form is OK).
    for a in args:
        assert TOKEN not in a, f"raw token leaked into argv: {a!r}"


def test_clone_scrubs_token_from_error(tmp_path):
    gh = _gh()
    leaky = f"fatal: could not read from https://x-access-token:{TOKEN}@github.com/leverj/ezel.git"
    completed = MagicMock(returncode=128, stdout="", stderr=leaky)
    with patch("secscan.github.subprocess.run", return_value=completed):
        with pytest.raises(GitHubError) as ei:
            gh.clone("dev", tmp_path / "repo")
    assert TOKEN not in str(ei.value)


# ---- list_subissues -------------------------------------------------------


def test_list_subissues_paginates():
    gh = _gh()
    page1 = _resp(
        200,
        json_body=[{"number": 1, "state": "open", "body": "", "title": "a", "html_url": "u1"}],
        headers={"Link": '<https://api.github.com/page2>; rel="next", <https://api.github.com/last>; rel="last"'},
    )
    page2 = _resp(
        200,
        json_body=[{"number": 2, "state": "closed", "body": "", "title": "b", "html_url": "u2"}],
        headers={},
    )
    with patch.object(requests.Session, "request", side_effect=[page1, page2]) as m:
        out = gh.list_subissues(451)
    assert [i["number"] for i in out] == [1, 2]
    assert m.call_count == 2
    # second call uses the next URL verbatim
    second_url = m.call_args_list[1].args[1] if len(m.call_args_list[1].args) >= 2 else m.call_args_list[1].kwargs["url"]
    assert second_url == "https://api.github.com/page2"


def test_list_subissues_returns_open_and_closed():
    gh = _gh()
    body = [
        {"number": 1, "state": "open", "body": "", "title": "a", "html_url": "u1"},
        {"number": 2, "state": "closed", "body": "", "title": "b", "html_url": "u2"},
    ]
    resp = _resp(200, json_body=body, headers={})
    with patch.object(requests.Session, "request", return_value=resp):
        out = gh.list_subissues(451)
    states = {i["state"] for i in out}
    assert states == {"open", "closed"}


# ---- create_issue ---------------------------------------------------------


def test_create_issue_posts_correct_payload():
    gh = _gh()
    created = {"id": 9001, "number": 42, "title": "t", "body": "b", "html_url": "u", "state": "open"}
    resp = _resp(201, json_body=created, headers={})
    with patch.object(requests.Session, "request", return_value=resp) as m:
        out = gh.create_issue("t", "b", labels=["security", "secscan"])
    assert out == created
    call = m.call_args
    method = call.args[0] if call.args else call.kwargs["method"]
    url = call.args[1] if len(call.args) > 1 else call.kwargs["url"]
    assert method == "POST"
    assert url == "https://api.github.com/repos/leverj/ezel/issues"
    assert call.kwargs["json"] == {"title": "t", "body": "b", "labels": ["security", "secscan"]}
    # auth header is set on the session
    assert gh.session.headers["Authorization"] == f"Bearer {TOKEN}"
    assert gh.session.headers["Accept"] == "application/vnd.github+json"
    assert gh.session.headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_create_issue_defaults_security_label():
    gh = _gh()
    created = {"id": 1, "number": 1, "title": "t", "body": "b", "html_url": "u", "state": "open"}
    resp = _resp(201, json_body=created)
    with patch.object(requests.Session, "request", return_value=resp) as m:
        gh.create_issue("t", "b")
    assert m.call_args.kwargs["json"]["labels"] == ["security"]


def test_create_issue_dry_run(capsys):
    gh = _gh(dry_run=True)
    with patch.object(requests.Session, "request") as m:
        out = gh.create_issue("hello", "body")
    assert m.call_count == 0
    assert out["number"] == 0
    assert out["title"] == "hello"
    assert out["html_url"] == "<dry-run>"
    err = capsys.readouterr().err
    assert "DRY-RUN" in err and "hello" in err


# ---- link_subissue --------------------------------------------------------


def test_link_subissue_uses_id_not_number():
    gh = _gh()
    child = {"id": 12345, "number": 7, "title": "x", "body": "", "html_url": "u", "state": "open"}
    resp = _resp(201, json_body={})
    with patch.object(requests.Session, "request", return_value=resp) as m:
        gh.link_subissue(451, child)
    call = m.call_args
    url = call.args[1] if len(call.args) > 1 else call.kwargs["url"]
    assert url == "https://api.github.com/repos/leverj/ezel/issues/451/sub_issues"
    assert call.kwargs["json"] == {"sub_issue_id": 12345}


def test_link_subissue_dry_run(capsys):
    gh = _gh(dry_run=True)
    child = {"id": 12345, "number": 7}
    with patch.object(requests.Session, "request") as m:
        gh.link_subissue(451, child)
    assert m.call_count == 0
    err = capsys.readouterr().err
    assert "DRY-RUN" in err and "#7" in err and "#451" in err


# ---- retry / rate limit / errors -----------------------------------------


def test_retry_on_500():
    gh = _gh()
    bad = _resp(500, json_body={"message": "boom"})
    good = _resp(200, json_body=[])
    with patch("secscan.github.time.sleep") as sl, \
         patch.object(requests.Session, "request", side_effect=[bad, good]) as m:
        out = gh.list_subissues(451)
    assert out == []
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
    good = _resp(200, json_body=[])
    with patch("secscan.github.time.sleep") as sl, \
         patch.object(requests.Session, "request", side_effect=[limited, good]) as m:
        out = gh.list_subissues(451)
    assert out == []
    assert m.call_count == 2
    assert sl.call_count == 1  # exactly one wait, then one retry


def test_4xx_raises_githuberror_without_token():
    gh = _gh()
    # Embed the token in the error message to make sure it gets scrubbed.
    resp = _resp(401, json_body={"message": f"bad creds {TOKEN}"})
    with patch.object(requests.Session, "request", return_value=resp):
        with pytest.raises(GitHubError) as ei:
            gh.list_subissues(451)
    assert ei.value.status == 401
    assert TOKEN not in str(ei.value)
