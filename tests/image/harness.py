"""Run the image's real entrypoint with only the GitHub client replaced (CI harness).

MODE=ok       fake board accepts everything            -> expect exit 0
MODE=fail401  project lookup -> GitHub 401 Bad creds    -> expect exit 4
MODE=fail403  issue creation -> GitHub 403 (token lacks repo) -> expect exit 4
"""
import os
import runpy
import sys
from unittest.mock import MagicMock, patch

from security_scan.github import GitHubError, ProjectContext, ProjectField

mode = os.environ["MODE"]
ctx = ProjectContext(
    id="PVT_x", owner="owner", number=5,
    severity=ProjectField(id="SEV", options={k: f"o-{k}" for k in ("critical", "high", "medium", "low", "info")}),
    category=ProjectField(id="CAT", options={k: f"o-{k}" for k in
                                             ("dependency", "secret", "sast", "iac", "license", "image", "config")}),
)
created = []

def fake_github(*a, **kw):
    gh = MagicMock()
    gh.dry_run = False
    gh.list_project_items.return_value = []
    gh.add_to_project.side_effect = lambda pid, nid: f"ITEM_{nid}"
    if mode == "fail401":
        gh.resolve_project.side_effect = GitHubError(401, "Bad credentials")
    else:
        gh.resolve_project.return_value = ctx
    def create(title, body, labels=None):
        if mode == "fail403":
            raise GitHubError(403, "Resource not accessible by personal access token")
        created.append(title)
        print(f"HARNESS issue: {title} | {' '.join(body.split())[:600]}", file=sys.stderr)
        n = len(created)
        return {"number": n, "id": n, "node_id": f"I_{n}", "title": title, "body": body, "html_url": "x"}
    gh.create_issue.side_effect = create
    return gh

sys.argv = ["security_scan", "--config", "/config/config.yaml", "--work-dir", "/work", "--repo-dir", "/work"]
with patch("security_scan.main.GitHub", side_effect=fake_github):
    try:
        runpy.run_module("security_scan", run_name="__main__", alter_sys=True)
        rc = 0
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
print(f"HARNESS mode={mode} rc={rc} issues_created={len(created)}", file=sys.stderr)
sys.exit(rc)
