"""GitHub adapter: clone, list/create sub-issues, link them.

All persistent state lives in GitHub Issues. This module is the only place that
talks to the GitHub REST API or shells out to `git`. The token must never appear
in log output or raised exceptions.
"""

from __future__ import annotations

import base64
import subprocess
import sys
import time
from pathlib import Path

import requests

_API = "https://api.github.com"
_UA = "secscan/0.1"
_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2022-11-28"


class GitHubError(RuntimeError):
    """Raised on non-retryable HTTP failure. Never includes the token."""

    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(f"GitHub API {status}: {message}")


class GitHub:
    def __init__(self, token: str, owner: str, name: str, dry_run: bool = False):
        self.token = token
        self.owner = owner
        self.name = name
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": _ACCEPT,
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": _UA,
        })

    # ---- clone -----------------------------------------------------------

    def clone(self, ref: str, dest: Path, shallow: bool = True) -> None:
        """Git-clone the repo at `ref` into `dest`. Token never leaks on failure.

        The token is passed via `http.<url>.extraheader` set with `-c`, which is
        process-scoped and is NOT written into the resulting `.git/config`. The clone
        URL itself contains no credentials. We use HTTP Basic (the format GitHub's
        smart-HTTP protocol expects); Bearer works for the REST API but not for git.
        """
        url = f"https://github.com/{self.owner}/{self.name}.git"
        basic = base64.b64encode(f"x-access-token:{self.token}".encode()).decode()
        # `-c` config is one-shot for this invocation only; nothing persists into .git/config.
        cmd = [
            "git",
            "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}",
            "clone",
        ]
        if shallow:
            cmd += ["--depth=1", "--single-branch", "--branch", ref]
        else:
            cmd += ["--branch", ref]
        cmd += [url, str(dest)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError as e:
            raise GitHubError(0, f"git not available: {e}") from None
        if r.returncode != 0:
            err = self._scrub(r.stderr or r.stdout or "git clone failed")
            raise GitHubError(0, f"git clone failed: {err.strip()}")

    def _scrub(self, text: str) -> str:
        """Remove the token (raw and base64-encoded forms) from arbitrary output."""
        if not text:
            return text
        out = text.replace(self.token, "***")
        out = out.replace(f"x-access-token:{self.token}", "x-access-token:***")
        # If git ever echoes the extraheader value, scrub the base64-encoded credential too.
        try:
            basic = base64.b64encode(f"x-access-token:{self.token}".encode()).decode()
            out = out.replace(basic, "***")
        except Exception:
            pass
        return out

    # ---- sub-issue listing ----------------------------------------------

    def list_subissues(self, parent_issue: int) -> list[dict]:
        """All sub-issues of `parent_issue`, both open and closed, across all pages."""
        url = f"{_API}/repos/{self.owner}/{self.name}/issues/{parent_issue}/sub_issues"
        params = {"per_page": 100, "state": "all"}
        out: list[dict] = []
        while url:
            resp = self._request("GET", url, params=params)
            out.extend(resp.json() or [])
            url = self._next_link(resp.headers.get("Link"))
            params = None  # next link already encodes them
        return out

    @staticmethod
    def _next_link(link_header: str | None) -> str | None:
        if not link_header:
            return None
        for part in link_header.split(","):
            seg = part.strip()
            if 'rel="next"' in seg:
                lt = seg.find("<")
                gt = seg.find(">")
                if lt != -1 and gt != -1 and gt > lt:
                    return seg[lt + 1:gt]
        return None

    # ---- create / link ---------------------------------------------------

    def create_issue(self, title: str, body: str, labels: list[str] | None = None) -> dict:
        if labels is None:
            labels = ["security"]
        if self.dry_run:
            print(f"DRY-RUN would create: {title}", file=sys.stderr)
            return {"number": 0, "title": title, "body": body, "html_url": "<dry-run>", "state": "open"}
        url = f"{_API}/repos/{self.owner}/{self.name}/issues"
        resp = self._request("POST", url, json={"title": title, "body": body, "labels": labels})
        return resp.json()

    def link_subissue(self, parent_issue: int, child_issue: dict) -> None:
        """Attach `child_issue` as a sub-issue of `parent_issue`.

        Takes the full issue dict (as returned by `create_issue`) because GitHub's
        sub_issues endpoint requires the child's internal node id, not its number.
        """
        if self.dry_run:
            print(
                f"DRY-RUN would link #{child_issue.get('number')} under #{parent_issue}",
                file=sys.stderr,
            )
            return
        url = f"{_API}/repos/{self.owner}/{self.name}/issues/{parent_issue}/sub_issues"
        self._request("POST", url, json={"sub_issue_id": child_issue["id"]})

    # ---- HTTP core: retry on 5xx, wait on rate-limit, never leak token --

    def _request(self, method: str, url: str, **kw) -> requests.Response:
        last_exc: Exception | None = None
        backoffs = [1, 2]
        attempts = len(backoffs) + 1
        for i in range(attempts):
            try:
                resp = self.session.request(method, url, timeout=30, **kw)
            except requests.RequestException as e:
                last_exc = e
                if i < attempts - 1:
                    time.sleep(backoffs[i])
                    continue
                raise GitHubError(0, f"network error: {self._scrub(str(e))}") from None

            if resp.status_code < 400:
                return resp

            # Rate limit: 403 with X-RateLimit-Remaining: 0. Wait then single retry.
            if (
                resp.status_code == 403
                and resp.headers.get("X-RateLimit-Remaining") == "0"
                and "X-RateLimit-Reset" in resp.headers
            ):
                try:
                    reset = int(resp.headers["X-RateLimit-Reset"])
                except ValueError:
                    reset = 0
                wait = max(0, reset - int(time.time())) + 1
                time.sleep(wait)
                resp = self.session.request(method, url, timeout=30, **kw)
                if resp.status_code < 400:
                    return resp
                raise GitHubError(resp.status_code, self._short_error(resp))

            if 500 <= resp.status_code < 600 and i < attempts - 1:
                time.sleep(backoffs[i])
                continue

            raise GitHubError(resp.status_code, self._short_error(resp))

        # Unreachable, but keep type-checkers happy.
        raise GitHubError(0, f"request failed: {self._scrub(str(last_exc))}")

    def _short_error(self, resp: requests.Response) -> str:
        try:
            data = resp.json()
            msg = data.get("message") or data.get("error") or ""
        except ValueError:
            msg = (resp.text or "")[:200]
        return self._scrub(str(msg))
