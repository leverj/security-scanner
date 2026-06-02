"""GitHub adapter: clone, create issues, attach them as items in a Projects v2 board.

All persistent state lives in GitHub Issues + their Projects v2 board membership.
This module is the only place that talks to GitHub (REST for issues/labels/clone;
GraphQL for the Projects v2 surface). The token must never appear in log output or
raised exceptions.
"""

from __future__ import annotations

import base64
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

_API = "https://api.github.com"
_GRAPHQL = "https://api.github.com/graphql"
_UA = "secscan/0.1"
_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2022-11-28"

# Single-select options + colors that secscan creates on the target Project v2 if
# the user hasn't created them already. GitHub's `ProjectV2SingleSelectFieldOptionColor`
# enum accepts: GRAY, BLUE, GREEN, YELLOW, ORANGE, RED, PINK, PURPLE.
_SEVERITY_OPTIONS: list[tuple[str, str]] = [
    ("critical", "RED"),
    ("high",     "ORANGE"),
    ("medium",   "YELLOW"),
    ("low",      "BLUE"),
    ("info",     "GRAY"),
]
_CATEGORY_OPTIONS: list[tuple[str, str]] = [
    ("dependency", "PURPLE"),
    ("secret",     "RED"),
    ("sast",       "YELLOW"),
    ("iac",        "GREEN"),
    ("license",    "BLUE"),
]


@dataclass(frozen=True)
class ProjectField:
    """A Projects v2 single-select field, with `option_name -> option_id` map."""
    id: str
    options: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ProjectContext:
    """Resolved Projects v2 target. Carry this through sync so we don't re-resolve."""
    id: str           # project node id (PVT_...)
    owner: str        # org or user login
    number: int       # project number (visible in URL)
    severity: ProjectField
    category: ProjectField


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
        self._LABEL_CREATED = set()
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

    # ---- Projects v2 (GraphQL) ------------------------------------------

    def resolve_project(self, owner: str, number: int) -> ProjectContext:
        """Find the Projects v2 board by (owner, number). Idempotently ensures
        single-select `Severity` and `Category` fields exist with the secscan
        option set. Re-running is safe.
        """
        if self.dry_run:
            return ProjectContext(
                id="DRY_RUN_PROJECT",
                owner=owner,
                number=number,
                severity=ProjectField(id="DRY_RUN_SEV",
                                      options={n: f"opt-sev-{n}" for n, _ in _SEVERITY_OPTIONS}),
                category=ProjectField(id="DRY_RUN_CAT",
                                      options={n: f"opt-cat-{n}" for n, _ in _CATEGORY_OPTIONS}),
            )

        node = self._lookup_project(owner, number)
        sev = self._ensure_single_select_field(node["id"], node["fields"], "Severity", _SEVERITY_OPTIONS)
        cat = self._ensure_single_select_field(node["id"], node["fields"], "Category", _CATEGORY_OPTIONS)
        return ProjectContext(id=node["id"], owner=owner, number=number, severity=sev, category=cat)

    def list_project_items(self, project_id: str) -> list[dict]:
        """Paginated list of project items (issues only). Each dict:
            {item_id, content_id, number, state, title, body}
        Drafts and PR items are skipped. Used for body-marker dedup.
        """
        if self.dry_run or project_id == "DRY_RUN_PROJECT":
            return []
        items: list[dict] = []
        cursor: str | None = None
        query = """
        query($pid: ID!, $after: String) {
          node(id: $pid) {
            ... on ProjectV2 {
              items(first: 100, after: $after) {
                pageInfo { hasNextPage endCursor }
                nodes {
                  id
                  content {
                    ... on Issue { id number state title body }
                  }
                }
              }
            }
          }
        }
        """
        while True:
            data = self._graphql(query, {"pid": project_id, "after": cursor})
            payload = (data.get("node") or {}).get("items") or {"nodes": [], "pageInfo": {"hasNextPage": False}}
            for n in payload.get("nodes") or []:
                content = n.get("content") or {}
                # `content.number` is absent for drafts and not-an-Issue items.
                if content.get("number") is None:
                    continue
                items.append({
                    "item_id": n["id"],
                    "content_id": content.get("id"),
                    "number": content["number"],
                    "state": content.get("state"),
                    "title": content.get("title") or "",
                    "body": content.get("body") or "",
                })
            if not payload.get("pageInfo", {}).get("hasNextPage"):
                break
            cursor = payload["pageInfo"]["endCursor"]
        return items

    def add_to_project(self, project_id: str, issue_node_id: str) -> str:
        """Attach an issue (by its GraphQL node id) to the project. Returns the
        new item id. Idempotent — calling twice for the same issue returns the
        same item id (GitHub deduplicates server-side)."""
        if self.dry_run:
            return f"DRY_RUN_ITEM_{issue_node_id}"
        data = self._graphql(
            """
            mutation($pid: ID!, $cid: ID!) {
              addProjectV2ItemById(input: {projectId: $pid, contentId: $cid}) {
                item { id }
              }
            }
            """,
            {"pid": project_id, "cid": issue_node_id},
        )
        return data["addProjectV2ItemById"]["item"]["id"]

    def set_project_field(self, project_id: str, item_id: str, field: ProjectField, option_name: str) -> None:
        """Set a single-select project field on an item. No-op if the option
        name isn't present on the field (e.g. user renamed it)."""
        opt_id = field.options.get(option_name)
        if not opt_id or self.dry_run:
            return
        self._graphql(
            """
            mutation($pid: ID!, $iid: ID!, $fid: ID!, $oid: String!) {
              updateProjectV2ItemFieldValue(input: {
                projectId: $pid, itemId: $iid, fieldId: $fid,
                value: {singleSelectOptionId: $oid}
              }) { projectV2Item { id } }
            }
            """,
            {"pid": project_id, "iid": item_id, "fid": field.id, "oid": opt_id},
        )

    # ---- create issue ---------------------------------------------------

    def create_issue(self, title: str, body: str, labels: list[str] | None = None) -> dict:
        if labels is None:
            labels = ["security"]
        if self.dry_run:
            print(f"DRY-RUN would create: {title} (labels={labels})", file=sys.stderr)
            return {
                "number": 0, "title": title, "body": body,
                "html_url": "<dry-run>", "state": "open",
                "node_id": "DRY_RUN_NODE",
            }
        # Idempotently ensure any non-default labels exist before we POST the issue;
        # GitHub returns 422 if an unknown label is passed in the issue payload.
        for lbl in labels:
            if lbl != "security":
                self._ensure_label(lbl)
        url = f"{_API}/repos/{self.owner}/{self.name}/issues"
        resp = self._request("POST", url, json={"title": title, "body": body, "labels": labels})
        return resp.json()

    # Color palette per category/severity. Anything unmapped becomes mid-grey.
    _LABEL_COLOR = {
        # categories
        "secscan:dependency": "5319e7",        # purple — language/OS package CVEs
        "secscan:secret": "d93f0b",            # red — pattern-matched secret
        "secscan:secret-verified": "b60205",   # dark red — live/verified secret
        "secscan:sast": "fbca04",              # yellow — code patterns
        "secscan:iac": "0e8a16",               # green — IaC misconfig
        "secscan:license": "1d76db",           # blue — license issues
        # severities
        "secscan:critical": "b60205",
        "secscan:high":     "d93f0b",
        "secscan:medium":   "fbca04",
        "secscan:low":      "c5def5",
        "secscan:info":     "ededed",
    }
    _LABEL_CREATED: set[str]  # populated in __init__

    def _ensure_label(self, name: str) -> None:
        """Create the label if it doesn't exist. 422 (already exists) is fine."""
        if name in self._LABEL_CREATED:
            return
        self._LABEL_CREATED.add(name)
        color = self._LABEL_COLOR.get(name, "ededed")
        try:
            self._request(
                "POST",
                f"{_API}/repos/{self.owner}/{self.name}/labels",
                json={"name": name, "color": color, "description": "secscan-managed label"},
            )
        except GitHubError as e:
            # 422 = label already exists with this name; anything else is a real problem.
            if e.status != 422:
                print(f"github: could not create label {name!r}: {e}", file=sys.stderr)

    # ---- Projects v2 internals ------------------------------------------

    def _lookup_project(self, owner: str, number: int) -> dict:
        """Resolve a Projects v2 board by (owner, number).

        GraphQL doesn't have a unified "owner" type, so we try `organization`
        first; if that resolves to nothing (or errors with 'Could not resolve to
        an Organization'), we try `user`. Two round-trips at worst, but each is
        clean — a single combined query returns top-level errors for whichever
        branch didn't match, which would force fragile error filtering.
        """
        fragment = """
        fragment P on ProjectV2 {
          id
          fields(first: 50) {
            nodes {
              ... on ProjectV2SingleSelectField {
                __typename
                id name
                options { id name }
              }
            }
          }
        }
        """
        for kind in ("organization", "user"):
            query = "query($login: String!, $number: Int!) { " \
                    f"{kind}(login: $login) {{ projectV2(number: $number) {{ ...P }} }} " \
                    "}" + fragment
            try:
                data = self._graphql(query, {"login": owner, "number": number})
            except GitHubError as e:
                # "Could not resolve to a {Kind}" -> wrong entity type; try the next one.
                if "could not resolve to" in str(e).lower():
                    continue
                raise
            node = (data.get(kind) or {}).get("projectV2")
            if node:
                return node
        raise GitHubError(404, f"project not found: {owner}/projects/{number} "
                               "(check owner, number, and that the PAT has the 'project' scope)")

    def _ensure_single_select_field(
        self, project_id: str, fields_payload: dict | None,
        name: str, options: list[tuple[str, str]],
    ) -> ProjectField:
        """If a single-select field with this name exists, return it. Otherwise
        create it with the given options. Missing options on an existing field
        are surfaced as a warning (not auto-added — that's a separate mutation
        and a deliberate user choice if they renamed things)."""
        existing = self._find_single_select_field(fields_payload, name)
        if existing:
            opts = {o["name"]: o["id"] for o in existing.get("options") or []}
            missing = [n for n, _ in options if n not in opts]
            if missing:
                print(
                    f"github: project field {name!r} is missing options {missing}; "
                    "secscan won't be able to set those values until you add them",
                    file=sys.stderr,
                )
            return ProjectField(id=existing["id"], options=opts)

        opt_input = [{"name": n, "color": c, "description": " "} for n, c in options]
        data = self._graphql(
            """
            mutation($pid: ID!, $name: String!, $opts: [ProjectV2SingleSelectFieldOptionInput!]!) {
              createProjectV2Field(input: {
                projectId: $pid, dataType: SINGLE_SELECT,
                name: $name, singleSelectOptions: $opts
              }) {
                projectV2Field {
                  ... on ProjectV2SingleSelectField {
                    id options { id name }
                  }
                }
              }
            }
            """,
            {"pid": project_id, "name": name, "opts": opt_input},
        )
        f = data["createProjectV2Field"]["projectV2Field"]
        print(f"github: created project field {name!r} with {len(f.get('options') or [])} options",
              file=sys.stderr)
        return ProjectField(id=f["id"], options={o["name"]: o["id"] for o in f.get("options") or []})

    @staticmethod
    def _find_single_select_field(fields_payload: dict | None, name: str) -> dict | None:
        for node in ((fields_payload or {}).get("nodes") or []):
            if not node:
                continue
            if node.get("__typename") == "ProjectV2SingleSelectField" and node.get("name") == name:
                return node
        return None

    def _graphql(self, query: str, variables: dict | None = None) -> dict:
        """POST a GraphQL request. Same retry/scrub policy as `_request` for REST."""
        resp = self._request("POST", _GRAPHQL, json={"query": query, "variables": variables or {}})
        data = resp.json()
        if "errors" in data:
            msg = "; ".join(e.get("message", "") for e in data["errors"] or [])
            raise GitHubError(0, self._scrub(msg) or "graphql error")
        return data.get("data") or {}

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
