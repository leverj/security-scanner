"""One-time backfill: add security_scan markers to sub-issues filed by an earlier tool.

Reads marker-less sub-issues under a parent issue, parses the ezel_scan format
(or a compatible one) to recover (rule_id, file_path, category), computes
security_scan's fingerprint, and PATCHes the body to inject the marker. Future
`security_scan run` invocations then dedup correctly against these issues.

Usage:
    python tools/backfill_markers.py --owner leverj --repo ezel --parent 451 \\
        --work-prefix file:///work/ezel --dry-run
    python tools/backfill_markers.py --owner leverj --repo ezel --parent 451 \\
        --work-prefix file:///work/ezel             # writes for real

Env:
    GITHUB_TOKEN must be set (or use `op run --env-file=.env.1password.tpl -- ...`).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass

import requests

# Allow running this from the repo root with `-m` or as a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_scan.fingerprint import compute_fingerprint, inject_marker, parse_marker
from security_scan.models import Finding

_API = "https://api.github.com"

# Ezel-scan body fields we know how to read.
_FIELD_RE = re.compile(r"^(?P<key>Type|Ecosystem|Package|Installed|Advisory):\s*(?P<val>.+)$", re.M)

# Map detected ecosystems (lowercased) to the canonical lockfile path in the repo.
# Tailor this to the repo you're backfilling against; for leverj/ezel it's:
_ECO_TO_LOCKFILE = {
    "npm":       "yarn.lock",
    "yarn":      "yarn.lock",
    "pnpm":      "yarn.lock",   # if pnpm-lock.yaml exists, change this
    "rubygems":  "ios-native/Gemfile.lock",
    "swiftpm":   "ios-native/Ezel.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved",
}


@dataclass
class ParsedIssue:
    number: int
    state: str
    title: str
    body: str
    category: str | None
    ecosystem: str | None
    package: str | None
    rule_id: str | None  # CVE-XXXX (preferred) or GHSA-XXXX


def parse_ezel_scan_body(title: str, body: str) -> ParsedIssue | None:
    """Best-effort parse. Returns None when the issue isn't a dependency vuln we recognize."""
    fields = {m.group("key").lower(): m.group("val").strip() for m in _FIELD_RE.finditer(body or "")}

    # ezel_scan's "Type: dependency vulnerability ..." indicates a dep finding.
    is_dep = "dependency" in fields.get("type", "").lower()
    if not is_dep:
        # Other ezel_scan types (secret, sast) — out of scope for this pass since the
        # file_path is too unpredictable to safely backfill without scanning. Skip.
        return None

    eco = fields.get("ecosystem", "").lower() or None
    pkg = fields.get("package") or None

    # Advisory: "CVE-2026-XXXX GHSA-..." — prefer CVE (matches what osv-scanner emits as ruleId).
    adv = fields.get("advisory", "")
    cve_match = re.search(r"\bCVE-\d{4}-\d+\b", adv) or re.search(r"\bCVE-\d{4}-\d+\b", title)
    ghsa_match = re.search(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", adv)
    rule_id = (cve_match.group(0) if cve_match else (ghsa_match.group(0) if ghsa_match else None))

    return ParsedIssue(
        number=0, state="", title=title, body=body,
        category="dependency", ecosystem=eco, package=pkg, rule_id=rule_id,
    )


def list_subissues(session: requests.Session, owner: str, repo: str, parent: int) -> list[dict]:
    issues: list[dict] = []
    url = f"{_API}/repos/{owner}/{repo}/issues/{parent}/sub_issues"
    params: dict | None = {"per_page": 100, "state": "all"}
    while url:
        r = session.get(url, params=params, timeout=30)
        r.raise_for_status()
        issues.extend(r.json() or [])
        link = r.headers.get("Link") or ""
        url = None
        for part in link.split(","):
            seg = part.strip()
            if 'rel="next"' in seg:
                lt, gt = seg.find("<"), seg.find(">")
                if lt != -1 and gt != -1:
                    url = seg[lt + 1:gt]
                    params = None  # next-link encodes them
                    break
    return issues


def patch_body(session: requests.Session, owner: str, repo: str, number: int, body: str) -> None:
    r = session.patch(
        f"{_API}/repos/{owner}/{repo}/issues/{number}",
        json={"body": body},
        timeout=30,
    )
    r.raise_for_status()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--parent", type=int, required=True)
    ap.add_argument("--work-prefix", default="file:///work/ezel",
                    help="Path prefix that matches what security_scan/osv-scanner emit "
                         "(e.g. file:///work/<repo-name>).")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("error: GITHUB_TOKEN unset", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "security_scan-backfill/0.1",
    })

    print(f"listing sub-issues of {args.owner}/{args.repo}#{args.parent} ...", file=sys.stderr)
    issues = list_subissues(session, args.owner, args.repo, args.parent)
    print(f"  total: {len(issues)}", file=sys.stderr)

    candidates = [i for i in issues if not parse_marker(i.get("body") or "") and i.get("state") == "open"]
    print(f"  marker-less open: {len(candidates)}", file=sys.stderr)
    print(file=sys.stderr)

    patched = 0
    skipped_no_parse = 0
    skipped_no_eco_map = 0
    for issue in candidates:
        parsed = parse_ezel_scan_body(issue.get("title", ""), issue.get("body", "") or "")
        if not parsed or not parsed.rule_id or not parsed.ecosystem:
            print(f"  - #{issue['number']:>4d}  SKIP (can't parse): {issue['title'][:80]}")
            skipped_no_parse += 1
            continue
        lockfile = _ECO_TO_LOCKFILE.get(parsed.ecosystem)
        if not lockfile:
            print(f"  - #{issue['number']:>4d}  SKIP (no lockfile map for ecosystem={parsed.ecosystem!r}): {issue['title'][:80]}")
            skipped_no_eco_map += 1
            continue
        file_path = f"{args.work_prefix.rstrip('/')}/{lockfile}"

        finding = Finding(
            scanner="osv",
            category="dependency",
            rule_id=parsed.rule_id,
            severity="medium",       # not used by the fingerprint
            file_path=file_path,
            line=None,
            title="",
            message="",
        )
        fp = compute_fingerprint(finding)
        new_body = inject_marker(issue.get("body") or "", fp, finding)

        action = "WOULD PATCH" if args.dry_run else "PATCH"
        print(f"  ✓ #{issue['number']:>4d}  {action}  fp={fp}  rule={parsed.rule_id}  -> {lockfile}")
        if not args.dry_run:
            patch_body(session, args.owner, args.repo, issue["number"], new_body)
        patched += 1

    print(file=sys.stderr)
    print(
        f"summary: {'would patch' if args.dry_run else 'patched'} {patched} · "
        f"skipped {skipped_no_parse} (unparseable) + {skipped_no_eco_map} (no eco map)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
