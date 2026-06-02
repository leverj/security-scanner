"""Live Supabase Security Advisor runner.

Connects to the project's Postgres (the Supabase-managed instance), runs each
vendored lint check from `supabase_lints.CHECKS`, and emits one `Finding` per
row.

Failure-mode parity with other runners: any connection / query error
contributes zero findings and is surfaced via RunnerResult.error. A live-scan
failure NEVER reads as "all clear" — `_absorb` keeps the scanner off the
`completed` list, the run completes, and the summary line marks the lane as
failed.

Read-only by construction:
  - A `SET TRANSACTION READ ONLY` is issued immediately after connecting.
  - We connect with `autocommit=False` and wrap all queries in a single
    transaction so the read-only flag actually applies.
  - We do not issue DDL / DML, ever.

This module returns RunnerResult with `sarif=None` and a synthetic
`_supabase_findings` payload in `extra_findings` — main.py normalizes via a
direct Finding construction path (no SARIF round-trip; lint rows aren't
SARIF-shaped).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from security_scan.models import Finding

from . import RunnerResult
from .supabase_lints import CHECKS, LintCheck


@dataclass
class SupabaseConnConfig:
    """Resolved Supabase connection parameters. Either `dsn` is set OR all of
    host/db/user/password are set. ssl defaults to require."""
    dsn: str | None = None
    host: str | None = None
    port: int = 5432
    dbname: str | None = None
    user: str | None = None
    password: str | None = None
    sslmode: str = "require"
    connect_timeout: int = 10
    query_timeout_ms: int = 30_000  # 30s per check
    checks: list[str] | None = None  # None => run all


class SupabaseRunResult:
    """Carrier for live-scan findings. Returned via RunnerResult.error=None,
    sarif={"_supabase_findings": [...]} so main.py can pull them out without
    a SARIF detour."""


def run(
    cfg: SupabaseConnConfig,
    connector: Callable | None = None,
) -> RunnerResult:
    """Connect, run each check, return findings packaged in a wrapper dict so
    main.py can normalize without SARIF.

    `connector` is an injection point for tests; defaults to `psycopg.connect`.
    """
    try:
        import psycopg
    except ImportError as e:
        return RunnerResult(
            "supabase_live", None, False,
            f"psycopg not installed: {e}. Install the `live` extra: "
            "`pip install security-scan[live]`.",
        )

    connect = connector or psycopg.connect
    conn_kwargs = _build_conn_kwargs(cfg)

    try:
        conn = connect(**conn_kwargs)
    except Exception as e:
        return RunnerResult(
            "supabase_live", None, False,
            f"connection failed: {type(e).__name__}: {_scrub(str(e), cfg)[:300]}",
        )

    findings: list[Finding] = []
    errors: list[str] = []
    try:
        # Enforce read-only at the transaction level — even a bug in our SQL
        # cannot mutate the DB if this is set.
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")

        wanted = set(cfg.checks) if cfg.checks else None
        for check in CHECKS:
            if wanted is not None and check.name not in wanted:
                continue
            try:
                rows, cols = _run_query(conn, check, cfg.query_timeout_ms)
            except Exception as e:
                errors.append(f"{check.name}: {type(e).__name__}: {_scrub(str(e), cfg)[:200]}")
                continue
            for row in rows:
                f = _row_to_finding(check, row, cols)
                if f is not None:
                    findings.append(f)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if not findings and errors:
        # Every check failed — surface as runner failure so the summary shows it.
        return RunnerResult(
            "supabase_live", None, False,
            f"all checks failed: {'; '.join(errors[:3])}",
        )

    # Some checks may have failed but others succeeded — log the partials and
    # still return findings. _absorb sees completed=True.
    if errors:
        import sys
        print(f"supabase_live: {len(errors)} check(s) failed: {errors[:3]}", file=sys.stderr)

    return RunnerResult(
        "supabase_live",
        {"_supabase_findings": findings},
        True,
        None,
    )


def _build_conn_kwargs(cfg: SupabaseConnConfig) -> dict:
    """Translate our config dataclass into psycopg.connect kwargs.
    DSN takes precedence over discrete host/db/user/password."""
    if cfg.dsn:
        return {
            "conninfo": cfg.dsn,
            "connect_timeout": cfg.connect_timeout,
            "autocommit": False,
        }
    return {
        "host": cfg.host,
        "port": cfg.port,
        "dbname": cfg.dbname,
        "user": cfg.user,
        "password": cfg.password,
        "sslmode": cfg.sslmode,
        "connect_timeout": cfg.connect_timeout,
        "autocommit": False,
    }


def _run_query(conn, check: LintCheck, timeout_ms: int) -> tuple[list[tuple], list[str]]:
    """Execute one check's SQL with a per-statement timeout. Returns
    (rows, column_names)."""
    with conn.cursor() as cur:
        # statement_timeout is reset to default at transaction end, so this
        # only affects the current SELECT.
        cur.execute(f"SET LOCAL statement_timeout = {int(timeout_ms)}")
        cur.execute(check.sql)
        cols = [d.name if hasattr(d, "name") else d[0] for d in (cur.description or [])]
        rows = cur.fetchall()
        return rows, cols


def _row_to_finding(check: LintCheck, row: tuple, cols: list[str]) -> Finding | None:
    """Apply the check's row_map and build a normalized Finding."""
    try:
        info = check.row_map(row, cols)
    except Exception:
        return None
    identifier = str(info.get("identifier") or "")
    if not identifier:
        return None
    return Finding(
        scanner="supabase_live",
        category="config",
        rule_id=check.name,
        severity=check.severity,
        file_path=str(info.get("file_path") or f"db://{identifier}"),
        line=None,
        title=check.title,
        message=str(info.get("message") or check.title),
        extra={"object": identifier},
    )


def _scrub(msg: str, cfg: SupabaseConnConfig) -> str:
    """Redact the password from error messages — psycopg embeds the DSN in
    its error strings for some failure modes, which would leak credentials
    into the project board via the failed-scanner log line."""
    out = msg
    # DSN substitution first (more specific — it can embed the password and
    # other identifying parts that we don't want to leak even if the password
    # scrub leaves them intact).
    if cfg.dsn:
        out = out.replace(cfg.dsn, "<REDACTED-DSN>")
    if cfg.password:
        out = out.replace(cfg.password, "<REDACTED>")
    return out
