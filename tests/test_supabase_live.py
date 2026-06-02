"""Tests for the live Supabase Security Advisor runner.

psycopg.connect is mocked end-to-end; no real DB is reachable from CI.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from security_scan.runners.supabase_lints import CHECKS, by_name
from security_scan.runners.supabase_live import (
    SupabaseConnConfig,
    _build_conn_kwargs,
    _scrub,
    run,
)

# -- helpers ------------------------------------------------------------------


class _Col:
    def __init__(self, name): self.name = name


class _FakeCursor:
    """A psycopg-cursor stand-in. Each call to execute() either matches one
    of the configured (sql_substring -> (rows, cols)) pairs, or runs no-op
    (for SET / SET TRANSACTION statements)."""

    def __init__(self, sql_to_result):
        self._mapping = sql_to_result
        self._last = None

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def execute(self, sql, *args):
        s = sql.strip()
        # Match on substring of the check's first WHERE/JOIN — coarse but enough.
        for key, payload in self._mapping.items():
            if key in s:
                self._last = payload
                return
        self._last = None  # SET / housekeeping

    @property
    def description(self):
        if self._last is None:
            return []
        _, cols = self._last
        return [_Col(c) for c in cols]

    def fetchall(self):
        if self._last is None:
            return []
        rows, _ = self._last
        return list(rows)


class _FakeConn:
    def __init__(self, sql_to_result):
        self._mapping = sql_to_result

    def cursor(self):
        return _FakeCursor(self._mapping)

    def close(self):
        pass


def _ensure_psycopg_importable():
    """If psycopg isn't installed in this venv, stub it out so the runner's
    `import psycopg` succeeds. We patch `psycopg.connect` per-test via the
    `connector` injection point anyway."""
    if "psycopg" not in sys.modules:
        sys.modules["psycopg"] = MagicMock()


# -- lint catalog -------------------------------------------------------------


def test_lint_catalog_has_unique_names():
    names = [c.name for c in CHECKS]
    assert len(names) == len(set(names)), f"duplicates: {names}"
    assert all(n.startswith("supabase.") for n in names)


def test_by_name_finds_known_check():
    assert by_name("supabase.rls_disabled_in_public") is not None
    assert by_name("supabase.does_not_exist") is None


# -- run() integration --------------------------------------------------------


def test_run_emits_findings_for_rls_disabled(tmp_path):
    """A row from the RLS-disabled query should produce one high-severity
    finding tagged scanner=supabase_live, category=config."""
    _ensure_psycopg_importable()
    rows = [("public", "users"), ("public", "orders")]
    cols = ["schema_name", "table_name"]
    mapping = {"NOT c.relrowsecurity": (rows, cols)}

    def _fake_connect(**kw):
        return _FakeConn(mapping)

    cfg = SupabaseConnConfig(
        dsn="postgres://u:p@h:5432/db",
        checks=["supabase.rls_disabled_in_public"],
    )
    result = run(cfg, connector=_fake_connect)

    assert result.completed is True
    payload = result.sarif["_supabase_findings"]
    assert [f.rule_id for f in payload] == ["supabase.rls_disabled_in_public"] * 2
    assert [f.file_path for f in payload] == ["db://public.users", "db://public.orders"]
    assert all(f.scanner == "supabase_live" for f in payload)
    assert all(f.category == "config" for f in payload)
    assert all(f.severity == "high" for f in payload)


def test_run_handles_security_definer_view_check():
    _ensure_psycopg_importable()
    rows = [("public", "user_lookup")]
    cols = ["schema_name", "view_name"]
    mapping = {"ILIKE '%security_definer%'": (rows, cols)}

    def _fake_connect(**kw):
        return _FakeConn(mapping)

    cfg = SupabaseConnConfig(
        dsn="postgres://u:p@h/db",
        checks=["supabase.security_definer_view"],
    )
    result = run(cfg, connector=_fake_connect)
    f = result.sarif["_supabase_findings"][0]
    assert f.rule_id == "supabase.security_definer_view"
    assert f.severity == "high"
    assert "public.user_lookup" in f.message


def test_run_handles_auth_users_exposed_critical():
    _ensure_psycopg_importable()
    rows = [("public", "v_user_profile")]
    cols = ["schema_name", "view_name"]
    mapping = {"src.relname = 'users'": (rows, cols)}

    def _fake_connect(**kw):
        return _FakeConn(mapping)

    cfg = SupabaseConnConfig(
        dsn="postgres://u:p@h/db",
        checks=["supabase.auth_users_exposed"],
    )
    result = run(cfg, connector=_fake_connect)
    f = result.sarif["_supabase_findings"][0]
    assert f.severity == "critical"
    assert f.rule_id == "supabase.auth_users_exposed"


def test_run_no_results_returns_empty_findings():
    _ensure_psycopg_importable()
    cfg = SupabaseConnConfig(
        dsn="postgres://u:p@h/db",
        checks=["supabase.rls_disabled_in_public"],
    )

    def _fake_connect(**kw):
        return _FakeConn({})  # no mapping = empty cursor

    result = run(cfg, connector=_fake_connect)
    assert result.completed is True
    assert result.sarif["_supabase_findings"] == []


def test_run_connection_failure_redacts_password():
    """A connection error must not echo the password back in the failed-runner
    error string (which would leak via project board's failed-scanner note)."""
    _ensure_psycopg_importable()

    def _fake_connect(**kw):
        raise ConnectionError("FATAL: password authentication failed for user 'a' (pass: sUper-Sekret-99)")

    cfg = SupabaseConnConfig(
        host="db.example.com", port=5432, dbname="postgres",
        user="a", password="sUper-Sekret-99",
    )
    result = run(cfg, connector=_fake_connect)
    assert result.completed is False
    assert "sUper-Sekret-99" not in (result.error or "")
    assert "<REDACTED>" in (result.error or "")


def test_run_partial_failure_logs_but_returns_completed(capsys):
    """If one check's SQL fails (e.g. permission denied) but others succeed,
    the run reports completed=True and stderr-logs the failures."""
    _ensure_psycopg_importable()

    class _PartiallyFailingCursor(_FakeCursor):
        def execute(self, sql, *args):
            if "ILIKE '%security_definer%'" in sql:
                raise PermissionError("permission denied for table pg_rewrite")
            super().execute(sql, *args)

    class _PartialConn(_FakeConn):
        def cursor(self):
            return _PartiallyFailingCursor({"NOT c.relrowsecurity": (
                [("public", "users")], ["schema_name", "table_name"]
            )})

    def _fake_connect(**kw):
        return _PartialConn({})

    cfg = SupabaseConnConfig(
        dsn="postgres://u:p@h/db",
        checks=["supabase.rls_disabled_in_public", "supabase.security_definer_view"],
    )
    result = run(cfg, connector=_fake_connect)
    assert result.completed is True
    out = capsys.readouterr().err
    assert "security_definer_view" in out
    # The successful check still produced its finding.
    assert any(f.rule_id == "supabase.rls_disabled_in_public"
               for f in result.sarif["_supabase_findings"])


def test_run_all_checks_fail_returns_failed():
    """If every check errors out, surface that as a runner failure so the
    summary line marks the lane as failed."""
    _ensure_psycopg_importable()

    class _AlwaysFailingCursor(_FakeCursor):
        def execute(self, sql, *args):
            if sql.strip().upper().startswith("SET"):
                return
            raise PermissionError("denied")

    class _BadConn(_FakeConn):
        def cursor(self):
            return _AlwaysFailingCursor({})

    def _fake_connect(**kw):
        return _BadConn({})

    cfg = SupabaseConnConfig(dsn="postgres://u:p@h/db")
    result = run(cfg, connector=_fake_connect)
    assert result.completed is False
    assert "all checks failed" in (result.error or "")


# -- helpers ------------------------------------------------------------------


def test_build_conn_kwargs_prefers_dsn():
    cfg = SupabaseConnConfig(dsn="postgres://x", host="ignored", dbname="ignored",
                             user="ignored", password="ignored")
    kw = _build_conn_kwargs(cfg)
    assert kw["conninfo"] == "postgres://x"
    assert "host" not in kw


def test_build_conn_kwargs_discrete_fields():
    cfg = SupabaseConnConfig(host="h", port=6543, dbname="d", user="u",
                             password="p", sslmode="verify-full")
    kw = _build_conn_kwargs(cfg)
    assert kw["host"] == "h"
    assert kw["port"] == 6543
    assert kw["dbname"] == "d"
    assert kw["sslmode"] == "verify-full"
    assert kw["autocommit"] is False


def test_scrub_strips_password_and_dsn():
    cfg = SupabaseConnConfig(dsn="postgres://x:y@z/db", password="y")
    msg = "auth failed (DSN postgres://x:y@z/db) for user; pw=y"
    out = _scrub(msg, cfg)
    assert "postgres://x:y@z/db" not in out
    assert "<REDACTED-DSN>" in out


# -- end-to-end via main._scan_supabase_live ---------------------------------


def test_main_supabase_lane_disabled_by_default(monkeypatch):
    """When cfg.supabase.enabled is False, _scan_supabase_live is a no-op
    and does not even try to import psycopg."""
    from security_scan.config import SupabaseConfig
    from security_scan.main import _scan_supabase_live

    cfg = MagicMock()
    cfg.supabase = SupabaseConfig(enabled=False)
    findings: list = []
    completed: list = []
    failed: list = []
    _scan_supabase_live(cfg, findings, completed, failed)
    assert findings == []
    assert completed == []
    assert failed == []


def test_main_supabase_lane_missing_env_yields_failed():
    from security_scan.config import SupabaseConfig
    from security_scan.main import _scan_supabase_live

    cfg = MagicMock()
    cfg.supabase = SupabaseConfig(enabled=True, url_env="NEVER_EXISTS_VAR_xyz")
    findings: list = []
    completed: list = []
    failed: list = []
    _scan_supabase_live(cfg, findings, completed, failed)
    assert ("supabase_live", pytest.approx) != failed
    assert len(failed) == 1
    assert failed[0][0] == "supabase_live"
    assert "env var" in failed[0][1].lower() or "unset" in failed[0][1].lower()
