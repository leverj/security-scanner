"""Vendored Supabase Security Advisor lint queries.

These mirror the checks that Supabase Studio runs in its Security Advisor view.
Each entry has:
  - name      — stable id used as `rule_id` (prefixed `supabase.`)
  - severity  — Supabase's severity classification (critical/high/medium/low/info)
  - title     — one-line human label
  - sql       — read-only SELECT returning rows of the form documented per-check
  - row_map   — function (row, columns) -> dict of finding fields:
                  - identifier  (used in fingerprint; e.g. "public.users")
                  - file_path   (synthetic; usually `db://<schema>.<object>`)
                  - message     (one or two factual sentences)

Source references (Supabase docs / open-source advisor):
  https://supabase.com/docs/guides/database/database-advisors
  https://github.com/supabase/supabase/tree/master/apps/studio/lib/lint

Read-only contract: every query is a SELECT and must run cleanly under
`SET TRANSACTION READ ONLY`. The runner sets that flag before iterating.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class LintCheck:
    name: str
    severity: str
    title: str
    sql: str
    row_map: Callable[[tuple, list[str]], dict]


def _col(cols: list[str], row: tuple, name: str) -> object:
    """Look up `name` in the cursor's column description."""
    return row[cols.index(name)] if name in cols else None


# -- 1. RLS disabled on a public table ----------------------------------------

_RLS_DISABLED_SQL = """
SELECT n.nspname AS schema_name,
       c.relname AS table_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname IN ('public')
  AND NOT c.relrowsecurity
ORDER BY 1, 2;
"""

def _rls_disabled_map(row: tuple, cols: list[str]) -> dict:
    schema = _col(cols, row, "schema_name")
    table = _col(cols, row, "table_name")
    obj = f"{schema}.{table}"
    return {
        "identifier": obj,
        "file_path": f"db://{obj}",
        "message": (
            f"Table {obj} is in the `public` schema (exposed via PostgREST) "
            "but has Row Level Security disabled. Any role with USAGE on the "
            "schema can read/write all rows. Enable RLS and add policies."
        ),
    }


# -- 2. RLS enabled but no policies exist (table is locked from anon) ---------
# This is a low-severity correctness check: a policy-less RLS table is
# effectively inaccessible to anon/authenticated, which is often unintended.

_RLS_NO_POLICY_SQL = """
SELECT n.nspname AS schema_name,
       c.relname AS table_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_policy p ON p.polrelid = c.oid
WHERE c.relkind = 'r'
  AND n.nspname IN ('public')
  AND c.relrowsecurity
  AND p.polrelid IS NULL
GROUP BY 1, 2
ORDER BY 1, 2;
"""

def _rls_no_policy_map(row: tuple, cols: list[str]) -> dict:
    schema = _col(cols, row, "schema_name")
    table = _col(cols, row, "table_name")
    obj = f"{schema}.{table}"
    return {
        "identifier": obj,
        "file_path": f"db://{obj}",
        "message": (
            f"Table {obj} has RLS enabled but no policies — all queries from "
            "anon/authenticated will return zero rows. Likely a config gap: "
            "either add a SELECT/INSERT/UPDATE/DELETE policy or move the table "
            "out of the `public` schema."
        ),
    }


# -- 3. SECURITY DEFINER view (executes as creator, often a superuser) --------

_SECURITY_DEFINER_VIEW_SQL = """
SELECT n.nspname AS schema_name,
       c.relname AS view_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_rewrite r ON r.ev_class = c.oid
WHERE c.relkind IN ('v', 'm')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND pg_get_viewdef(c.oid) ILIKE '%security_definer%'
GROUP BY 1, 2
ORDER BY 1, 2;
"""

def _security_definer_view_map(row: tuple, cols: list[str]) -> dict:
    schema = _col(cols, row, "schema_name")
    view = _col(cols, row, "view_name")
    obj = f"{schema}.{view}"
    return {
        "identifier": obj,
        "file_path": f"db://{obj}",
        "message": (
            f"View {obj} is defined with SECURITY DEFINER. Queries through "
            "this view execute with the privileges of the view's creator "
            "(often `postgres`), bypassing RLS on the underlying tables. "
            "Verify the view's contents are safe to expose to anon."
        ),
    }


# -- 4. SECURITY DEFINER function without pinned search_path ------------------
# `SECURITY DEFINER` runs as the function owner; combined with a mutable
# `search_path`, an attacker who can create objects in any schema in the
# default search path can shadow built-in functions and escalate.

_SECDEF_FN_MUTABLE_SEARCH_PATH_SQL = """
SELECT n.nspname AS schema_name,
       p.proname AS function_name,
       pg_get_function_identity_arguments(p.oid) AS args
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND (
    p.proconfig IS NULL
    OR NOT EXISTS (
      SELECT 1 FROM unnest(p.proconfig) cfg
      WHERE cfg LIKE 'search_path=%'
    )
  )
ORDER BY 1, 2;
"""

def _secdef_fn_map(row: tuple, cols: list[str]) -> dict:
    schema = _col(cols, row, "schema_name")
    fn = _col(cols, row, "function_name")
    args = _col(cols, row, "args") or ""
    obj = f"{schema}.{fn}({args})"
    return {
        "identifier": obj,
        "file_path": f"db://{obj}",
        "message": (
            f"Function {obj} is SECURITY DEFINER but does not pin search_path. "
            "Add `SET search_path = pg_catalog, pg_temp` (or similar) to the "
            "function so an attacker can't shadow built-ins via a writable "
            "schema in the default search path."
        ),
    }


# -- 5. Anon/authenticated roles with broad schema USAGE ----------------------

_BROAD_ANON_USAGE_SQL = """
SELECT n.nspname AS schema_name,
       r.rolname AS role_name
FROM pg_namespace n,
     pg_roles r
WHERE r.rolname IN ('anon', 'authenticated')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND has_schema_privilege(r.oid, n.oid, 'USAGE')
  AND n.nspname NOT IN ('public', 'extensions', 'graphql', 'graphql_public',
                        'realtime', 'storage', 'auth', 'vault')
ORDER BY 1, 2;
"""

def _broad_anon_usage_map(row: tuple, cols: list[str]) -> dict:
    schema = _col(cols, row, "schema_name")
    role = _col(cols, row, "role_name")
    obj = f"{schema}:{role}"
    return {
        "identifier": obj,
        "file_path": f"db://schema:{schema}",
        "message": (
            f"Role `{role}` has USAGE on schema `{schema}`. Outside of the "
            "expected Supabase-managed schemas (public, auth, storage, etc.), "
            "this often means a private schema was accidentally exposed. "
            "REVOKE USAGE unless this is intentional."
        ),
    }


# -- 6. Materialized view in `public` (exposed via PostgREST but no RLS) ------

_MATERIALIZED_VIEW_IN_PUBLIC_SQL = """
SELECT n.nspname AS schema_name,
       c.relname AS view_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'm'
  AND n.nspname = 'public'
ORDER BY 1, 2;
"""

def _matview_map(row: tuple, cols: list[str]) -> dict:
    schema = _col(cols, row, "schema_name")
    view = _col(cols, row, "view_name")
    obj = f"{schema}.{view}"
    return {
        "identifier": obj,
        "file_path": f"db://{obj}",
        "message": (
            f"Materialized view {obj} is in `public` and therefore exposed via "
            "PostgREST. Materialized views do not support RLS — every anon/"
            "authenticated request can read all rows. Move to a non-public "
            "schema or wrap behind a SECURITY INVOKER view with RLS."
        ),
    }


# -- 7. auth.users column exposed via a view in public ------------------------

_AUTH_USERS_EXPOSED_SQL = """
SELECT n.nspname AS schema_name,
       c.relname AS view_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('v', 'm')
  AND n.nspname = 'public'
  AND EXISTS (
    SELECT 1 FROM pg_rewrite r
    JOIN pg_depend d ON d.objid = r.oid
    JOIN pg_class src ON src.oid = d.refobjid
    JOIN pg_namespace srcn ON srcn.oid = src.relnamespace
    WHERE r.ev_class = c.oid
      AND srcn.nspname = 'auth'
      AND src.relname = 'users'
  )
ORDER BY 1, 2;
"""

def _auth_users_exposed_map(row: tuple, cols: list[str]) -> dict:
    schema = _col(cols, row, "schema_name")
    view = _col(cols, row, "view_name")
    obj = f"{schema}.{view}"
    return {
        "identifier": obj,
        "file_path": f"db://{obj}",
        "message": (
            f"View {obj} references `auth.users` and is exposed via PostgREST. "
            "If it surfaces emails / encrypted_password / metadata, you may be "
            "leaking PII or auth material. Restrict the view to non-sensitive "
            "columns or move it out of `public`."
        ),
    }


# -- catalog ------------------------------------------------------------------

CHECKS: tuple[LintCheck, ...] = (
    LintCheck(
        name="supabase.rls_disabled_in_public",
        severity="high",
        title="Public table has Row Level Security disabled",
        sql=_RLS_DISABLED_SQL,
        row_map=_rls_disabled_map,
    ),
    LintCheck(
        name="supabase.policy_exists_rls_disabled",
        severity="low",
        title="Public table has RLS enabled but no policies",
        sql=_RLS_NO_POLICY_SQL,
        row_map=_rls_no_policy_map,
    ),
    LintCheck(
        name="supabase.security_definer_view",
        severity="high",
        title="View uses SECURITY DEFINER",
        sql=_SECURITY_DEFINER_VIEW_SQL,
        row_map=_security_definer_view_map,
    ),
    LintCheck(
        name="supabase.function_search_path_mutable",
        severity="medium",
        title="SECURITY DEFINER function has mutable search_path",
        sql=_SECDEF_FN_MUTABLE_SEARCH_PATH_SQL,
        row_map=_secdef_fn_map,
    ),
    LintCheck(
        name="supabase.role_usage_unexpected_schema",
        severity="medium",
        title="anon/authenticated role has USAGE on an unexpected schema",
        sql=_BROAD_ANON_USAGE_SQL,
        row_map=_broad_anon_usage_map,
    ),
    LintCheck(
        name="supabase.materialized_view_in_public",
        severity="high",
        title="Materialized view in `public` (no RLS support)",
        sql=_MATERIALIZED_VIEW_IN_PUBLIC_SQL,
        row_map=_matview_map,
    ),
    LintCheck(
        name="supabase.auth_users_exposed",
        severity="critical",
        title="Public view references `auth.users`",
        sql=_AUTH_USERS_EXPOSED_SQL,
        row_map=_auth_users_exposed_map,
    ),
)


def by_name(name: str) -> LintCheck | None:
    for c in CHECKS:
        if c.name == name:
            return c
    return None
