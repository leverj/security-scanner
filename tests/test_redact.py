"""Tests for security_scan.redact — covers each known-token pattern, the
entropy heuristic, and the local-URL classifier."""

from __future__ import annotations

import pytest

from security_scan.redact import is_local_url, redact_obj, redact_text

# -- token-shape patterns ------------------------------------------------------


# Tokens are assembled at runtime so the source file itself does not contain
# the literal prefix shapes — otherwise GitHub push protection flags them.
@pytest.mark.parametrize(
    "raw,label",
    [
        ("creds AKIAIOSFODNN7EXAMPLE end",     "<REDACTED:aws-key>"),
        ("session ASIAY34FZKBOKMUTVV7A end",   "<REDACTED:aws-key>"),
        ("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  "<REDACTED:github-token>"),
        ("github_pat_" + "A" * 80,             "<REDACTED:github-pat>"),
        ("sk" + "_live_abcdefghijklmnopqrstuvwx",   "<REDACTED:stripe-key>"),
        ("xox" + "b-123456789012-abcdefghijklmnop", "<REDACTED:slack-token>"),
        ("AIza" + "SyAbcdefghijklmnopqrstuvwxyz0123456",  "<REDACTED:google-api-key>"),
        ("sk-" + "proj_abcdef0123456789abcdef0123",  "<REDACTED:llm-api-key>"),
    ],
)
def test_known_token_shapes(raw, label):
    out = redact_text(raw)
    assert label in out, f"{raw!r} → {out!r}"
    # The original token must not survive.
    secret = raw.split()[1] if " " in raw else raw
    assert secret not in out


def test_jwt_redaction():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJKb2huIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    out = redact_text(f"Authorization: Bearer {jwt}")
    assert "<REDACTED:jwt>" in out
    assert jwt not in out


def test_pem_block_redaction():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redact_text(f"# config\nkey={pem}\n# end")
    assert "<REDACTED:pem-key>" in out
    assert "MIIEpAIBAAKCAQEA" not in out


def test_assignment_shapes():
    cases = [
        'api_key = "sometokenvalueWith16chars"',
        "API_KEY=longvalueXXXXXXXXXXXXXXX",
        'password: "supersecret_password_123"',
        "BEARER_TOKEN = abcdefghijklmnopqrstuvwxyz",
    ]
    for raw in cases:
        out = redact_text(raw)
        assert "<REDACTED:" in out, f"no redaction in {raw!r} → {out!r}"


# -- entropy heuristic ---------------------------------------------------------


def test_high_entropy_redacted():
    # 32 chars of high-entropy random data.
    blob = "f4Z7q2pHk8wT3sNcRy9LbVxJgQmDeAo5"
    out = redact_text(f"const tok = '{blob}';")
    assert "<REDACTED:high-entropy>" in out
    assert blob not in out


def test_low_entropy_identifier_survives():
    identifier = "internationalization_module_v2_handler"
    out = redact_text(f"function {identifier}() {{}}")
    assert identifier in out, out


def test_short_token_not_redacted():
    # Below the 20-char minimum — let it through.
    out = redact_text("var x = 'abc123XYZ';")
    assert "abc123XYZ" in out


# -- redact_obj recursion ------------------------------------------------------


def test_redact_obj_walks_nested():
    obj = {
        "rule_id": "secret.aws-key",
        "extra": {
            "snippet": "AKIAIOSFODNN7EXAMPLE",
            "ok": True,
            "nested": ["plain text", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        },
    }
    red = redact_obj(obj)
    assert red["rule_id"] == "secret.aws-key"
    assert "<REDACTED:aws-key>" in red["extra"]["snippet"]
    assert red["extra"]["ok"] is True
    assert "<REDACTED:github-token>" in red["extra"]["nested"][1]
    # Original untouched.
    assert "AKIAIOSFODNN7EXAMPLE" in obj["extra"]["snippet"]


def test_redact_text_handles_none_and_empty():
    assert redact_text(None) == ""
    assert redact_text("") == ""


# -- is_local_url --------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434",
        "http://127.0.0.1:11434",
        "http://[::1]:11434",
        "http://host.docker.internal:11434",
        "http://ollama.local",
        "http://10.0.0.5:11434",
        "http://192.168.1.10",
        "http://172.16.5.5:11434",
    ],
)
def test_local_urls(url):
    assert is_local_url(url) is True, url


@pytest.mark.parametrize(
    "url",
    [
        "http://1.2.3.4:11434",
        "https://api.openai.com",
        "https://ollama.example.com",
        "",
        None,
        "not a url",
    ],
)
def test_remote_urls(url):
    assert is_local_url(url) is False, url


# -- idempotency ---------------------------------------------------------------


def test_assignment_regex_matches_prefixed_names():
    """Codex review caught that AWS_SECRET_ACCESS_KEY and similar prefixed
    names didn't match the original `\\b`-anchored assignment regex because `_`
    is a word character. Permissive left-boundary now handles them."""
    cases = [
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdefghijkl12345678",
        "DB_PASSWORD = 'supersecret_password_123'",
        "JWT_SECRET: mySuperSecretValue123",
        '"apiKey": "secret_value_for_api"',
    ]
    for raw in cases:
        out = redact_text(raw)
        assert "<REDACTED:secret-like>" in out, f"missed: {raw!r} → {out!r}"


def test_database_url_credentials_redacted():
    cases = [
        "postgres://app:hunter2@db.internal:5432/myapp",
        "mongodb+srv://admin:somelongpassword@cluster0.example.com/db",
        "redis://:hunter2@cache:6379/0",
        "mysql://root:rootpw@localhost/test",
    ]
    for raw in cases:
        out = redact_text(raw)
        assert "<REDACTED:db-url-cred>" in out, raw
        # The password segment must not survive (sample values).
        for pw in ("hunter2", "somelongpassword", "rootpw"):
            if pw in raw:
                assert pw not in out, f"{pw} survived in {out!r}"


def test_hex_digest_redacted():
    """Hex blobs of 32+ chars (HMAC keys, session secrets) — entropy heuristic
    misses them because hex's per-char entropy ≤ 4."""
    cases = [
        "key=" + "a" * 32,  # 32 hex
        "deadbeefcafebabe0123456789abcdef",  # 32 hex
        "abc" + "0" * 64,  # 64 hex but with prefix so we hit the boundary correctly
        "1234567890abcdef1234567890abcdef12345678",  # 40 hex
    ]
    for raw in cases:
        out = redact_text(raw)
        # Either hex-digest OR secret-like (the `key=` form will catch some too)
        assert "<REDACTED:" in out, raw


def test_gitlab_and_stripe_webhook():
    # Prefixes split at runtime so the file itself doesn't contain literal
    # secret-shape prefixes (GitHub push protection flags those).
    raw = (
        "tokens: " + "glpat-" + "AbCdEfGhIj0123456789 and "
        + "whsec_" + "1234567890abcdef1234567890ab"
    )
    out = redact_text(raw)
    assert "<REDACTED:gitlab-token>" in out
    assert "<REDACTED:stripe-webhook>" in out


def test_azure_account_key():
    raw = "DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=" + "B" * 88 + "==;EndpointSuffix=core.windows.net"
    out = redact_text(raw)
    assert "<REDACTED:azure-key>" in out
    assert "B" * 88 not in out


def test_age_secret_key():
    raw = "key: AGE-SECRET-KEY-1" + "Q" * 58
    out = redact_text(raw)
    assert "<REDACTED:age-key>" in out


def test_redact_is_idempotent():
    raw = "key=AKIAIOSFODNN7EXAMPLE and token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    once = redact_text(raw)
    twice = redact_text(once)
    assert once == twice
