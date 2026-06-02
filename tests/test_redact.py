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


def test_redact_is_idempotent():
    raw = "key=AKIAIOSFODNN7EXAMPLE and token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    once = redact_text(raw)
    twice = redact_text(once)
    assert once == twice
