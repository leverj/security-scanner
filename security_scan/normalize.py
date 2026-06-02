"""SARIF -> Finding. One shape for all scanners; scanner-specific bits in extra.

For Trivy (multi-category) and Trufflehog (JSONL, not SARIF), this module
special-cases the parse path. The output shape is identical regardless.
"""

from __future__ import annotations

import fnmatch
import json
import sys
from fnmatch import fnmatchcase

from security_scan.models import Finding, normalize_severity

_CATEGORY = {
    "osv": "dependency",
    "gitleaks": "secret",
    "semgrep": "sast",
    "codex": "sast",
    "gemma": "sast",
}


def normalize_sarif(sarif: dict, scanner: str, exclude: list[str] | None = None) -> list[Finding]:
    """Parse a SARIF document into Findings. Drops results with no location."""
    exclude = exclude or []

    # Trufflehog uses JSONL, not SARIF — carried inside a wrapper dict.
    if scanner == "trufflehog":
        return _normalize_trufflehog(sarif, exclude)
    # Trivy multi-category SARIF.
    if scanner == "trivy":
        return _normalize_trivy(sarif, exclude)
    # Syft produces an SBOM artifact, not findings.
    if scanner == "syft":
        return []

    if scanner not in _CATEGORY:
        raise ValueError(f"unknown scanner: {scanner!r}")
    category = _CATEGORY[scanner]

    findings: list[Finding] = []
    for run in sarif.get("runs") or []:
        rules_by_id = _index_rules(run)
        for result in run.get("results") or []:
            f = _result_to_finding(result, scanner, category, rules_by_id)
            if f is None:
                continue
            if _is_excluded(f.file_path, exclude):
                continue
            findings.append(f)
    return findings


# ---- Trivy: multi-category SARIF ------------------------------------------

# Trivy stamps each rule with a "Type" property. Map the tags/types we see to
# our categories. Unknown ones fall back to "dependency" (most common).
_TRIVY_TYPE_TO_CATEGORY = {
    "vulnerability": "dependency",
    "secret": "secret",
    "misconfiguration": "iac",
    "license": "license",
}


def _normalize_trivy(sarif: dict, exclude: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for run in sarif.get("runs") or []:
        rules_by_id = _index_rules(run)
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or ""
            rule_def = rules_by_id.get(rule_id) or {}
            category = _trivy_category_for(rule_def, result)
            f = _result_to_finding(result, "trivy", category, rules_by_id)
            if f is None:
                continue
            if _is_excluded(f.file_path, exclude):
                continue
            findings.append(f)
    return findings


def _trivy_category_for(rule_def: dict, result: dict) -> str:
    """Inspect Trivy's rule properties to pick one of our categories."""
    props = {**(rule_def.get("properties") or {}), **(result.get("properties") or {})}
    rtype = (props.get("type") or "").lower()
    if rtype in _TRIVY_TYPE_TO_CATEGORY:
        return _TRIVY_TYPE_TO_CATEGORY[rtype]
    tags = props.get("tags") or []
    if isinstance(tags, list):
        lowered = {str(t).lower() for t in tags}
        if "secret" in lowered:
            return "secret"
        if "misconfiguration" in lowered or "iac" in lowered:
            return "iac"
        if "license" in lowered:
            return "license"
        if "vulnerability" in lowered or "cve" in lowered:
            return "dependency"
    # Heuristic: rule_id pattern (Trivy uses CVE-/GHSA-/AVD-/DS- prefixes)
    rid = (rule_def.get("id") or result.get("ruleId") or "").upper()
    if rid.startswith(("CVE-", "GHSA-")):
        return "dependency"
    if rid.startswith(("AVD-", "KSV", "DS")):
        return "iac"
    return "dependency"


# ---- Trufflehog: JSONL with verified-secret semantics ----------------------

def _normalize_trufflehog(wrapper: dict, exclude: list[str]) -> list[Finding]:
    """Parse the JSONL payload carried in runners.trufflehog's RunnerResult.sarif."""
    payload = wrapper.get("_trufflehog_jsonl")
    if not isinstance(payload, str) or not payload.strip():
        return []
    findings: list[Finding] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            print(f"normalize: skipping unparseable trufflehog line: {line[:80]!r}", file=sys.stderr)
            continue
        f = _trufflehog_obj_to_finding(obj)
        if f is None:
            continue
        if _is_excluded(f.file_path, exclude):
            continue
        findings.append(f)
    return findings


def _trufflehog_obj_to_finding(obj: dict) -> Finding | None:
    """One Trufflehog JSON record -> Finding.

    Verified secrets get severity=critical; unverified get severity=high.
    The raw secret is NEVER stored on the Finding; only Trufflehog's redacted
    form is exposed.
    """
    detector = obj.get("DetectorName") or obj.get("DetectorType") or "unknown"
    verified = bool(obj.get("Verified"))
    category = "secret-verified" if verified else "secret"

    meta = ((obj.get("SourceMetadata") or {}).get("Data") or {})
    # Trufflehog reports source under several keys depending on the scan type.
    src = meta.get("Filesystem") or meta.get("Git") or {}
    file_path = (src.get("file") or src.get("filename") or src.get("path") or "").replace("\\", "/")
    line = src.get("line")
    try:
        line = int(line) if line is not None else None
    except (TypeError, ValueError):
        line = None
    if not file_path:
        print(f"normalize: skipping trufflehog result {detector!r} (no path)", file=sys.stderr)
        return None

    # Build a deterministic secret_fingerprint from the redacted form + detector;
    # do NOT use the raw secret in any identity computation.
    redacted = (obj.get("Redacted") or "")
    raw_v2 = (obj.get("RawV2") or "")
    secret_fp = _trufflehog_fingerprint(detector, redacted or raw_v2 or "unknown")

    masked_preview = redacted or _mask(raw_v2 or "")
    severity = "critical" if verified else "high"

    rule_id = f"trufflehog/{detector}" + ("/verified" if verified else "")
    title = f"{rule_id}: {redacted or detector}"
    if len(title) > 200:
        title = title[:197] + "..."

    extra = {
        "detector": detector,
        "verified": verified,
        "secret_fingerprint": secret_fp,
    }
    return Finding(
        scanner="trufflehog",
        category=category,
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line=line,
        title=title,
        message=f"{detector} secret detected" + (" (VERIFIED LIVE)" if verified else ""),
        masked_preview=masked_preview,
        sarif_fingerprint=None,
        extra=extra,
    )


def _trufflehog_fingerprint(detector: str, key_material: str) -> str:
    """Deterministic per-(detector, redacted-value) hash. Used in Finding.extra
    so fingerprint.py's secret-category logic produces a stable fp."""
    import hashlib

    return hashlib.sha256(f"{detector}\0{key_material}".encode()).hexdigest()[:16]


def _mask(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if len(s) <= 6:
        return "•" * len(s)
    return f"{s[:2]}{'•' * (len(s) - 6)}{s[-4:]}"


def _index_rules(run: dict) -> dict[str, dict]:
    driver = (run.get("tool") or {}).get("driver") or {}
    out: dict[str, dict] = {}
    for rule in driver.get("rules") or []:
        rid = rule.get("id")
        if rid:
            out[rid] = rule
    return out


def _result_to_finding(
    result: dict, scanner: str, category: str, rules_by_id: dict[str, dict]
) -> Finding | None:
    rule_id = result.get("ruleId") or ""
    file_path, line, snippet_text = _first_location(result)
    if not file_path:
        print(
            f"normalize: skipping {scanner} result rule={rule_id!r} (no location)",
            file=sys.stderr,
        )
        return None

    rule_def = rules_by_id.get(rule_id) or {}
    sec_sev = _security_severity(result, rule_def)
    level = result.get("level")
    severity = normalize_severity(level, sec_sev)

    message_text = ((result.get("message") or {}).get("text") or "").strip()
    sarif_fp = _sarif_fingerprint(result)

    masked_preview = ""
    extra: dict = {}

    if scanner == "gitleaks":
        raw_secret = snippet_text or ""
        masked_preview = _mask_secret(raw_secret)
        # Prefer partialFingerprints value (already a hash); fall back to fingerprints.
        secret_fp = _any_value(result.get("partialFingerprints")) or _any_value(
            result.get("fingerprints")
        )
        if secret_fp:
            extra["secret_fingerprint"] = secret_fp
    elif scanner == "semgrep":
        if snippet_text:
            extra["snippet"] = snippet_text
    elif scanner == "osv":
        extra.update(_osv_extras(result, rule_def))

    title = _build_title(rule_id, message_text)

    return Finding(
        scanner=scanner,
        category=category,
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line=line,
        title=title,
        message=message_text,
        masked_preview=masked_preview,
        sarif_fingerprint=sarif_fp,
        extra=extra,
    )


def _first_location(result: dict) -> tuple[str, int | None, str]:
    locs = result.get("locations") or []
    if not locs:
        return "", None, ""
    phys = (locs[0] or {}).get("physicalLocation") or {}
    uri = ((phys.get("artifactLocation") or {}).get("uri") or "").replace("\\", "/")
    region = phys.get("region") or {}
    line = region.get("startLine")
    try:
        line = int(line) if line is not None else None
    except (TypeError, ValueError):
        line = None
    snippet_text = ((region.get("snippet") or {}).get("text") or "")
    return uri, line, snippet_text


def _security_severity(result: dict, rule_def: dict) -> str | float | None:
    props = result.get("properties") or {}
    if "security-severity" in props:
        return props["security-severity"]
    rprops = rule_def.get("properties") or {}
    if "security-severity" in rprops:
        return rprops["security-severity"]
    return None


def _sarif_fingerprint(result: dict) -> str | None:
    for key in ("fingerprints", "partialFingerprints"):
        fps = result.get(key)
        if not fps:
            continue
        values = [str(v) for v in fps.values() if v is not None]
        if values:
            return "|".join(values)
    return None


def _any_value(d: dict | None) -> str | None:
    if not d:
        return None
    for v in d.values():
        if v:
            return str(v)
    return None


def _mask_secret(raw: str) -> str:
    s = raw.strip()
    if not s:
        return ""
    if len(s) <= 6:
        return "•" * len(s)
    return f"{s[:2]}{'•' * (len(s) - 6)}{s[-4:]}"


def _osv_extras(result: dict, rule_def: dict) -> dict:
    props = {**(rule_def.get("properties") or {}), **(result.get("properties") or {})}
    out: dict = {}
    for key in ("ecosystem", "package", "installed_version"):
        if key in props:
            out[key] = props[key]
    fixed = props.get("fixed_versions")
    if fixed is not None:
        out["fixed_versions"] = list(fixed) if isinstance(fixed, (list, tuple)) else [fixed]
    aliases = props.get("aliases")
    if aliases is not None:
        out["aliases"] = list(aliases) if isinstance(aliases, (list, tuple)) else [aliases]
    return out


def _build_title(rule_id: str, message: str) -> str:
    head = (message.splitlines()[0] if message else "").strip()
    if len(head) > 80:
        head = head[:77].rstrip() + "..."
    if rule_id and head:
        return f"{rule_id}: {head}"
    return rule_id or head or "finding"


def _is_excluded(file_path: str, patterns: list[str]) -> bool:
    path = file_path.replace("\\", "/")
    for pat in patterns:
        p = pat.replace("\\", "/")
        if not p:
            continue
        if p.endswith("/"):
            if path.startswith(p) or path == p.rstrip("/"):
                return True
            continue
        if path.startswith(p):
            return True
        if any(ch in p for ch in "*?[") and (fnmatchcase(path, p) or fnmatch.fnmatch(path, p)):
            return True
    return False
