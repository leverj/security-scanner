from secscan.models import Finding, normalize_severity


def test_normalize_severity_from_security_severity_score():
    assert normalize_severity("warning", 9.8) == "critical"
    assert normalize_severity("warning", 7.5) == "high"
    assert normalize_severity("warning", 5.0) == "medium"
    assert normalize_severity("warning", 1.0) == "low"
    assert normalize_severity("warning", 0.0) == "info"


def test_normalize_severity_falls_back_to_level():
    assert normalize_severity("error") == "high"
    assert normalize_severity("warning") == "medium"
    assert normalize_severity("note") == "low"
    assert normalize_severity(None) == "info"
    assert normalize_severity("unknown") == "info"


def test_normalize_severity_ignores_unparseable_score():
    assert normalize_severity("error", "not-a-number") == "high"


def test_finding_meets_floor():
    f = Finding("s", "sast", "r", "medium", "f", 1, "t", "m")
    assert f.meets_floor("info")
    assert f.meets_floor("low")
    assert f.meets_floor("medium")
    assert not f.meets_floor("high")
    assert not f.meets_floor("critical")
