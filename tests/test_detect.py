from pathlib import Path

from secscan.detect import ScannerTarget, detect_stack

ALL_ON = {"osv": True, "gitleaks": True, "semgrep": True}


def _touch(p: Path, content: str = "") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def _scanners(r, name: str) -> list[ScannerTarget]:
    return [t for t in r.targets if t.scanner == name]


def _ecosystems(r) -> list[str]:
    return [t.ecosystem for t in _scanners(r, "osv")]


def test_empty_repo(tmp_path):
    r = detect_stack(tmp_path, ALL_ON)
    assert _scanners(r, "osv") == []
    assert _scanners(r, "semgrep") == []  # no source files
    # gitleaks runs whole-tree even on an empty dir — that's fine; it just emits nothing.
    assert len(_scanners(r, "gitleaks")) == 1


def test_npm_monorepo(tmp_path):
    for sub in ("", "frontend", "services/api"):
        d = tmp_path / sub if sub else tmp_path
        _touch(d / "package.json", "{}")
        _touch(d / "package-lock.json", "{}")
    _touch(tmp_path / "frontend" / "app.js", "console.log(1)")

    r = detect_stack(tmp_path, ALL_ON)
    osv = _scanners(r, "osv")
    assert len(osv) == 3
    assert all(t.ecosystem == "npm" for t in osv)
    assert {str(t.targets[0].relative_to(tmp_path)) for t in osv} == {
        ".", "frontend", "services/api"
    }
    assert len(_scanners(r, "gitleaks")) == 1
    assert len(_scanners(r, "semgrep")) == 1


def test_yarn_pnpm_distinct_ecosystems(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    _touch(a / "package.json", "{}")
    _touch(a / "yarn.lock", "")
    _touch(b / "package.json", "{}")
    _touch(b / "pnpm-lock.yaml", "")

    r = detect_stack(tmp_path, ALL_ON)
    ecos = sorted(_ecosystems(r))
    assert ecos == ["pnpm", "yarn"]


def test_multiple_ecosystems_same_repo(tmp_path):
    # npm
    _touch(tmp_path / "js" / "package.json", "{}")
    _touch(tmp_path / "js" / "package-lock.json", "{}")
    # pip
    _touch(tmp_path / "py" / "requirements.txt", "")
    # go
    _touch(tmp_path / "gosvc" / "go.mod", "module x")
    _touch(tmp_path / "gosvc" / "go.sum", "")
    # cargo
    _touch(tmp_path / "rs" / "Cargo.lock", "")
    # swiftpm
    _touch(tmp_path / "ios" / "Package.resolved", "")
    # rubygems
    _touch(tmp_path / "rb" / "Gemfile.lock", "")
    # a source file so semgrep triggers
    _touch(tmp_path / "py" / "main.py", "print(1)")

    r = detect_stack(tmp_path, ALL_ON)
    osv = _scanners(r, "osv")
    assert len(osv) == 6
    assert sorted(t.ecosystem for t in osv) == [
        "cargo", "go", "npm", "pip", "rubygems", "swiftpm",
    ]
    assert len(_scanners(r, "gitleaks")) == 1
    assert len(_scanners(r, "semgrep")) == 1


def test_exclude_directory_prefix(tmp_path):
    _touch(tmp_path / "archive" / "legacy" / "package.json", "{}")
    _touch(tmp_path / "archive" / "legacy" / "package-lock.json", "{}")
    _touch(tmp_path / "live" / "package.json", "{}")
    _touch(tmp_path / "live" / "package-lock.json", "{}")

    r = detect_stack(tmp_path, ALL_ON, exclude=["archive/"])
    osv = _scanners(r, "osv")
    assert len(osv) == 1
    assert "archive" not in str(osv[0].targets[0])


def test_exclude_glob(tmp_path):
    _touch(tmp_path / "third_party" / "vendor" / "lib" / "package.json", "{}")
    _touch(tmp_path / "third_party" / "vendor" / "lib" / "package-lock.json", "{}")
    _touch(tmp_path / "app" / "package.json", "{}")
    _touch(tmp_path / "app" / "package-lock.json", "{}")

    r = detect_stack(tmp_path, ALL_ON, exclude=["**/vendor/**", "vendor"])
    osv = _scanners(r, "osv")
    assert len(osv) == 1
    assert "vendor" not in str(osv[0].targets[0])


def test_node_modules_always_skipped(tmp_path):
    _touch(tmp_path / "node_modules" / "pkg" / "package.json", "{}")
    _touch(tmp_path / "node_modules" / "pkg" / "package-lock.json", "{}")
    r = detect_stack(tmp_path, ALL_ON)
    assert _scanners(r, "osv") == []


def test_disabled_scanner_creates_note(tmp_path):
    _touch(tmp_path / "package.json", "{}")
    _touch(tmp_path / "package-lock.json", "{}")
    r = detect_stack(tmp_path, {"osv": False, "gitleaks": True, "semgrep": True})
    assert _scanners(r, "osv") == []
    assert any("npm" in n and "osv" in n for n in r.detected_no_scanner)


def test_semgrep_skipped_when_no_source(tmp_path):
    _touch(tmp_path / "Gemfile.lock", "")
    r = detect_stack(tmp_path, ALL_ON)
    assert _scanners(r, "semgrep") == []
    # osv-rubygems still fires
    assert _ecosystems(r) == ["rubygems"]


def test_unknown_ecosystem_adds_note(tmp_path):
    _touch(tmp_path / "pom.xml", "<project/>")
    r = detect_stack(tmp_path, ALL_ON)
    assert any("Java/Maven" in n for n in r.detected_no_scanner)


def test_deterministic_ordering(tmp_path):
    _touch(tmp_path / "b" / "package.json", "{}")
    _touch(tmp_path / "b" / "package-lock.json", "{}")
    _touch(tmp_path / "a" / "package.json", "{}")
    _touch(tmp_path / "a" / "package-lock.json", "{}")
    _touch(tmp_path / "a" / "app.js", "x=1")

    r1 = detect_stack(tmp_path, ALL_ON)
    r2 = detect_stack(tmp_path, ALL_ON)
    def sig(r):
        return [(t.scanner, t.ecosystem, str(t.targets[0])) for t in r.targets]
    assert sig(r1) == sig(r2)
    # And the OSV pair is sorted by relpath: 'a' before 'b'.
    osv_paths = [str(t.targets[0].relative_to(tmp_path)) for t in _scanners(r1, "osv")]
    assert osv_paths == ["a", "b"]
