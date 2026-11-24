#!/usr/bin/env bash
# Runtime contract for a built scanner image, on whatever platform it runs on.
#
#   tests/image/run.sh <image> [--platform linux/amd64|linux/arm64]
#
# Runs the image's own `python -m security_scan` against a synthetic fixture
# repo (tests/image/fixture) with every lane enabled, replacing only the
# GitHub client (tests/image/harness.py):
#   ok       -> exit 0, all six lanes complete, issues filed
#   fail401  -> exit 4 (project lookup rejected)
#   fail403  -> exit 4 (issue creation rejected, the "token lacks repo" case)
#   extra    -> exit 0 with config-extra.yaml: the opt-in semgrep_extra_rules
#               file is loaded, its rule is active and it produces a finding;
#               the default config must not mention extra rules at all
# plus a black-box run of the unmodified ENTRYPOINT with an invalid token
# against the real GitHub API -> exit 4.
#
# Only meaningful on a native host for the platform: under QEMU some Go tools
# fault inside their runtime, which is an emulator artefact, not an image bug.
set -uo pipefail
img=${1:?usage: run.sh <image> [--platform P]}; shift
plat=(); [ "${1:-}" = "--platform" ] && plat=(--platform "$2")
here=$(cd "$(dirname "$0")" && pwd)
# Under Docker Desktop/Colima only some host paths are shared with the VM; point
# TMPDIR at one of them (e.g. under $HOME) when running locally.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/image-test.XXXXXX"); chmod 755 "$tmp"; trap 'rm -rf "$tmp"' EXIT
fail=0
lanes="gitleaks, osv, semgrep, syft, trivy, trufflehog"

work() {  # fresh writable copy of the fixture as a git repo, owned by uid 1000
  rm -rf "$tmp/w"; cp -R "$here/fixture" "$tmp/w"
  git -C "$tmp/w" init -q && git -C "$tmp/w" add -A \
    && git -C "$tmp/w" -c user.email=ci@example.invalid -c user.name=ci commit -qm fixture
  chmod -R a+rwX "$tmp/w"
}

check() {  # check <name> <want-rc> <got-rc> <log> [require-all-lanes]
  local name=$1 want=$2 got=$3 log=$4 all=${5:-}
  local ok=1
  [ "$got" = "$want" ] || ok=0
  if [ -n "$all" ] && ! grep -qF "scanners completed: $lanes" "$log"; then ok=0; fi
  if [ $ok = 1 ]; then echo "PASS $name (exit $got)"; else
    echo "FAIL $name: want exit $want${all:+ with all lanes}, got $got"; sed 's/^/    /' "$log"; fail=1; fi
}

uname_m=$(docker run --rm "${plat[@]}" --entrypoint uname "$img" -m)
echo "image $img: container arch $uname_m"

for mode in ok fail401 fail403; do
  work
  docker run --rm "${plat[@]}" -e MODE=$mode -e GITHUB_TOKEN=fake \
    -v "$here/config.yaml:/config/config.yaml:ro" -v "$here/harness.py:/harness.py:ro" -v "$tmp/w:/work" \
    --entrypoint python "$img" /harness.py >"$tmp/$mode.log" 2>&1
  rc=$?
  case $mode in ok) check "$mode" 0 $rc "$tmp/$mode.log" all ;; *) check "$mode" 4 $rc "$tmp/$mode.log" ;; esac
done

# Opt-in extra Semgrep rules (and their absence by default).
if grep -q "semgrep: extra rules" "$tmp/ok.log"; then
  echo "FAIL default config mentions extra rules"; fail=1
else
  echo "PASS default config loads no extra rules"
fi
work
docker run --rm "${plat[@]}" -e MODE=ok -e GITHUB_TOKEN=fake \
  -v "$here/config-extra.yaml:/config/config.yaml:ro" -v "$here/harness.py:/harness.py:ro" -v "$tmp/w:/work" \
  --entrypoint python "$img" /harness.py >"$tmp/extra.log" 2>&1
rc=$?
check extra 0 $rc "$tmp/extra.log" all
if grep -q "semgrep: extra rules demo.yaml: 1/1 rules active" "$tmp/extra.log" \
   && grep "^HARNESS issue:" "$tmp/extra.log" | grep -q "image-test-shell-true"; then
  echo "PASS extra rule loaded and produced its finding"
else
  echo "FAIL extra rule not active or no finding"; sed 's/^/    /' "$tmp/extra.log"; fail=1
fi

work
docker run --rm "${plat[@]}" -e GITHUB_TOKEN=invalid-token-for-image-test \
  -v "$here/config.yaml:/config/config.yaml:ro" -v "$tmp/w:/work" "$img" --repo-dir /work >"$tmp/bb.log" 2>&1
check "entrypoint+invalid-token" 4 $? "$tmp/bb.log"

exit $fail
