#!/usr/bin/env bash
# Install (or update) the secscan Claude Code skill.
#
# Copies this directory to ~/.claude/skills/secscan/ — or to $CLAUDE_SKILLS_DIR
# if that env var is set (CC honors a couple of locations; consult `cc --help`
# if your install puts skills elsewhere).
#
# Re-running this is safe: existing files are overwritten with the latest copy
# from the security-scanner repo. The user's $SECSCAN_HOME (where the scanner
# tooling itself lives) is unaffected.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_BASE="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
DEST="$DEST_BASE/secscan"

mkdir -p "$DEST_BASE"
if [[ -d "$DEST" ]]; then
  echo "updating existing skill at $DEST"
else
  echo "installing skill to $DEST"
fi

# rsync if available (preserves timestamps cleanly); fall back to cp -R.
if command -v rsync >/dev/null; then
  rsync -a --delete --exclude install.sh "$HERE/" "$DEST/"
else
  rm -rf "$DEST"
  mkdir -p "$DEST"
  cp -R "$HERE/SKILL.md" "$HERE/references" "$DEST/"
fi

echo "done."
echo
echo "Make sure these env vars are set in your shell so the skill can find the scanner:"
echo "  export SECSCAN_HOME=$(cd "$HERE/.." && pwd)"
echo "  # optionally: export SECSCAN_CONFIG_DIR=/path/to/per-project/config"
