#!/usr/bin/env bash
# Installs the talkbawt skill for Claude Code.
#   ./skill/install.sh            -> ~/.claude/skills/talkbawt   (all projects)
#   ./skill/install.sh --project  -> ./.claude/skills/talkbawt   (this repo only)
set -euo pipefail

src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/talkbawt"
dest="$HOME/.claude/skills/talkbawt"
[[ "${1:-}" == "--project" ]] && dest=".claude/skills/talkbawt"

mkdir -p "$(dirname "$dest")"
cp -r "$src/." "$dest/"
echo "Installed talkbawt skill -> $dest"
echo
echo "For Codex / Cursor / other agents, append skill/AGENTS.md to the project's AGENTS.md:"
echo "  cat skill/AGENTS.md >> AGENTS.md"
