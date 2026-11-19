#!/usr/bin/env sh
# npc-fingerprint installer. User-level only: it never calls sudo and never writes outside your home directory.
#
#   ./install.sh             install (pipx, else uv, else a private virtualenv) and run `npc-fingerprint setup`
#   ./install.sh --no-setup  install only
#   ./install.sh --dry-run   print what would happen
#   ./install.sh --uninstall remove what this script installed (data in ~/.local/share/npc-fingerprint is kept)
#
# Environment (for CI/testing): NPC_INSTALL_PIP_ARGS and NPC_INSTALL_VENV_ARGS add arguments to the pip / venv steps.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DRY=0; SETUP=1; UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --no-setup) SETUP=0 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
run() { say "+ $*"; if [ "$DRY" = 0 ]; then "$@"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/npc-fingerprint"
BIN_DIR="$HOME/.local/bin"
VENV="$DATA_HOME/venv"

if [ "$UNINSTALL" = 1 ]; then
  have pipx && run pipx uninstall npc-fingerprint || true
  have uv && run uv tool uninstall npc-fingerprint || true
  run rm -f "$BIN_DIR/npc-fingerprint" "$BIN_DIR/npcf"
  run rm -rf "$VENV"
  say "Removed. Downloaded data and caches remain under $DATA_HOME (delete it to reclaim space)."
  exit 0
fi

# --- Python 3.11+ -------------------------------------------------------------------------------------------
PY=""
for c in python3 python; do
  if have "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  say "error: Python 3.11 or newer is required (found: $(python3 --version 2>&1 || echo none))." >&2
  say "       Kali/Debian: it ships with Python 3.11+; otherwise install it with your package manager or https://www.python.org." >&2
  exit 1
fi

# --- install: pipx > uv > private venv ---------------------------------------------------------------------------
if have pipx && [ -z "${NPC_INSTALL_PIP_ARGS:-}" ]; then
  say "Installing with pipx (isolated environment, recommended on Kali)."
  run pipx install --force "$HERE"
  METHOD=pipx
elif have uv && [ -z "${NPC_INSTALL_PIP_ARGS:-}" ]; then
  say "Installing with uv."
  run uv tool install --force "$HERE"
  METHOD=uv
else
  say "Installing into a private virtualenv at $VENV (no pipx/uv found)."
  run mkdir -p "$DATA_HOME" "$BIN_DIR"
  # shellcheck disable=SC2086
  run "$PY" -m venv ${NPC_INSTALL_VENV_ARGS:-} "$VENV"
  # shellcheck disable=SC2086
  run "$VENV/bin/python" -m pip install --upgrade ${NPC_INSTALL_PIP_ARGS:-} "$HERE"
  run ln -sf "$VENV/bin/npc-fingerprint" "$BIN_DIR/npc-fingerprint"
  run ln -sf "$VENV/bin/npcf" "$BIN_DIR/npcf"
  METHOD=venv
fi

# --- PATH hint -------------------------------------------------------------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say ""; say "Add ~/.local/bin to your PATH (once):"; say "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc   # or ~/.zshrc"; [ "$METHOD" = pipx ] && say "    (or run: pipx ensurepath)" ;;
esac

# --- first-run setup: user-level Chromium + databases --------------------------------------------------------------------
if [ "$SETUP" = 1 ]; then
  say ""
  say "Running first-time setup (Chromium for JavaScript rendering + CVE/fingerprint data)..."
  if [ "$DRY" = 1 ]; then say "+ npc-fingerprint setup"; else
    if have npc-fingerprint; then npc-fingerprint setup || say "Setup reported warnings; re-run later with: npc-fingerprint setup"
    elif [ -x "$BIN_DIR/npc-fingerprint" ]; then "$BIN_DIR/npc-fingerprint" setup || say "Setup reported warnings; re-run later with: npc-fingerprint setup"
    else say "Open a new shell (so PATH updates) and run: npc-fingerprint setup"; fi
  fi
fi
say ""
say "Done. Try: npc-fingerprint -u https://example.com"
