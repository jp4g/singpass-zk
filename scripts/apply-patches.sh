#!/usr/bin/env bash
# Apply local patches to deps/mockpass. Idempotent: skips patches already applied.
# Bash-only — uses arrays + `shopt -s nullglob`. Don't switch the shebang to
# /bin/sh (busybox/dash will fail). Dockerfile.mockpass invokes the patch
# utility directly instead of sourcing this script.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUBMODULE="$REPO_ROOT/deps/mockpass"
PATCHES_DIR="$REPO_ROOT/patches"

if [ ! -d "$SUBMODULE/.git" ] && [ ! -f "$SUBMODULE/.git" ]; then
  echo "deps/mockpass is not initialized. Run: git submodule update --init --recursive" >&2
  exit 1
fi

shopt -s nullglob
patches=("$PATCHES_DIR"/*.patch)

if [ ${#patches[@]} -eq 0 ]; then
  echo "No patches to apply."
  exit 0
fi

for patch in "${patches[@]}"; do
  name="$(basename "$patch")"

  # Already applied if reversing the patch would apply cleanly.
  if git -C "$SUBMODULE" apply -R --check "$patch" >/dev/null 2>&1; then
    echo "  skip  $name (already applied)"
    continue
  fi

  # Not applied if forward apply would succeed.
  if git -C "$SUBMODULE" apply --check "$patch" >/dev/null 2>&1; then
    git -C "$SUBMODULE" apply "$patch"
    echo "  apply $name"
    continue
  fi

  echo "ERROR: $name does not apply cleanly and is not already applied." >&2
  git -C "$SUBMODULE" apply --check "$patch" || true
  exit 1
done
