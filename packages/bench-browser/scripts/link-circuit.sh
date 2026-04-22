#!/usr/bin/env sh
# Copy the compiled circuit into public/ so Vite can serve it as a static
# asset. Run as `postinstall`. We copy (not symlink) so the artifact survives
# Docker `COPY` semantics where a relative symlink would dangle.
#
# The target may not exist yet on a fresh clone: in that case print a hint
# and skip; running `bun run circuit:compile` then re-running `bun install`
# (or this script directly) will populate it.

set -e
cd "$(dirname "$0")/.."

target="../../circuit/target/singpass_zk.json"
link="public/singpass_zk.json"

mkdir -p public

if [ ! -f "$target" ]; then
  echo "link-circuit: $target does not exist."
  echo "  Run \`bun run circuit:compile\` at the repo root, then re-run \`bun install\`."
  exit 0
fi

# Remove stale symlink (from previous installs that used `ln -sf`) so we
# don't accidentally cp into the symlink target.
rm -f "$link"
cp -f "$target" "$link"
echo "link-circuit: copied $target -> $link"
