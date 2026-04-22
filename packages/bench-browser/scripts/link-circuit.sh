#!/usr/bin/env sh
# Symlink the compiled circuit into public/ so Vite can serve it as a static
# asset. Run as `postinstall`. The target may not exist yet on a fresh clone:
# in that case print a hint and skip linking; running `bun run circuit:compile`
# at the repo root will produce the artifact, then `bun install` again or
# manually re-run this script will create the link.

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

ln -sf "../$target" "$link"
echo "link-circuit: $link -> $target"
