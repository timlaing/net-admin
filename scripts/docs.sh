#!/usr/bin/env bash
# Build (default) or serve the GitHub Pages documentation site.
#
# Canonical documents live at the repository root (README.md, MIGRATION.md,
# SECURITY.md, AGENTS.md, CONTRIBUTING.md, LICENSE); site-only pages live in
# docs/. This script stages everything into site-src/ (gitignored): root docs
# are renamed to stable site slugs and every in-repo link is rewritten to
# match. MkDocs then builds from site-src/ — nothing else is ever published.
#
# Local runs need the docs toolchain, e.g.:
#   pip install -r docs/requirements.txt && scripts/docs.sh serve
#   uvx --with-requirements docs/requirements.txt bash scripts/docs.sh build
set -euo pipefail

cd "$(dirname "$0")/.."

command -v mkdocs >/dev/null 2>&1 || {
  echo "mkdocs not found." >&2
  echo "  install:   pip install -r docs/requirements.txt" >&2
  echo "  ephemeral: uvx --with-requirements docs/requirements.txt bash scripts/docs.sh build" >&2
  exit 1
}

rm -rf site-src
mkdir -p site-src

# Redirect-based sed: portable across GNU and BSD sed (no -i flag).
stage() {
  sed -e 's|](MIGRATION\.md|](migration.md|g' \
      -e 's|](SECURITY\.md|](security.md|g' \
      -e 's|](AGENTS\.md|](development.md|g' \
      -e 's|](CONTRIBUTING\.md|](contributing.md|g' \
      -e 's|](README\.md|](index.md|g' \
      -e 's|](docs/|](|g' \
      "$1" > "$2"
}

stage README.md site-src/index.md
stage MIGRATION.md site-src/migration.md
stage SECURITY.md site-src/security.md
stage AGENTS.md site-src/development.md
stage CONTRIBUTING.md site-src/contributing.md
cp LICENSE site-src/LICENSE

# Site-only pages pass through the same link rewriting (names unchanged).
for page in docs/*.md; do
  stage "$page" "site-src/$(basename "$page")"
done

case "${1:-build}" in
  build)
    exec mkdocs build --strict
    ;;
  serve)
    exec mkdocs serve
    ;;
  *)
    echo "usage: $0 [build|serve]" >&2
    exit 2
    ;;
esac
