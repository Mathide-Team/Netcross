#!/usr/bin/env bash
# build-rpm/build.sh -- construit le paquet .rpm de netcross (Rocky 8/9,
# RHEL et derives).
#
# Comme pour build-deb/, le code source (src/) vit a la racine du depot :
# ce script assemble un tarball "netcross-<version>.tar.gz" avec la
# structure attendue par netcross.spec, prepare une arborescence
# rpmbuild locale (pas besoin d'installer dans le HOME de l'utilisateur),
# et lance rpmbuild dedans.
#
# Prerequis : rpm-build (dnf install rpm-build ; sur Debian/Ubuntu pour
# tester en croise : apt-get install rpm)
#
# Usage : ./build-rpm/build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Issue #939 : la version vient de pyproject.toml (source unique), comme pour
# le .deb via debian/changelog -- en dur ici, chaque bump cassait le build
# (tarball netcross-<ancienne>.tar.gz introuvable pour le spec à jour).
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO_ROOT/pyproject.toml" | head -1)"
[ -n "$VERSION" ] || { echo "version introuvable dans $REPO_ROOT/pyproject.toml" >&2; exit 1; }
STAGE_DIR="$SCRIPT_DIR/_build/netcross-${VERSION}"
TOPDIR="$SCRIPT_DIR/_build/rpmbuild"

echo "=== netcross : construction du paquet .rpm ==="

rm -rf "$SCRIPT_DIR/_build"
mkdir -p "$STAGE_DIR"
mkdir -p "$TOPDIR"/{SOURCES,SPECS,BUILD,RPMS,SRPMS,BUILDROOT}

cp -r "$REPO_ROOT/src/pcap_parser" "$STAGE_DIR/"
cp -r "$REPO_ROOT/src/netcross_core" "$STAGE_DIR/"
cp -r "$REPO_ROOT/src/netcross_report" "$STAGE_DIR/"
cp -r "$REPO_ROOT/src/netcross_gtk4" "$STAGE_DIR/"
cp -r "$REPO_ROOT/src/netcross_api" "$STAGE_DIR/"
cp -r "$REPO_ROOT/src/netcross_ai" "$STAGE_DIR/"
cp "$REPO_ROOT/src/cross_capture_analyzer_cli.py" "$STAGE_DIR/"
cp "$REPO_ROOT/src/cross_capture_diff_cli.py" "$STAGE_DIR/"
cp "$REPO_ROOT/src/cross_history_cli.py" "$STAGE_DIR/"
cp "$REPO_ROOT/src/cross_capture_batch_cli.py" "$STAGE_DIR/"
cp "$REPO_ROOT/src/netcross_ai_models_cli.py" "$STAGE_DIR/"
cp "$REPO_ROOT/src/netcross_lua_doc_cli.py" "$STAGE_DIR/"
cp "$REPO_ROOT/src/netcross_annotations_cli.py" "$STAGE_DIR/"
mkdir -p "$STAGE_DIR/data"
cp "$REPO_ROOT/data/lua_api.json" "$STAGE_DIR/data/"
cp "$REPO_ROOT/data/lua_dissectors.csv" "$STAGE_DIR/data/"
# catalogues de traduction (issue #299), toutes les locales de lang/LINGUAS
"$REPO_ROOT/scripts/i18n-update.sh" --compile "$STAGE_DIR/locale"
cp "$SCRIPT_DIR/wrappers/netcross-wrapper" "$STAGE_DIR/"
cp "$SCRIPT_DIR/wrappers/netcross-gui-wrapper" "$STAGE_DIR/"
cp "$SCRIPT_DIR/wrappers/netcross-diff-wrapper" "$STAGE_DIR/"
cp "$SCRIPT_DIR/wrappers/netcross-history-wrapper" "$STAGE_DIR/"
cp "$SCRIPT_DIR/wrappers/netcross-batch-wrapper" "$STAGE_DIR/"
cp "$SCRIPT_DIR/wrappers/netcross-ai-models-wrapper" "$STAGE_DIR/"
cp "$SCRIPT_DIR/wrappers/netcross-lua-doc-wrapper" "$STAGE_DIR/"

find "$STAGE_DIR" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

tar czf "$TOPDIR/SOURCES/netcross-${VERSION}.tar.gz" -C "$SCRIPT_DIR/_build" "netcross-${VERSION}"
cp "$SCRIPT_DIR/netcross.spec" "$TOPDIR/SPECS/"

rpmbuild --define "_topdir $TOPDIR" -bb "$TOPDIR/SPECS/netcross.spec"

mkdir -p "$SCRIPT_DIR/dist"
find "$TOPDIR/RPMS" -name "*.rpm" -exec cp {} "$SCRIPT_DIR/dist/" \;

echo ""
echo "=== Paquet(s) genere(s) dans build-rpm/dist/ ==="
ls -la "$SCRIPT_DIR/dist/"
echo ""
echo "Installation : sudo dnf install ./build-rpm/dist/netcross-${VERSION}-*.rpm"
