#!/usr/bin/env bash
# build-deb/build.sh -- construit le paquet .deb de netcross.
#
# Le code source (src/) vit a la racine du depot, separement de
# build-deb/ : ce script assemble une arborescence de build temporaire
# (_build/) qui reunit src/, debian/ et les wrappers, lance
# dpkg-buildpackage dedans, puis recupere le .deb resultant.
#
# Prerequis : debhelper, dpkg-dev, gettext (apt-get install debhelper dpkg-dev gettext)
#
# Usage : ./build-deb/build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/_build"

echo "=== netcross : construction du paquet .deb ==="

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cp -r "$REPO_ROOT/src" "$BUILD_DIR/src"
# API Lua Wireshark pour netcross-lua-doc (issues #386/#388)
mkdir -p "$BUILD_DIR/data"
cp "$REPO_ROOT/data/lua_api.json" "$BUILD_DIR/data/"
cp "$REPO_ROOT/data/lua_dissectors.csv" "$BUILD_DIR/data/"
cp -r "$SCRIPT_DIR/debian" "$BUILD_DIR/debian"
cp -r "$SCRIPT_DIR/wrappers" "$BUILD_DIR/wrappers"

# catalogues de traduction (issue #299) : toutes les locales de lang/LINGUAS,
# installees dans /usr/share/locale/<locale>/LC_MESSAGES/netcross.mo
"$REPO_ROOT/scripts/i18n-update.sh" --compile "$BUILD_DIR/locale"

# nettoyage des residus de compilation Python eventuellement presents
find "$BUILD_DIR/src" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

cd "$BUILD_DIR"
dpkg-buildpackage -us -uc -b

# dpkg-buildpackage depose le .deb dans le parent de BUILD_DIR (convention
# Debian : a cote du repertoire source, pas dedans)
mkdir -p "$SCRIPT_DIR/dist"
mv "$SCRIPT_DIR"/netcross_*.deb "$SCRIPT_DIR/dist/" 2>/dev/null || \
    mv "$BUILD_DIR"/../netcross_*.deb "$SCRIPT_DIR/dist/" 2>/dev/null || true

echo ""
echo "=== Paquet(s) genere(s) dans build-deb/dist/ ==="
ls -la "$SCRIPT_DIR/dist/"
echo ""
echo "Installation : sudo apt install ./build-deb/dist/netcross_*.deb"
