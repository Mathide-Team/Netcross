"""Tests de couverture de netcross_core/application/banners.py (issue #712, suite #665).

Complète tests/test_banners.py par les chemins rares, tous synthétiques
(octets fabriqués à la main, ni capture ni tshark) :

- HTTP : fin d'en-têtes en ``\\n\\n``, segment tronqué sans ligne vide,
  réponse sans ``Server``, requête sans ``User-Agent`` ou au seul jeton
  de compatibilité (``Mozilla``) ;
- SSH : préfixe ``SSH-`` sans version de protocole valide, ligne terminée par LF seul
  ou sans fin de ligne ;
- repli défensif de ``_http_banners`` (appel direct : inatteignable via ``extract_banners``) ;
- SMB1 : message trop court, commande hors Negotiate/Session Setup, sécurité
  étendue (blob avant les chaînes), chaînes ASCII/UTF-16 tronquées ;
- SMB2 : message court, commande ou sens non conforme, dialecte inconnu ;
- SMB : en-tête NetBIOS invalide, signature ni SMB1 ni SMB2.

Les charges utiles malformées doivent donner ``()`` sans lever (contrat de
``extract_banners``).
"""

from __future__ import annotations

import struct

import pytest

from netcross_core.application.banners import _http_banners, extract_banners


def _found(*args):
    return [(b.service, b.version, b.role) for b in extract_banners(*args)]


# -- HTTP ----------------------------------------------------------------------


def test_http_entetes_termines_par_lf_lf():
    payload = b"HTTP/1.1 200 OK\nServer: nginx/1.18.0\n\ncorps"
    assert _found("TCP", 80, 51000, payload) == [("nginx", "1.18.0", "server")]


def test_http_segment_tronque_sans_ligne_vide_lit_toute_la_charge():
    payload = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
    assert _found("TCP", 80, 51000, payload) == [("nginx", "1.18.0", "server")]


def test_http_reponse_sans_en_tete_server_ne_donne_rien():
    assert extract_banners("TCP", 80, 51000, b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n") == ()


def test_http_requete_sans_user_agent_ne_donne_rien():
    assert extract_banners("TCP", 51000, 80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") == ()


def test_http_requete_avec_user_agent_donne_un_client():
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n"
    assert _found("TCP", 51000, 80, payload) == [("curl", "7.68.0", "client")]


def test_http_user_agent_de_compatibilite_seul_ne_donne_rien():
    payload = b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n\r\n"
    assert extract_banners("TCP", 51000, 80, payload) == ()


# -- SSH -----------------------------------------------------------------------


def test_ssh_prefixe_sans_version_de_protocole_valide_ne_donne_rien():
    assert extract_banners("TCP", 22, 51000, b"SSH-garbage\r\n") == ()


@pytest.mark.parametrize("payload", [b"SSH-2.0-OpenSSH_8.2p1\nsuite", b"SSH-2.0-OpenSSH_8.2p1"])
def test_ssh_banniere_terminee_par_lf_seul_ou_sans_fin_de_ligne(payload):
    assert _found("TCP", 22, 51000, payload) == [("OpenSSH", "8.2p1", "server")]


# -- Garde defensive -----------------------------------------------------------


def test_http_banners_repli_defensif_hors_http():
    # extract_banners n'appelle _http_banners que pour "HTTP/1." ou une methode
    # HTTP ; le "return []" final est un filet de securite atteignable seulement
    # par appel direct, on le fige ici plutot que de le marquer no cover.
    assert _http_banners(b"\x16\x03\x03 pas du HTTP") == []


# -- SMB -----------------------------------------------------------------------


def _nbss(message: bytes) -> bytes:
    return b"\x00" + len(message).to_bytes(3, "big") + message


def _smb1(command, words=b"", data=b"", flags2=0x0000):
    header = b"\xffSMB" + bytes([command]) + b"\x00" * 4 + bytes([0x80]) + struct.pack("<H", flags2) + b"\x00" * 20
    assert len(header) == 32
    return _nbss(header + bytes([len(words) // 2]) + words + struct.pack("<H", len(data)) + data)


def _utf16(text):
    return text.encode("utf-16-le") + b"\x00\x00"


_WORDS_3 = b"\xff\x00\x00\x00\x00\x00"


def test_smb_entete_netbios_invalide_ne_donne_rien():
    assert extract_banners("TCP", 445, 50000, b"\x00\x00\x00") == ()  # trop court
    assert extract_banners("TCP", 445, 50000, b"\x85\x00\x00\x04" + b"\xffSMB") == ()  # type != 0


def test_smb_signature_ni_smb1_ni_smb2_ne_donne_rien():
    assert extract_banners("TCP", 445, 50000, _nbss(b"ABCDEFGH")) == ()


def test_smb1_message_trop_court_ne_donne_rien():
    assert extract_banners("TCP", 445, 50000, _nbss(b"\xffSMB" + b"\x00" * 20)) == ()


def test_smb1_commande_hors_negotiate_et_session_setup_ne_donne_rien():
    assert extract_banners("TCP", 445, 50000, _smb1(0x2B, b"\x00" * 2)) == ()


def test_smb1_session_setup_securite_etendue_saute_le_blob():
    words = b"\xff\x00\x00\x00" + b"\x00\x00" + struct.pack("<H", 4)  # 4 mots ; longueur du blob = 4 octets
    payload = _smb1(0x73, words, b"BLOB" + b"Unix\x00Samba 4.9.5\x00WG\x00")
    banners = extract_banners("TCP", 445, 50000, payload)
    assert [(b.service, b.version) for b in banners] == [("SMB", "1.0"), ("Samba", "4.9.5")]
    assert "NativeOS=Unix;" in banners[0].raw  # le blob "BLOB" n'est pas lu comme NativeOS


@pytest.mark.parametrize(
    ("data", "flags2"),
    [
        (b"Unix", 0x0000),  # NativeOS ASCII sans NUL final
        (b"Unix\x00Samba 4.9.5", 0x0000),  # NativeLanMan ASCII sans NUL final
        (b"\x00" + "Win".encode("utf-16-le"), 0x8000),  # NativeOS UTF-16 sans terminateur
        (b"\x00" + _utf16("Windows") + "Win".encode("utf-16-le"), 0x8000),  # NativeLanMan UTF-16 tronqué
    ],
)
def test_smb1_chaines_tronquees_donnent_un_resultat_vide_sans_lever(data, flags2):
    assert extract_banners("TCP", 445, 50000, _smb1(0x73, _WORDS_3, data, flags2)) == ()


def _smb2(command=0, flags=1, dialect=0x0311, length=None):
    msg = bytearray(b"\xfeSMB" + b"\x00" * 60)
    struct.pack_into("<H", msg, 12, command)
    struct.pack_into("<I", msg, 16, flags)
    msg += struct.pack("<HHH", 65, 1, dialect) + b"\x00" * 10
    return _nbss(bytes(msg if length is None else msg[:length]))


def test_smb2_message_trop_court_ne_donne_rien():
    assert extract_banners("TCP", 445, 50000, _smb2(length=69)) == ()


@pytest.mark.parametrize(("command", "flags"), [(1, 1), (0, 0)])  # autre commande ; requête (pas réponse)
def test_smb2_commande_ou_sens_non_conforme_ne_donne_rien(command, flags):
    assert extract_banners("TCP", 445, 50000, _smb2(command=command, flags=flags)) == ()


def test_smb2_dialecte_inconnu_est_affiche_en_hexadecimal():
    assert _found("TCP", 445, 50000, _smb2(dialect=0x0999)) == [("SMB", "0x0999", "server")]
