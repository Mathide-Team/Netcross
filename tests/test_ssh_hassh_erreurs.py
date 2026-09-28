"""Tests des chemins d'erreur de netcross_core.fingerprint.ssh_hassh (#684).

Couvre les sorties None de `_parse_kexinit` (banniere sans fin de ligne,
segment trop court, longueur de charge utile incoherente, cookie qui
depasse la borne du message) et le repli `except UnicodeError` de
`parse_kexinit` (name-list non ASCII).
"""

from __future__ import annotations

from netcross_core.fingerprint.ssh_hassh import parse_kexinit

_SSH_MSG_KEXINIT = 20


def _namelist(raw: bytes) -> bytes:
    return len(raw).to_bytes(4, "big") + raw


def _kexinit_packet(kex_raw: bytes = b"curve25519-sha256") -> bytes:
    """Paquet binaire SSH_MSG_KEXINIT complet (RFC 4253 §6 et §7.1)."""
    body = bytes([_SSH_MSG_KEXINIT]) + bytes(16)  # msg_type + cookie
    body += _namelist(kex_raw)
    for name in (b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none"):
        body += _namelist(name)
    body += _namelist(b"") + _namelist(b"")  # langues c2s / s2c
    body += b"\x00" + bytes(4)  # first_kex_packet_follows + reserved
    padding_length = 4
    packet_length = len(body) + padding_length + 1
    return packet_length.to_bytes(4, "big") + bytes([padding_length]) + body + bytes(padding_length)


def test_kexinit_valide_de_reference():
    """Garde-fou : le paquet de test est bien decodable."""
    kexinit = parse_kexinit(_kexinit_packet())
    assert kexinit is not None
    assert kexinit["kex_algorithms"] == ["curve25519-sha256"]


def test_banniere_sans_fin_de_ligne_renvoie_none():
    """Banniere "SSH-..." sans "\\n" : rien a decoder apres elle."""
    assert parse_kexinit(b"SSH-2.0-OpenSSH_9.6") is None


def test_segment_trop_court_renvoie_none():
    """Moins de 6 octets : ni longueur, ni padding, ni type de message."""
    assert parse_kexinit(b"\x00\x00\x00") is None


def test_longueur_de_charge_utile_incoherente_renvoie_none():
    """packet_length - padding_length - 1 < 1 : aucune charge utile."""
    data = (1).to_bytes(4, "big") + bytes([1]) + bytes([_SSH_MSG_KEXINIT])
    assert parse_kexinit(data) is None


def test_message_trop_court_pour_le_cookie_renvoie_none():
    """Le message annonce 1 octet de charge utile : le cookie de 16 octets
    depasse la borne du message."""
    data = (2).to_bytes(4, "big") + bytes([0]) + bytes([_SSH_MSG_KEXINIT]) + bytes(16)
    assert parse_kexinit(data) is None


def test_namelist_non_ascii_renvoie_none():
    """UnicodeError pendant le decodage d'une name-list : repli sur None."""
    assert parse_kexinit(_kexinit_packet(kex_raw=b"\xff\xfe")) is None
