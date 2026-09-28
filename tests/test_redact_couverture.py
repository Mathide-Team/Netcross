"""
netcross_core.redact -- champs presents mais NON redigeables (issue #735,
suite de #665).

tests/test_redact.py couvre le cas nominal de chaque champ (adresse valide
-> pseudonyme). Ce fichier couvre l'autre cote de chaque garde de
AddressRedactor._redact_one : un champ present mais vide, tronque ou qui
n'a pas la forme attendue (capture reelle imparfaite) doit etre laisse tel
quel, sans lever et sans consommer de pseudonyme, et ne doit pas empecher
la redaction des champs suivants du meme paquet.

Branches visees (lignes mesurees sur dev @ aff1a70, identiques sur dev @ 7bec95f ;
ligne -> destination) :

- 181->183 : STP, src absent ou pas une MAC ;
- 183->195 : STP, dst absent ou pas une MAC ;
- 188->190 : hors STP, src pas une adresse IP ;
- 192->195 : hors STP, dst pas une adresse IP ;
- 200->203 : dhcp_server_id pas une adresse IP ;
- 205->207 : stp_root_id "prio/mac" dont la partie MAC est invalide.

Objets Pkt synthetiques uniquement : ni tshark ni GTK.
"""

import pytest
from conftest import make_pkt

from netcross_core.redact import AddressRedactor, redact_packets

MAC_A = "00:11:22:33:44:55"
MAC_B = "aa:bb:cc:dd:ee:ff"
MAC_STP_MULTICAST = "01:80:c2:00:00:00"

# Formes invalides communes : vide, texte libre, MAC/IP tronquee.
_PAS_UNE_MAC = ["", "pas-une-mac", "00:11:22:33:44"]
_PAS_UNE_IP = ["", "pas-une-ip", "999.1.1.1", MAC_A]


# ---------------------------------------------------------------------
# STP -- src/dst portent une MAC (181->183, 183->195)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("src", [None, *_PAS_UNE_MAC])
def test_stp_src_absent_ou_non_mac_laisse_tel_quel_et_dst_reste_redige(src):
    pk = make_pkt(proto="STP", src=src, dst=MAC_STP_MULTICAST)
    redactor = redact_packets([pk])
    assert pk.src == src
    # Le src ignore n'a consomme aucun pseudonyme : le dst prend le premier.
    assert pk.dst == "02:00:00:00:00:00"
    assert redactor.mapping == {MAC_STP_MULTICAST: "02:00:00:00:00:00"}


@pytest.mark.parametrize("dst", [None, *_PAS_UNE_MAC])
def test_stp_dst_absent_ou_non_mac_laisse_tel_quel_et_src_reste_redige(dst):
    pk = make_pkt(proto="STP", src=MAC_A, dst=dst)
    redactor = redact_packets([pk])
    assert pk.src == "02:00:00:00:00:00"
    assert pk.dst == dst
    assert redactor.mapping == {MAC_A: "02:00:00:00:00:00"}


def test_stp_dst_non_mac_ne_bloque_pas_les_champs_suivants():
    # 183->195 : apres un dst ignore, l'execution reprend a arp_sender_mac.
    pk = make_pkt(proto="STP", src=MAC_A, dst="pas-une-mac", arp_sender_mac=MAC_B)
    redactor = redact_packets([pk])
    assert pk.dst == "pas-une-mac"
    assert pk.src == "02:00:00:00:00:00"
    assert pk.arp_sender_mac == "02:00:00:00:00:01"
    assert len(redactor) == 2


# ---------------------------------------------------------------------
# Hors STP -- src/dst doivent etre des adresses IP (188->190, 192->195)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("src", _PAS_UNE_IP)
def test_src_non_ip_laisse_tel_quel_et_dst_reste_redige(src):
    pk = make_pkt(src=src, dst="10.0.0.10")
    redactor = redact_packets([pk])
    assert pk.src == src
    assert pk.dst == "192.0.2.1"
    assert redactor.mapping == {"10.0.0.10": "192.0.2.1"}


@pytest.mark.parametrize("dst", _PAS_UNE_IP)
def test_dst_non_ip_laisse_tel_quel_et_src_reste_redige(dst):
    pk = make_pkt(src="10.0.0.5", dst=dst)
    redactor = redact_packets([pk])
    assert pk.src == "192.0.2.1"
    assert pk.dst == dst
    assert redactor.mapping == {"10.0.0.5": "192.0.2.1"}


def test_dst_non_ip_ne_bloque_pas_les_champs_suivants():
    # 192->195 : apres un dst ignore, l'execution reprend a arp_sender_mac.
    pk = make_pkt(proto="ARP", src="10.0.0.5", dst="pas-une-ip", arp_sender_mac=MAC_B)
    redact_packets([pk])
    assert pk.dst == "pas-une-ip"
    assert pk.arp_sender_mac == "02:00:00:00:00:00"


def test_src_et_dst_non_ip_ne_creent_aucune_entree():
    pk = make_pkt(src="pas-une-ip", dst="")
    redactor = redact_packets([pk])
    assert (pk.src, pk.dst) == ("pas-une-ip", "")
    assert len(redactor) == 0
    assert redactor.entries() == []


# ---------------------------------------------------------------------
# arp_sender_mac present mais invalide (operande droit du `and`)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("mac", ["", "pas-une-mac", "aa:bb:cc:dd:ee", "192.168.1.1"])
def test_arp_sender_mac_non_mac_laisse_tel_quel(mac):
    pk = make_pkt(proto="ARP", src="10.0.0.5", dst="10.0.0.6", arp_sender_mac=mac)
    redactor = redact_packets([pk])
    assert pk.arp_sender_mac == mac
    assert mac not in redactor.mapping
    assert len(redactor) == 2  # seulement src et dst


# ---------------------------------------------------------------------
# dhcp_server_id present mais pas une IP (200->203)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("server_id", _PAS_UNE_IP)
def test_dhcp_server_id_non_ip_laisse_tel_quel(server_id):
    pk = make_pkt(proto="UDP", src="10.0.0.50", dst="10.0.0.51", dhcp_server_id=server_id)
    redactor = redact_packets([pk])
    assert pk.dhcp_server_id == server_id
    assert server_id not in redactor.mapping
    assert len(redactor) == 2  # seulement src et dst


def test_dhcp_server_id_non_ip_ne_bloque_pas_stp_root_id():
    # 200->203 : apres un dhcp_server_id ignore, l'execution reprend a
    # stp_root_id.
    pk = make_pkt(
        proto="STP", src=MAC_A, dst=MAC_STP_MULTICAST, dhcp_server_id="pas-une-ip", stp_root_id=f"4096/{MAC_B}"
    )
    redact_packets([pk])
    assert pk.dhcp_server_id == "pas-une-ip"
    assert pk.stp_root_id == "4096/02:00:00:00:00:02"


# ---------------------------------------------------------------------
# stp_root_id "prio/mac" (205->207)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("root_id", ["32768/pas-une-mac", "32768/", "32768/aa:bb:cc:dd:ee", "32768/10.0.0.5"])
def test_stp_root_id_partie_mac_invalide_laisse_tel_quel(root_id):
    pk = make_pkt(proto="STP", src=MAC_A, dst=MAC_STP_MULTICAST, stp_root_id=root_id)
    redactor = redact_packets([pk])
    assert pk.stp_root_id == root_id
    assert len(redactor) == 2  # seulement src et dst : rien pour le root_id


@pytest.mark.parametrize("root_id", ["", "pas-de-separateur", "32768"])
def test_stp_root_id_sans_separateur_laisse_tel_quel(root_id):
    pk = make_pkt(proto="STP", src=MAC_A, dst=MAC_STP_MULTICAST, stp_root_id=root_id)
    redactor = redact_packets([pk])
    assert pk.stp_root_id == root_id
    assert len(redactor) == 2


def test_stp_root_id_invalide_puis_valide_sur_le_meme_redacteur():
    # Un root_id invalide ne pollue pas le mapping : le suivant, valide,
    # prend bien le premier pseudonyme MAC restant.
    redactor = AddressRedactor()
    invalide = make_pkt(proto="STP", src=None, dst=None, stp_root_id="32768/pas-une-mac")
    valide = make_pkt(proto="STP", src=None, dst=None, stp_root_id=f"32768/{MAC_B}")
    redactor.redact([invalide, valide])
    assert invalide.stp_root_id == "32768/pas-une-mac"
    assert valide.stp_root_id == "32768/02:00:00:00:00:00"
    assert redactor.mapping == {MAC_B: "02:00:00:00:00:00"}
