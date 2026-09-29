"""capfile.py : chemins rares du cadrage binaire pcap/pcapng (issue #747).

Complete `test_capfile.py` : options ou blocs sans rapport avec ce que lit
chaque fonction, en-tete global tronque, byte-order magic invalide.
"""

from __future__ import annotations

import struct

import pytest
from pcap_builders import IDB, block, dsb, epb, frame, idb, shb, write_bytes

from pcap_parser.capfile import _BLOCK_EPB, _PCAPNG_MAGIC, first_timestamp, read_structure, split_by_size

_BLOCK_ISB = 5
_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"


# -- read_structure -------------------------------------------------------------


def test_read_structure_pcapng_idb_option_autre_que_if_name(tmp_path):
    """Une option d'IDB autre que if_name (ici if_tsresol) est ignoree : le nom reste None."""
    p = tmp_path / "test.pcapng"
    options = struct.pack("<HH", 9, 1) + b"\x06\x00\x00\x00" + struct.pack("<HH", 0, 0)
    write_bytes(p, shb(), block(IDB, struct.pack("<HHI", 1, 0, 65535) + options))
    info = read_structure(str(p))
    assert info is not None
    assert [(i.linktype, i.name) for i in info.interfaces] == [(1, None)]


def test_read_structure_pcapng_isb_option_inconnue_ignoree(tmp_path):
    """Une option d'ISB de 8 octets mais inconnue (isb_starttime, code 2) ne renseigne aucun compteur."""
    p = tmp_path / "test.pcapng"
    options = (
        struct.pack("<HH", 2, 8)
        + struct.pack("<II", 1, 2)  # isb_starttime : pas un compteur
        + struct.pack("<HH", 4, 8)
        + struct.pack("<Q", 7)  # isb_ifrecv
        + struct.pack("<HH", 0, 0)
    )
    write_bytes(p, shb(), idb(), block(_BLOCK_ISB, struct.pack("<III", 0, 0, 0) + options))
    info = read_structure(str(p))
    assert info is not None
    (iface,) = info.interfaces
    assert iface.received == 7
    assert iface.dropped_by_interface is None
    assert iface.dropped_by_os is None


def test_read_structure_pcapng_shb_bom_invalide(tmp_path):
    """SHB au byte-order magic invalide : aucune version lue, donc pas de structure (None)."""
    p = tmp_path / "test.pcapng"
    p.write_bytes(_PCAPNG_MAGIC + struct.pack("<I", 28) + b"\xde\xad\xbe\xef")
    assert read_structure(str(p)) is None


# -- pcap tronque avant la fin de l'en-tete global --------------------------------


def test_split_by_size_pcap_en_tete_global_incomplet(tmp_path):
    """Rien a decouper dans un pcap tronque avant la fin de son en-tete global : aucun segment."""
    p = tmp_path / "court.pcap"
    p.write_bytes(_PCAP_MAGIC_LE + b"\x02\x00")
    assert split_by_size(str(p), str(tmp_path / "seg"), 1024) == []
    assert list(tmp_path.glob("seg_*")) == []


def test_first_timestamp_pcap_en_tete_global_tronque(tmp_path):
    """first_timestamp sur un pcap tronque avant la fin de l'en-tete global : ValueError."""
    p = tmp_path / "court.pcap"
    p.write_bytes(_PCAP_MAGIC_LE + b"\x02\x00")
    with pytest.raises(ValueError, match="tronque"):
        first_timestamp(str(p))


# -- first_timestamp pcapng ---------------------------------------------------------


def test_first_timestamp_pcapng_saute_les_blocs_sans_rapport(tmp_path):
    """Option d'IDB autre que if_tsresol (if_name), bloc ni SHB/IDB/EPB (DSB) et EPB trop court
    sont ignores : le timestamp est celui du premier EPB complet.

    if_tsresol = 0 (une seconde) : meme lecture en puissance de 2 ou de 10, le test ne depend pas
    de l'echelle appliquee par defaut."""
    p = tmp_path / "test.pcapng"
    idb_options = (
        struct.pack("<HH", 2, 4)
        + b"eth0"  # if_name : code different de if_tsresol
        + struct.pack("<HH", 9, 1)
        + b"\x00\x00\x00\x00"  # if_tsresol = 0, rembourre a 4 octets
        + struct.pack("<HH", 0, 0)
    )
    write_bytes(
        p,
        shb(),
        block(IDB, struct.pack("<HHI", 1, 0, 65535) + idb_options),
        dsb(),
        block(_BLOCK_EPB, b"\x00" * 4),  # EPB de 16 octets : trop court pour porter un timestamp
        epb(frame(0), ts_us=1500),
        epb(frame(1), ts_us=9000),
    )
    assert first_timestamp(str(p)) == 1500.0
