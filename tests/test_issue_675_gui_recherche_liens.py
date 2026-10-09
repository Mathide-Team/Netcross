"""Issue #675 : resultats de recherche forensic « cliquables vers le flux » --
choix d'un resultat, filtre Wireshark, « Annoter la trame », « Ouvrir dans
Wireshark » (wireshark -r FICHIER -g TRAME)."""

from __future__ import annotations

import pytest
from conftest import make_pkt

from netcross_core.forensic_search import ForensicSearchIndex, ForensicSearchResult
from netcross_gtk4.forensic_view import (
    capture_for_point,
    describe_selection,
    wireshark_command,
    wireshark_filter,
)

R = ForensicSearchResult(kind="packet", point="A", frame_number=12, ts=1.0)
SANS_TRAME = ForensicSearchResult(kind="flow", point="A", frame_number=None, ts=None)


def test_filtre_et_commande():
    assert wireshark_filter(R) == "frame.number == 12"
    assert wireshark_filter(SANS_TRAME) is None
    assert wireshark_command("/c/a.pcap", 12) == ["wireshark", "-r", "/c/a.pcap", "-g", "12"]
    assert wireshark_command("/c/a.pcap", 3, "/usr/bin/wireshark")[0] == "/usr/bin/wireshark"


def test_fichier_du_point():
    caps = [("A", "/c/a.pcap"), ("B", "/c/b1.pcap"), ("B", "/c/b2.pcap")]
    assert capture_for_point(R, caps) == "/c/a.pcap"
    assert capture_for_point(ForensicSearchResult("packet", "B", 1, 1.0), caps) is None  # rotation : ambigu
    assert capture_for_point(ForensicSearchResult("packet", "Z", 1, 1.0), caps) is None
    assert capture_for_point(ForensicSearchResult("packet", None, 1, 1.0), caps) is None
    assert capture_for_point(R, None) is None


def test_description():
    assert describe_selection(R, "/c/a.pcap") == (
        "Trame 12 (point A) -- filtre Wireshark : frame.number == 12 -- fichier : /c/a.pcap"
    )
    assert describe_selection(ForensicSearchResult("packet", None, 4, 1.0), None) == (
        "Trame 4 (point inconnu) -- filtre Wireshark : frame.number == 4"
    )
    assert "pas de lien" in describe_selection(SANS_TRAME, None)


# -- panneau GTK (ignore sans GTK4 ni affichage) --


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


def _index():
    return ForensicSearchIndex(
        [
            make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", dport=443, ts=1.0, frame_number=7),
            make_pkt(point="B", src="10.0.0.7", dst="10.0.0.8", dport=53, ts=2.0, frame_number=9),
        ]
    )


@pytest.fixture()
def panneau():
    _gtk()
    from netcross_gtk4.forensic_panel import ForensicSearchPanel

    lances, annotes = [], []
    panel = ForensicSearchPanel(
        on_annotate=lambda p, f: annotes.append((p, f)),
        launcher=lances.append,
        find_program=lambda name: "/usr/bin/" + name,
    )
    panel.set_index(_index(), [("A", "/c/a.pcap"), ("B", "/c/b.pcap")])
    panel.address_entry.set_text("10.0.0.1")
    panel.run_search()
    return panel, lances, annotes


def _position_paquet(panel):
    return next(i for i, r in enumerate(panel._displayed) if r.frame_number == 7)


def test_sans_choix_boutons_inactifs(panneau):
    panel, _l, _a = panneau
    assert not panel.annotate_btn.get_sensitive()
    assert not panel.wireshark_btn.get_sensitive()
    assert panel.annotate_selected() is False
    assert panel.open_selected_in_wireshark() is False


def test_choix_d_un_resultat_puis_wireshark_et_annotation(panneau):
    panel, lances, annotes = panneau
    panel.select_result(_position_paquet(panel))
    assert panel.selected.frame_number == 7
    assert "frame.number == 7" in panel.status_label.get_text()
    assert "/c/a.pcap" in panel.status_label.get_text()
    assert panel.annotate_btn.get_sensitive() and panel.wireshark_btn.get_sensitive()

    assert panel.open_selected_in_wireshark() is True
    assert lances == [["/usr/bin/wireshark", "-r", "/c/a.pcap", "-g", "7"]]
    assert panel.status_label.get_text().startswith("Wireshark ouvert : ")

    assert panel.annotate_selected() is True
    assert annotes == [("A", 7)]


def test_wireshark_absent_ou_lancement_impossible():
    _gtk()
    from netcross_gtk4.forensic_panel import ForensicSearchPanel

    panel = ForensicSearchPanel(find_program=lambda _n: None)
    panel.set_index(_index(), [("A", "/c/a.pcap")])
    panel.address_entry.set_text("10.0.0.1")
    panel.run_search()
    panel.select_result(_position_paquet(panel))
    assert not panel.annotate_btn.get_sensitive()  # pas de callback d'annotation
    assert panel.open_selected_in_wireshark() is False
    assert "Wireshark introuvable" in panel.status_label.get_text()

    def echec(_argv):
        raise OSError("refus")

    panel2 = ForensicSearchPanel(launcher=echec, find_program=lambda n: n)
    panel2.set_index(_index(), [("A", "/c/a.pcap")])
    panel2.address_entry.set_text("10.0.0.1")
    panel2.run_search()
    panel2.select_result(_position_paquet(panel2))
    assert panel2.open_selected_in_wireshark() is False
    assert "Lancement de Wireshark impossible : refus" in panel2.status_label.get_text()


def test_sans_fichiers_pas_de_wireshark(panneau):
    panel, _l, _a = panneau
    panel.set_index(_index())  # capture en direct : pas de fichiers
    panel.address_entry.set_text("10.0.0.1")
    panel.run_search()
    panel.select_result(_position_paquet(panel))
    assert panel.annotate_btn.get_sensitive()
    assert not panel.wireshark_btn.get_sensitive()
    assert panel.open_selected_in_wireshark() is False


def test_nouvelle_recherche_efface_le_choix(panneau):
    panel, _l, _a = panneau
    panel.select_result(_position_paquet(panel))
    panel.run_search()
    assert panel.selected is None
    assert not panel.wireshark_btn.get_sensitive()


def test_fenetre_annoter_preremplit_le_panneau(monkeypatch):
    gtk = _gtk()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test675liens")
    app.register(None)
    window = MainWindow(app)
    vus = []
    monkeypatch.setattr(window.annotations_panel, "prefill", lambda p, f: vus.append((p, f)))
    window.forensic_panel.set_index(_index(), [("A", "/c/a.pcap")])
    window.forensic_panel.address_entry.set_text("10.0.0.1")
    window.forensic_panel.run_search()
    window.forensic_panel.select_result(_position_paquet(window.forensic_panel))
    assert window.forensic_panel.annotate_selected()
    assert vus == [("A", 7)]
    assert window.annotations_expander.get_expanded()
