"""Issue #877 (GUI) : portées, marqueurs et correspondance privée du ticket
de support, mêmes règles et même fichier que la CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netcross_core.support import SCOPES, ConsentRequiredError
from netcross_gtk4.report_exports import (
    ReportContext,
    SupportTicketError,
    check_support_scopes,
    parse_support_markers,
    write_support_map,
    write_support_ticket,
)


def _ticket(chemin):
    return json.loads(Path(chemin).read_text(encoding="utf-8"))


def test_marqueurs():
    assert parse_support_markers("") == {}
    assert parse_support_markers(" trace_id = T-042 ; ticket=INC=7 ;") == {"trace_id": "T-042", "ticket": "INC=7"}


@pytest.mark.parametrize("texte", ["trace_id", "=x", "a=1; b"])
def test_marqueur_mal_forme(texte):
    with pytest.raises(SupportTicketError, match="CLE=VALEUR"):
        parse_support_markers(texte)


def test_portees():
    assert check_support_scopes(["marqueurs", "journal"]) == ("journal", "marqueurs")
    with pytest.raises(SupportTicketError, match="au moins une"):
        check_support_scopes([])
    with pytest.raises(SupportTicketError, match="inconnue"):
        check_support_scopes(["journal", "secret"])


def test_ticket_par_defaut_toutes_portees(tmp_path):
    result = write_support_ticket(str(tmp_path / "t.json"), ReportContext(captures=2), consent=True)
    assert result.scopes == SCOPES
    assert _ticket(result.path)["consentement"]["portees"] == list(SCOPES)


def test_ticket_portees_et_marqueurs(tmp_path):
    result = write_support_ticket(
        str(tmp_path / "t.json"),
        ReportContext(captures=2),
        consent=True,
        scopes=["journal", "marqueurs"],
        markers={"trace_id": "T-042"},
    )
    ticket = _ticket(result.path)
    assert ticket["consentement"]["portees"] == ["journal", "marqueurs"]
    assert ticket["marqueurs"]["trace_id"] == "T-042"
    assert "environnement" not in ticket or not ticket["environnement"]
    assert result.markers == {"trace_id": "T-042"}


def test_marqueurs_sans_la_portee_absents(tmp_path):
    result = write_support_ticket(
        str(tmp_path / "t.json"), ReportContext(), consent=True, scopes=["journal"], markers={"trace_id": "T-1"}
    )
    assert "T-1" not in Path(result.path).read_text(encoding="utf-8")


def test_portee_refusee_n_ecrit_rien(tmp_path):
    with pytest.raises(SupportTicketError):
        write_support_ticket(str(tmp_path / "t.json"), ReportContext(), consent=True, scopes=[])
    assert not (tmp_path / "t.json").exists()


def test_sans_consentement(tmp_path):
    with pytest.raises(ConsentRequiredError):
        write_support_ticket(str(tmp_path / "t.json"), ReportContext(), consent=False, scopes=["journal"])


def test_correspondance_meme_csv_que_la_cli(tmp_path):
    from netcross_core.support.ticket import write_support_map_csv

    result = write_support_ticket(str(tmp_path / "t.json"), ReportContext(captures=1), consent=True)
    result.scrubber.scrub("hote srv-prod-01.example.com 10.1.2.3 /home/alice/x.pcap")
    write_support_map(result.scrubber, str(tmp_path / "gui.csv"))
    write_support_map_csv(result.scrubber, str(tmp_path / "cli.csv"))
    gui = (tmp_path / "gui.csv").read_text(encoding="utf-8")
    assert gui == (tmp_path / "cli.csv").read_text(encoding="utf-8")
    assert gui.startswith("valeur_reelle,pseudonyme,categorie\n")
    assert "10.1.2.3" in gui


def test_correspondance_sans_ticket(tmp_path):
    with pytest.raises(ValueError, match="aucun ticket"):
        write_support_map(None, str(tmp_path / "m.csv"))


def _gtk():
    from gtk4_display import exiger_gtk4_avec_affichage

    return exiger_gtk4_avec_affichage()


def test_panneau_portees_marqueurs_et_correspondance(tmp_path):
    _gtk()
    from netcross_gtk4.report_exports_panel import ReportExportsPanel

    panel = ReportExportsPanel()
    assert panel.selected_scopes() == SCOPES
    assert not panel.support_map_btn.get_sensitive()
    panel.set_context(None, None, ReportContext(captures=1, redact=True))
    panel.consent_check.set_active(True)
    assert panel.ticket_btn.get_sensitive()

    for scope in ("environnement", "journal", "trace_appels", "marqueurs"):
        panel.scope_checks[scope].set_active(False)
    assert not panel.ticket_btn.get_sensitive()
    panel.scope_checks["journal"].set_active(True)
    panel.scope_checks["marqueurs"].set_active(True)
    assert panel.ticket_btn.get_sensitive()

    panel.markers_entry.set_text("trace_id")
    with pytest.raises(SupportTicketError):
        panel.write_ticket_to(tmp_path / "t.json")
    assert not (tmp_path / "t.json").exists()

    panel.markers_entry.set_text("trace_id=T-042")
    chemin = panel.write_ticket_to(tmp_path / "t.json")
    ticket = _ticket(chemin)
    assert ticket["consentement"]["portees"] == ["journal", "marqueurs"]
    assert ticket["marqueurs"]["trace_id"] == "T-042"
    assert "portees journal, marqueurs" in panel.status_label.get_text()
    assert panel.support_map_btn.get_sensitive()

    carte = panel.write_support_map_to(tmp_path / "m.csv")
    assert Path(carte).read_text(encoding="utf-8").startswith("valeur_reelle,pseudonyme,categorie")
    assert "NE PAS transmettre" in panel.status_label.get_text()

    # Une nouvelle analyse oublie le ticket précédent et sa correspondance.
    panel.set_context(None, None, ReportContext(captures=1))
    assert panel.last_ticket is None and not panel.support_map_btn.get_sensitive()
