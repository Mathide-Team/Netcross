"""
Parite du JSON produit par la GUI et par la CLI (Job 5/issue #14).

`netcross_gtk4.app._generate_json_thread` n'exposait aucun des objets de la
Session 0 (`flows`, `conversations`, `expert_events`, `diagnoses`,
`compliance`) ni `wireshark_expert_events` : le JSON de la GUI etait ampute
par rapport a celui de `--json-report`. Ces tests fixent le contrat :

* le JSON construit avec les kwargs de la GUI porte EXACTEMENT les memes
  cles que celui de la CLI ;
* `MainWindow._session_objects()` n'exige pas que l'utilisateur ait coche le
  triage (les Finding sont recalcules si besoin) et ne recalcule JAMAIS les
  signaux tshark (les paquets bruts ne sont plus disponibles a l'export) ;
* les deux threads d'export (JSON et PDF) passent bien ces objets.

GTK4 n'est pas installable partout (serveur de CI sans libgtk-4) : les tests
qui ont besoin de la classe `MainWindow` sont ignores dans ce cas, et le
contrat des deux threads d'export est alors verifie sur le SOURCE de
`app.py`. C'est volontairement grossier, mais cela detecte la regression qui
compte ici -- un export qui cesse de passer les objets enrichis -- sur une
plateforme ou la fenetre elle-meme ne peut pas etre instanciee.
"""

import json
import pathlib
import types

import pytest
from conftest import make_pkt

from netcross_core.models import Report
from netcross_report import build_findings, build_session_objects, generate_json_report
from netcross_report.synthesis import Finding

APP_SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src" / "netcross_gtk4" / "app.py"


def _report():
    r = Report(points=["A", "B"])
    r.pairs = [("A", "B")]
    return r


def _findings():
    return [
        Finding("anomalie", "Pertes", "A -> B", "12% de pertes", rule_id="loss_per_segment"),
        Finding("anomalie", "TCP", "A -> B", "retransmissions RTO", rule_id="tcp_retransmission_rto"),
    ]


def _flows():
    pkt = make_pkt(ts=1.0, src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100)
    return {("10.0.0.1", "10.0.0.2", 1234, 80, "TCP"): {"A": [pkt], "B": [pkt]}}


def _keys(tmp_path, nom, **kwargs):
    chemin = tmp_path / nom
    generate_json_report(_report(), str(chemin), findings=_findings(), **kwargs)
    return set(json.loads(chemin.read_text()))


# -- parite des cles ---------------------------------------------------


def test_les_kwargs_gui_produisent_les_memes_cles_que_la_cli(tmp_path):
    """La GUI passe des signaux tshark deja construits, la CLI les fait
    construire depuis les paquets : le JSON doit etre indiscernable."""
    pkt = make_pkt(ts=1.0, src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100)
    cli = build_session_objects(_report(), _findings(), flows=_flows(), all_packets=[pkt])
    gui = build_session_objects(
        _report(),
        _findings(),
        flows=_flows(),
        wireshark_expert_events=cli.wireshark_expert_events,
    )
    assert _keys(tmp_path, "cli.json", **cli.json_kwargs()) == _keys(tmp_path, "gui.json", **gui.json_kwargs())


def test_les_cles_enrichies_sont_bien_presentes(tmp_path):
    cles = _keys(
        tmp_path, "enrichi.json", **build_session_objects(_report(), _findings(), flows=_flows()).json_kwargs()
    )
    assert {"flows", "conversations", "expert_events", "diagnoses", "compliance"} <= cles


def test_wireshark_absent_quand_les_signaux_nont_pas_ete_calcules(tmp_path):
    """Un run GUI qui n'a pas produit de signaux tshark (mode diff, ou
    version anterieure) ne doit pas afficher une cle vide -- ce serait
    affirmer qu'aucun signal n'existe."""
    objs = build_session_objects(_report(), _findings(), flows=_flows())
    assert "wireshark_expert_events" not in _keys(tmp_path, "sans.json", **objs.json_kwargs())


def test_wireshark_present_meme_vide_quand_calcule(tmp_path):
    objs = build_session_objects(_report(), _findings(), wireshark_expert_events=[])
    assert "wireshark_expert_events" in _keys(tmp_path, "vide.json", **objs.json_kwargs())


def test_signaux_tshark_fournis_priment_sur_les_paquets():
    """La GUI fournit le resultat, pas les paquets : si les deux arrivent,
    on ne relance pas le calcul."""
    pkt = make_pkt(ts=1.0, src="10.0.0.1", dst="10.0.0.2", proto="TCP", length=100)
    deja_construits = []
    objs = build_session_objects(
        _report(),
        _findings(),
        all_packets=[pkt],
        wireshark_expert_events=deja_construits,
    )
    assert objs.wireshark_expert_events is deja_construits


# -- MainWindow._session_objects --------------------------------------


def _fenetre_factice(**etat):
    """Etat minimal d'un run "single" : `_session_objects()` ne lit que ces
    attributs, aucun widget n'est touche -- inutile d'instancier une vraie
    fenetre (et impossible sans serveur graphique)."""
    defauts = {
        "last_mode": "single",
        "last_report": _report(),
        "last_flows": None,
        "last_findings": None,
        "last_tls_findings": None,
        "last_quic_findings": None,
        "last_wireshark_expert_events": None,
    }
    defauts.update(etat)
    return types.SimpleNamespace(**defauts)


@pytest.fixture
def main_window():
    gi = pytest.importorskip("gi", reason="pygobject absent")
    try:
        gi.require_version("Gtk", "4.0")
    except ValueError:
        pytest.skip("GTK 4 absent de cette plateforme")
    from netcross_gtk4.app import MainWindow as _MainWindow

    return _MainWindow


def test_session_objects_recalcule_les_findings_sans_triage(main_window):
    """Le triage est une case a cocher de la GUI : sans elle,
    `last_findings` vaut None et les ExpertEvent seraient vides."""
    objs = main_window._session_objects(_fenetre_factice())
    assert objs.expert_events == build_session_objects(_report(), build_findings(_report())).expert_events


def test_session_objects_reutilise_les_findings_du_triage(main_window):
    findings = _findings()
    objs = main_window._session_objects(_fenetre_factice(last_findings=findings))
    assert [ev.message for ev in objs.expert_events] == [f.message for f in findings]


def test_session_objects_construit_les_flux_quand_ils_sont_connus(main_window):
    objs = main_window._session_objects(_fenetre_factice(last_flows=_flows(), last_findings=_findings()))
    assert len(objs.flows) == 1
    assert len(objs.conversations) == 1


def test_session_objects_ne_recalcule_pas_les_signaux_tshark(main_window):
    """Les paquets bruts ne sont plus en memoire a l'export : la fenetre ne
    conserve QUE le resultat, calcule pendant l'analyse."""
    signaux = []
    fenetre = _fenetre_factice(last_wireshark_expert_events=signaux)
    assert main_window._session_objects(fenetre).wireshark_expert_events is signaux


def test_session_objects_laisse_none_si_lanalyse_na_rien_fourni(main_window):
    assert main_window._session_objects(_fenetre_factice()).wireshark_expert_events is None


# -- contrat des threads d'export (verifiable sans GTK) ----------------


def test_le_thread_json_passe_les_objets_enrichis():
    source = APP_SOURCE.read_text()
    assert "**self._session_objects().json_kwargs()" in source


def test_le_thread_pdf_passe_les_objets_enrichis():
    source = APP_SOURCE.read_text()
    assert "session_objects = self._session_objects()" in source
    assert "session_objects=session_objects," in source


def test_lanalyse_calcule_les_signaux_tshark_avant_de_liberer_les_paquets():
    """Les signaux Expert Info doivent etre calcules dans le thread
    d'analyse, tant que les paquets existent encore (issue #14), et le
    resultat remonte a la fenetre.

    La seconde verification portait sur la ligne litterale
    `self.last_wireshark_expert_events = wireshark_expert_events`. Elle est
    devenue fausse avec l'extraction de #285 (lot 2) alors que le
    comportement est intact : la fenetre recopie desormais les quinze
    champs d'etat en boucle depuis `RunOutcome.etat()`, ce qui est
    precisement ce qui empeche qu'un champ soit oublie d'un cote.

    Le test verifie donc ce qui est observable ici -- que le resultat est
    transmis au constructeur d'etat -- et la conservation effective du
    champ est verifiee pour de vrai dans tests/test_run_outcome.py, sur
    l'objet et non sur une chaine de caracteres. Un test de sous-chaine est
    une approximation du comportement ; quand le vrai test devient
    possible, c'est lui qui fait foi.
    """
    source = APP_SOURCE.read_text()
    assert "build_wireshark_expert_events(all_packets)" in source
    assert "wireshark_expert_events=wireshark_expert_events" in source
    assert "analysis_outcome(" in source

    from netcross_gtk4.run_outcome import RunOutcome, analysis_outcome

    assert "wireshark_expert_events" in RunOutcome.CHAMPS_ETAT
    outcome = analysis_outcome("single", None, None, None, "", wireshark_expert_events=["signal"])
    assert outcome.etat()["last_wireshark_expert_events"] == ["signal"]
