"""Issue #675 : panneau « Contenus (extraction) » de la page Resultats.

Ignore sans GTK4 ou sans affichage, meme garde que test_app_gtk4_lot4.py.
"""

import json

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_core.extract.contents import KINDS, USAGE_REMINDER, ContentExtraction  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.extraction_panel import ExtractionPanel  # noqa: E402
from netcross_gtk4.extraction_view import UNAVAILABLE_NO_FILES, UNAVAILABLE_REDACTED  # noqa: E402

_N = 0


def _pump():
    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    while ctx.iteration(False):
        pass


class _Runner:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result, self.error = result, error

    def __call__(self, captures, *, out_dir, kinds):
        self.calls.append((captures, out_dir, kinds))
        if self.error:
            raise self.error
        return self.result or ContentExtraction(out_dir, tuple(kinds))


def _panel(runner):
    # thread remplace par un appel direct ; GLib.idle_add reel, boucle videe
    return ExtractionPanel(runner=runner, start_thread=lambda fn: fn())


def test_cases_dans_l_ordre_de_kinds_et_rappel_affiche():
    panel = _panel(_Runner())
    assert tuple(panel.kind_checks) == KINDS
    assert all(c.get_active() for c in panel.kind_checks.values())
    textes = []
    child = panel.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.Label):
            textes.append(child.get_text())
        child = child.get_next_sibling()
    assert USAGE_REMINDER in textes


def test_indisponible_sans_fichiers_ou_anonymise():
    panel = _panel(_Runner())
    assert panel.status_label.get_text() == UNAVAILABLE_NO_FILES
    assert not panel.extract_btn.get_sensitive()
    panel.set_source([("A", "/a.pcap")], redacted=True)
    assert panel.status_label.get_text() == UNAVAILABLE_REDACTED
    assert not panel.extract_btn.get_sensitive()
    assert panel.start_extraction("/tmp/jamais") is False


def test_extraction_lancee_avec_les_types_coches(tmp_path):
    runner = _Runner()
    panel = _panel(runner)
    panel.set_source([("A", "/a.pcap"), ("B", "/b.pcap")], redacted=False)
    assert panel.extract_btn.get_sensitive()
    panel.kind_checks["video"].set_active(False)
    cible = tmp_path / "out"

    assert panel.start_extraction(str(cible)) is True
    _pump()

    assert runner.calls == [([("A", "/a.pcap"), ("B", "/b.pcap")], str(cible), ("audio", "documents"))]
    assert "Aucun flux RTP" in panel.status_label.get_text()
    assert panel.running is False
    assert panel.extract_btn.get_sensitive()


def test_vrai_moteur_ecrit_manifeste_et_lisez_moi(tmp_path, monkeypatch):
    """Sans tshark ni paquets : le moteur reel produit quand meme le
    manifeste et le rappel d'usage dans le dossier choisi."""
    import netcross_core.extract.contents as contents

    monkeypatch.setattr(contents, "export_documents", lambda captures, out, tshark_bin="tshark": ([], []))
    import pcap_parser

    monkeypatch.setattr(pcap_parser, "parse_capture", lambda path, raise_on_error=False: [])
    panel = ExtractionPanel(start_thread=lambda fn: fn())
    panel.set_source([("A", "/a.pcap")], redacted=False)
    cible = tmp_path / "out"
    assert panel.start_extraction(str(cible))
    _pump()
    manifeste = json.loads((cible / "manifest.json").read_text(encoding="utf-8"))
    assert manifeste["kinds"] == list(KINDS)
    assert (cible / "LISEZ-MOI.txt").exists()
    assert "Manifeste :" in panel.status_label.get_text()


def test_dossier_non_vide_refuse(tmp_path):
    (tmp_path / "x").write_text("deja la")
    runner = _Runner()
    panel = _panel(runner)
    panel.set_source([("A", "/a.pcap")], redacted=False)
    assert panel.start_extraction(str(tmp_path)) is False
    assert runner.calls == []
    assert "pas un repertoire vide" in panel.status_label.get_text()


def test_aucun_type_refuse(tmp_path):
    panel = _panel(_Runner())
    panel.set_source([("A", "/a.pcap")], redacted=False)
    for check in panel.kind_checks.values():
        check.set_active(False)
    assert panel.start_extraction(str(tmp_path / "o")) is False
    assert "au moins un type" in panel.status_label.get_text()


def test_erreur_du_moteur_au_statut(tmp_path):
    panel = _panel(_Runner(error=RuntimeError("tshark absent")))
    panel.set_source([("A", "/a.pcap")], redacted=False)
    assert panel.start_extraction(str(tmp_path / "o"))
    _pump()
    assert "Extraction en echec : tshark absent" in panel.status_label.get_text()
    assert panel.extract_btn.get_sensitive()


def test_pendant_l_extraction_bouton_inactif(tmp_path):
    en_attente = []
    panel = ExtractionPanel(runner=_Runner(), start_thread=en_attente.append)
    panel.set_source([("A", "/a.pcap")], redacted=False)
    assert panel.start_extraction(str(tmp_path / "o"))
    assert panel.running
    assert not panel.extract_btn.get_sensitive()
    assert panel.start_extraction(str(tmp_path / "p")) is False


# -- fenetre principale --


@pytest.fixture()
def window():
    global _N
    _N += 1
    app = Gtk.Application(application_id=f"org.netcross.test675extract.n{_N}")
    app.register(None)
    return MainWindow(app)


def test_fenetre_alimente_le_panneau(window, monkeypatch):
    monkeypatch.setattr(window, "_appliquer_outcome", lambda *a, **k: None)
    window._annotation_captures = [("A", "/a.pcap")]
    window._extraction_redacted = False
    window._on_analysis_done("single", None, [], None, "")
    assert window.extraction_panel.captures == [("A", "/a.pcap")]
    assert window.extraction_panel.extract_btn.get_sensitive()

    window._extraction_redacted = True
    window._on_analysis_done("single", None, [], None, "")
    assert not window.extraction_panel.extract_btn.get_sensitive()

    window._on_diff_done([], None, None, "")
    assert window.extraction_panel.captures is None


def test_lancement_releve_l_anonymisation(window, monkeypatch):
    class _T:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

    monkeypatch.setattr(app_module.threading, "Thread", _T)
    window.add_capture_row("/tmp/a.pcap", "A")
    window.redact_check.set_active(True)
    window.on_run_analysis(None)
    assert window._extraction_redacted is True
