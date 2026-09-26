"""
Tests app.py -- lot 6/10 (issue #427, sous-issue de #421) : threads
d'analyse/diff + export CSV/PDF, pilotes via pygobject.

Ignore si GTK4/pygobject ou un affichage manquent (CI sans libgtk-4) ; meme
garde-fou que tests/test_gui_security_window.py.

Perimetre (lignes 1719-2023 de src/netcross_gtk4/app.py) :
    _run_analysis_thread / _run_diff_thread (+ callbacks _on_progress
    imbriques), _on_analysis_error, _on_analysis_done, _on_diff_done,
    on_export_csv, _on_csv_path_chosen, on_export_pdf.

Les pipelines eux-memes (netcross_gtk4.analysis_pipeline.run_analysis_pipeline
et netcross_gtk4.diff_pipeline.run_diff_pipeline) sont deja testes en pur
Python ailleurs (tests/test_analysis_pipeline.py, tests/test_pipeline_optional_branches.py) :
ici on les remplace par des doublures pour ne verifier QUE le cablage GUI --
le thread appelle le pipeline, relaie sa progression au journal via
GLib.idle_add, et route le resultat ou l'erreur vers les bons callbacks.

Les threads sont appeles directement (comme des methodes normales) plutot
que via threading.Thread : le test reste synchrone et deterministe. Comme
GLib.idle_add se contente d'empiler les rappels sur la boucle principale
par defaut, on la vide explicitement avec
GLib.MainContext.default().iteration(False) apres chaque appel -- c'est ce
que fait _pump() ci-dessous.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib, Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

import netcross_gtk4.analysis_pipeline as analysis_pipeline_module  # noqa: E402
import netcross_gtk4.app as app_module  # noqa: E402
import netcross_gtk4.diff_pipeline as diff_pipeline_module  # noqa: E402
from netcross_gtk4.analysis_pipeline import AnalysisResult  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_gtk4.diff_pipeline import DiffResult  # noqa: E402


def _pump():
    """Vide la boucle d'evenements GLib -- necessaire pour que les rappels
    empiles par GLib.idle_add (journal, _on_analysis_done/_on_diff_done,
    _on_analysis_error) s'executent effectivement pendant le test."""
    ctx = GLib.MainContext.default()
    while ctx.iteration(False):
        pass


def _log_text(window):
    buf = window.log_view.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test427")
    app.register(None)
    return MainWindow(app)


# ================= _run_analysis_thread / _on_progress imbrique =================


def test_run_analysis_thread_succes_relaye_la_progression_et_le_resultat(window, monkeypatch):
    """Le pipeline est appele avec les bonnes captures, sa progression
    remonte au journal via le _on_progress imbrique (GLib.idle_add), et le
    resultat est route vers _on_analysis_done -- page Resultats affichee,
    boutons d'export reactives."""
    captures_recues = []

    def fake_pipeline(captures, options, on_progress=None):
        captures_recues.append(captures)
        if on_progress:
            on_progress("etape de test")
        return AnalysisResult(
            mode="single",
            report=None,
            flows=[],
            findings=None,
            text="rapport ok",
            tls_findings=None,
            quic_findings=None,
            wireshark_expert_events=[],
            security_report=None,
        )

    monkeypatch.setattr(analysis_pipeline_module, "run_analysis_pipeline", fake_pipeline)
    window._annotation_captures = None
    window.run_btn.set_sensitive(False)
    window.pdf_btn.set_sensitive(False)
    window.csv_btn.set_sensitive(False)
    window.json_btn.set_sensitive(False)

    window._run_analysis_thread(
        [("A", "/tmp/a.pcap")],
        1000.0,
        8000,
        False,
        False,
        True,
        False,
        5,
        False,
        False,
        False,
        False,
        25,
        False,
        False,
        2.0,
    )
    _pump()

    assert captures_recues == [[("A", "/tmp/a.pcap")]]
    assert "etape de test" in _log_text(window)
    assert window.last_mode == "single"
    assert (
        window.result_view.get_buffer().get_text(
            window.result_view.get_buffer().get_start_iter(),
            window.result_view.get_buffer().get_end_iter(),
            False,
        )
        == "rapport ok"
    )
    assert window.run_btn.get_sensitive()
    assert window.pdf_btn.get_sensitive()
    assert window.csv_btn.get_sensitive()
    assert window.json_btn.get_sensitive()
    assert window.stack.get_visible_child_name() == "results"


def test_run_analysis_thread_erreur_desactive_puis_reactive_le_bouton(window, monkeypatch):
    """Une exception levee dans le pipeline ne doit jamais faire planter le
    thread de fond : elle est journalisee puis routee vers
    _on_analysis_error, qui affiche le message et redonne la main sur le
    bouton Lancer."""

    def fake_pipeline(captures, options, on_progress=None):
        raise RuntimeError("boom analyse")

    monkeypatch.setattr(analysis_pipeline_module, "run_analysis_pipeline", fake_pipeline)
    window.run_btn.set_sensitive(False)

    window._run_analysis_thread(
        [("A", "/tmp/a.pcap")],
        1000.0,
        8000,
        False,
        False,
        True,
        False,
        5,
        False,
        False,
        False,
        False,
        25,
        False,
        False,
        2.0,
    )
    _pump()

    assert "ERREUR : boom analyse" in _log_text(window)
    assert "boom analyse" in window.work_status_label.get_text()
    assert window.run_btn.get_sensitive()


# ================= _run_diff_thread / _on_progress imbrique =================


def test_run_diff_thread_succes_relaye_la_progression_et_le_resultat(window, monkeypatch):
    captures_recues = []

    def fake_pipeline(baseline_captures, current_captures, options, on_progress=None):
        captures_recues.append((baseline_captures, current_captures))
        if on_progress:
            on_progress("etape de comparaison")
        return DiffResult(
            mode="diff",
            findings=[],
            baseline_report=None,
            current_report=None,
            text="comparaison ok",
            tls_findings_baseline=None,
            tls_findings_current=None,
            quic_findings_baseline=None,
            quic_findings_current=None,
        )

    monkeypatch.setattr(diff_pipeline_module, "run_diff_pipeline", fake_pipeline)
    window.run_btn.set_sensitive(False)

    window._run_diff_thread(
        [("A", "/tmp/base.pcap")],
        [("A", "/tmp/cur.pcap")],
        1000.0,
        8000,
        False,
        False,
        True,
        5.0,
        2.0,
        False,
        False,
        False,
    )
    _pump()

    assert captures_recues == [([("A", "/tmp/base.pcap")], [("A", "/tmp/cur.pcap")])]
    assert "etape de comparaison" in _log_text(window)
    assert window.last_mode == "diff"
    assert window.run_btn.get_sensitive()
    assert window.pdf_btn.get_sensitive()
    assert window.csv_btn.get_sensitive()
    assert window.stack.get_visible_child_name() == "results"


def test_run_diff_thread_erreur_route_vers_on_analysis_error(window, monkeypatch):
    """_run_diff_thread partage le meme chemin d'erreur que
    _run_analysis_thread : _on_analysis_error, pas un gestionnaire dedie."""

    def fake_pipeline(baseline_captures, current_captures, options, on_progress=None):
        raise RuntimeError("boom diff")

    monkeypatch.setattr(diff_pipeline_module, "run_diff_pipeline", fake_pipeline)
    window.run_btn.set_sensitive(False)

    window._run_diff_thread(
        [("A", "/tmp/base.pcap")],
        [("A", "/tmp/cur.pcap")],
        1000.0,
        8000,
        False,
        False,
        True,
        5.0,
        2.0,
        False,
        False,
        False,
    )
    _pump()

    assert "ERREUR : boom diff" in _log_text(window)
    assert "boom diff" in window.work_status_label.get_text()
    assert window.run_btn.get_sensitive()


def test_on_analysis_done_charge_les_annotations_si_des_captures_sont_analysees(window, monkeypatch):
    """Quand des captures annotables ont ete utilisees pour l'analyse
    (self._annotation_captures non vide), _on_analysis_done doit charger
    le panneau d'annotations plutot que de le vider."""
    appels = []
    monkeypatch.setattr(window.annotations_panel, "load", lambda captures: appels.append(captures))
    window._annotation_captures = ["/tmp/a.pcap"]

    window._on_analysis_done("single", None, [], None, "rapport ok", None, None, [], None)

    assert appels == [["/tmp/a.pcap"]]


# ================= _on_analysis_error (appel direct) =================


def test_on_analysis_error_affiche_le_message_et_reactive_le_bouton(window):
    window.run_btn.set_sensitive(False)
    window._on_analysis_error("panne synthetique")
    assert window.work_status_label.get_text() == "Erreur : panne synthetique"
    assert window.run_btn.get_sensitive()


# ================= export CSV =================


class _FakeFileDialog:
    """Doublure de Gtk.FileDialog : verifie l'etat du dialogue (nom
    initial propose, appel a .save()) sans jamais toucher a un vrai
    selecteur systeme -- meme approche que le selecteur de captures
    (CaptureListPanel._on_add_clicked, cf. lot 2 de l'issue #421)."""

    last_instance = None

    def __init__(self):
        self.initial_name = None
        self.saved_with = None
        _FakeFileDialog.last_instance = self

    def set_initial_name(self, name):
        self.initial_name = name

    def save(self, parent, cancellable, callback):
        self.saved_with = (parent, cancellable, callback)


def test_on_export_csv_propose_le_bon_nom_selon_le_mode(window, monkeypatch):
    monkeypatch.setattr(Gtk, "FileDialog", _FakeFileDialog)

    window.last_mode = "single"
    window.on_export_csv(None)
    dlg = _FakeFileDialog.last_instance
    assert dlg.initial_name == "details_flux.csv"
    assert dlg.saved_with is not None

    window.last_mode = "diff"
    window.on_export_csv(None)
    dlg = _FakeFileDialog.last_instance
    assert dlg.initial_name == "ecarts.csv"


def test_on_export_csv_sans_run_prealable_ne_fait_rien(window, monkeypatch):
    monkeypatch.setattr(Gtk, "FileDialog", _FakeFileDialog)
    _FakeFileDialog.last_instance = None
    window.last_mode = None
    window.on_export_csv(None)
    assert _FakeFileDialog.last_instance is None


class _FakeGFile:
    def __init__(self, path):
        self._path = path

    def get_path(self):
        return self._path


class _FakeSaveDialog:
    """Doublure de resultat de Gtk.FileDialog.save() : soit un chemin
    choisi (save_finish renvoie un Gio.File), soit une annulation
    (save_finish leve GLib.Error, comme le fait GTK)."""

    def __init__(self, path=None, cancelled=False):
        self._path = path
        self._cancelled = cancelled

    def save_finish(self, result):
        if self._cancelled:
            raise GLib.Error("annulation")
        return _FakeGFile(self._path)


def test_on_csv_path_chosen_mode_single_appelle_write_detail_csv(window, monkeypatch, tmp_path):
    appels = []
    monkeypatch.setattr(
        app_module,
        "write_detail_csv",
        lambda path, flows, points: appels.append((path, flows, points)),
    )
    window.last_mode = "single"
    window.last_flows = ["flow-1"]
    window.last_report = SimpleNamespace(points=["A", "B"])
    dest = str(tmp_path / "details_flux.csv")

    window._on_csv_path_chosen(_FakeSaveDialog(dest), None)

    assert appels == [(dest, ["flow-1"], ["A", "B"])]
    assert f"CSV ecrit : {dest}" == window.status_label.get_text()


def test_on_csv_path_chosen_mode_diff_appelle_write_diff_csv(window, monkeypatch, tmp_path):
    appels = []
    monkeypatch.setattr(
        app_module,
        "write_diff_csv",
        lambda findings, path: appels.append((findings, path)),
    )
    window.last_mode = "diff"
    window.last_diff_findings = ["ecart-1"]
    dest = str(tmp_path / "ecarts.csv")

    window._on_csv_path_chosen(_FakeSaveDialog(dest), None)

    assert appels == [(["ecart-1"], dest)]
    assert f"CSV ecrit : {dest}" == window.status_label.get_text()


def test_on_csv_path_chosen_annulation_n_ecrit_rien(window, monkeypatch):
    appels = []
    monkeypatch.setattr(app_module, "write_detail_csv", lambda *a: appels.append(a))
    monkeypatch.setattr(app_module, "write_diff_csv", lambda *a: appels.append(a))
    window.last_mode = "single"
    window.status_label.set_text("etat precedent")

    window._on_csv_path_chosen(_FakeSaveDialog(cancelled=True), None)

    assert appels == []
    # l'annulation ne touche pas au statut affiche -- pas d'exception non plus
    assert window.status_label.get_text() == "etat precedent"


def test_on_csv_path_chosen_erreur_ecriture_affiche_le_message(window, monkeypatch, tmp_path):
    def _echec(*_args):
        raise OSError("disque plein")

    monkeypatch.setattr(app_module, "write_detail_csv", _echec)
    window.last_mode = "single"
    window.last_flows = []
    window.last_report = SimpleNamespace(points=[])
    dest = str(tmp_path / "x.csv")

    window._on_csv_path_chosen(_FakeSaveDialog(dest), None)

    assert "Erreur CSV : disque plein" in window.status_label.get_text()


# ================= export PDF (declenchement uniquement, lot 6) =================


def test_on_export_pdf_propose_le_bon_nom_selon_le_mode(window, monkeypatch):
    monkeypatch.setattr(Gtk, "FileDialog", _FakeFileDialog)

    window.last_mode = "single"
    window.on_export_pdf(None)
    dlg = _FakeFileDialog.last_instance
    assert dlg.initial_name == "rapport_analyse.pdf"
    assert dlg.saved_with is not None

    window.last_mode = "diff"
    window.on_export_pdf(None)
    dlg = _FakeFileDialog.last_instance
    assert dlg.initial_name == "rapport_comparaison.pdf"


def test_on_export_pdf_sans_run_prealable_ne_fait_rien(window, monkeypatch):
    monkeypatch.setattr(Gtk, "FileDialog", _FakeFileDialog)
    _FakeFileDialog.last_instance = None
    window.last_mode = None
    window.on_export_pdf(None)
    assert _FakeFileDialog.last_instance is None
