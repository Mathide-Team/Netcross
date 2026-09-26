"""
Tests app.py -- Lot 9/10 (issue #430, sous-issue de #421) : cartographie des
communications, threads d'export PDF/JSON, declenchement de l'export
securite (lignes 2366-2593 de src/netcross_gtk4/app.py).

Methodes couvertes : `_comm_map_filters`, `_refresh_comm_map`,
`_generate_pdf_thread`, `_on_pdf_error`, `_on_pdf_done`, `on_export_json`,
`_on_json_path_chosen`, `export_json_to`, `_generate_json_thread`,
`_on_json_error`, `_on_json_done`, `on_export_security`.

Meme garde-fou GTK4/CI que `tests/test_gui_security_window.py` : GTK4 n'est
pas installable partout (serveur de CI sans libgtk-4/affichage), donc tout
le module est ignore dans ce cas plutot que d'echouer -- aucun test n'exige
GTK4 en CI (critere d'acceptation commun aux dix lots de #421).

Les threads d'export (`_generate_pdf_thread`/`_generate_json_thread`)
appellent `GLib.idle_add(...)` pour revenir sur le thread principal ; sans
boucle GLib en cours d'execution ici, `GLib.idle_add` est remplace par un
appel synchrone immediat (meme esprit que les doublures de threading
utilisees ailleurs dans la suite -- voir `tests/test_notify.py`). Le
pipeline PDF reel (reportlab/matplotlib/networkx) est monkeypatche : ces
dependances sont optionnelles et le contrat verifie ici est le cablage GUI
(succes -> `_on_pdf_done` ; exception -> `_on_pdf_error`), pas le rendu
PDF lui-meme (deja teste dans `tests/test_pdf_report.py`). Le pipeline JSON
est pur Python (voir `netcross_report.json_report`) : le chemin de succes
utilise le vrai `generate_json_report`, seul le chemin d'erreur est
simule. `_session_objects()` (parite JSON/PDF) est deja couvert par
`tests/test_gui_json_parity.py` -- on verifie seulement ici que les
threads l'appellent, sans dupliquer ce test.

Le selecteur de fichiers (`Gtk.FileDialog`) est remplace par une doublure
minimale pour piloter `save()`/`save_finish()` sans ouvrir de vrai
selecteur (pas de portail D-Bus disponible en CI) -- meme necessite que
les callbacks GLib ci-dessus.
"""

from __future__ import annotations

import pathlib

import pytest
from conftest import make_pkt

gi = pytest.importorskip("gi", reason="pygobject absent")
try:
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib, Gtk
except (ValueError, ImportError):
    pytest.skip("GTK4 absent", allow_module_level=True)
if not Gtk.init_check():
    pytest.skip("pas d'affichage pour GTK4", allow_module_level=True)

import netcross_gtk4.app as app_module  # noqa: E402
import netcross_report  # noqa: E402
from netcross_core.analysis import analyse  # noqa: E402
from netcross_core.correlate import correlate  # noqa: E402
from netcross_core.models import Report  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_report.security_report import SecurityReport  # noqa: E402


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test430")
    app.register(None)
    return MainWindow(app)


def _analysis_result():
    """Report + flows minimaux mais reels (2 points, TCP et UDP), assez
    pour que `build_comm_map`/`available_protocols` aient de quoi filtrer --
    meme esprit que la fixture de `tests/test_gui_security_window.py`."""
    pkts = [
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP", sport=1111, dport=443, frame_number=1),
        make_pkt(point="B", src="10.0.0.1", dst="10.0.0.2", proto="TCP", sport=1111, dport=443, frame_number=1),
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.3", proto="UDP", sport=2222, dport=53, frame_number=2),
        make_pkt(point="B", src="10.0.0.1", dst="10.0.0.3", proto="UDP", sport=2222, dport=53, frame_number=2),
    ]
    flows = correlate(pkts)
    report = analyse(flows, ["A", "B"], pkts)
    return report, flows


def _appliquer_run_single(window, report, flows):
    """Etat minimal d'un run "single" termine -- suffisant pour
    `_generate_pdf_thread`/`_generate_json_thread`/`_session_objects`."""
    window.last_mode = "single"
    window.last_report = report
    window.last_flows = flows
    window.last_findings = None
    window.last_tls_findings = None
    window.last_quic_findings = None
    window.last_wireshark_expert_events = None
    window.last_security_report = None


def _run_idle_now(fn, *args, **kwargs):
    """Remplace `GLib.idle_add` : execute la callback tout de suite plutot
    que de l'empiler pour une boucle GLib qui ne tourne pas ici."""
    fn(*args, **kwargs)
    return 0


class _SyncThread:
    """Remplace `threading.Thread` : `start()` execute la cible
    immediatement, dans l'appelant -- rend `export_json_to` deterministe
    sans faire tourner un vrai thread d'arriere-plan dans le test."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


class _FakeGFile:
    def __init__(self, path):
        self._path = path

    def get_path(self):
        return self._path


class _FakeSaveDialog:
    """Remplace `Gtk.FileDialog` : `save()` appelle la callback
    immediatement avec un chemin fixe, `save_finish()` le restitue --
    aucun selecteur reel n'est ouvert."""

    def __init__(self, path):
        self._path = path
        self.initial_name = None

    def set_initial_name(self, name):
        self.initial_name = name

    def save(self, parent, cancellable, callback):
        callback(self, None)

    def save_finish(self, result):
        return _FakeGFile(self._path)


# ======================= cartographie des communications =======================


def test_comm_map_filters_lit_les_widgets(window):
    _report, flows = _analysis_result()
    window.last_flows = flows
    window._reset_comm_map_filters()

    model = window.comm_proto_drop.get_model()
    protocoles = [model.get_string(i) for i in range(model.get_n_items())]
    assert protocoles[0] == "Tous"
    assert set(protocoles[1:]) == {"TCP", "UDP"}

    window.comm_proto_drop.set_selected(protocoles.index("TCP"))
    window.comm_topn_spin.set_value(3)
    window.comm_anomalies_check.set_active(True)

    assert window._comm_map_filters() == {"protocols": ["TCP"], "top_n": 3, "only_anomalies": True}


def test_comm_map_filters_protocole_tous_donne_aucun_filtre(window):
    _report, flows = _analysis_result()
    window.last_flows = flows
    window._reset_comm_map_filters()
    window.comm_proto_drop.set_selected(0)
    window.comm_anomalies_check.set_active(False)

    filtres = window._comm_map_filters()
    assert filtres["protocols"] is None
    assert filtres["only_anomalies"] is False


def test_comm_map_filters_sans_modele(window):
    """Cas defensif : `comm_proto_drop` sans modele (jamais le cas en
    usage normal, la fenetre en pose toujours un a la construction)."""
    _report, flows = _analysis_result()
    window.last_flows = flows
    window._reset_comm_map_filters()
    window.comm_proto_drop.set_model(None)

    filtres = window._comm_map_filters()
    assert filtres["protocols"] is None


def test_refresh_comm_map_sans_flux_desactive_la_vue(window):
    window.last_flows = None
    window._refresh_comm_map()
    assert window.comm_map_picture.get_file() is None
    assert window.comm_map_label.get_text() == "Cartographie disponible apres une analyse simple."


def test_refresh_comm_map_avec_flux_dessine_la_carte(window):
    pytest.importorskip("matplotlib")
    pytest.importorskip("networkx")
    _report, flows = _analysis_result()
    window.last_flows = flows
    window._reset_comm_map_filters()

    assert window.comm_map_picture.get_file() is not None
    assert "arete" in window.comm_map_label.get_text()


def test_refresh_comm_map_erreur_rendu_affiche_le_message(window, monkeypatch):
    _report, flows = _analysis_result()
    window.last_flows = flows

    def _boom(*_a, **_k):
        raise RuntimeError("rendu impossible")

    monkeypatch.setattr("netcross_report.charts.chart_comm_map", _boom)
    window._refresh_comm_map()

    assert window.comm_map_picture.get_file() is None
    assert window.comm_map_label.get_text() == "Cartographie indisponible : rendu impossible"


# ============================= export PDF (thread) =============================


def test_generate_pdf_thread_single_succes(window, monkeypatch, tmp_path):
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)

    dest = str(tmp_path / "rapport.pdf")
    ecrit = {}

    def _fake_generate_pdf(report_, path, **kwargs):
        ecrit["path"] = path
        ecrit["kwargs"] = kwargs
        pathlib.Path(path).write_bytes(b"%PDF-1.4 factice")
        return path

    monkeypatch.setattr(netcross_report, "generate_pdf", _fake_generate_pdf)

    window._generate_pdf_thread(dest)

    assert ecrit["path"] == dest
    assert "session_objects" in ecrit["kwargs"]
    assert f"PDF ecrit : {dest}" == window.status_label.get_text()


def test_generate_pdf_thread_single_sans_generate_pdf(window, monkeypatch, tmp_path):
    """`generate_pdf is None` (reportlab/matplotlib/networkx absents) :
    l'ImportError est capturee comme toute autre exception du thread."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)
    monkeypatch.setattr(netcross_report, "generate_pdf", None)

    window._generate_pdf_thread(str(tmp_path / "rapport.pdf"))

    assert window.status_label.get_text() == "Erreur PDF : reportlab/matplotlib/networkx requis pour l'export PDF"


def test_generate_pdf_thread_diff_sans_generate_diff_pdf(window, monkeypatch, tmp_path):
    window.last_mode = "diff"
    window.last_diff_findings = []
    window.last_baseline_report = Report(points=["A"])
    window.last_current_report = Report(points=["B"])
    window.last_diff_tls_findings_baseline = None
    window.last_diff_tls_findings_current = None
    window.last_diff_quic_findings_baseline = None
    window.last_diff_quic_findings_current = None
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)
    monkeypatch.setattr(netcross_report, "generate_diff_pdf", None)

    window._generate_pdf_thread(str(tmp_path / "comparaison.pdf"))

    assert window.status_label.get_text() == "Erreur PDF : reportlab/matplotlib/networkx requis pour l'export PDF"


def test_generate_pdf_thread_diff_succes(window, monkeypatch, tmp_path):
    window.last_mode = "diff"
    window.last_diff_findings = []
    window.last_baseline_report = Report(points=["A"])
    window.last_current_report = Report(points=["B"])
    window.last_diff_tls_findings_baseline = None
    window.last_diff_tls_findings_current = None
    window.last_diff_quic_findings_baseline = None
    window.last_diff_quic_findings_current = None
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)

    dest = str(tmp_path / "comparaison.pdf")
    appele = {}

    def _fake_generate_diff_pdf(findings, baseline, current, path, **kwargs):
        appele["path"] = path
        pathlib.Path(path).write_bytes(b"%PDF-1.4 factice")
        return path

    monkeypatch.setattr(netcross_report, "generate_diff_pdf", _fake_generate_diff_pdf)

    window._generate_pdf_thread(dest)

    assert appele["path"] == dest
    assert f"PDF ecrit : {dest}" == window.status_label.get_text()


def test_generate_pdf_thread_erreur_appelle_on_pdf_error(window, monkeypatch, tmp_path):
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)

    def _boom(*_a, **_k):
        raise RuntimeError("echec pipeline pdf")

    monkeypatch.setattr(netcross_report, "generate_pdf", _boom)

    window._generate_pdf_thread(str(tmp_path / "rapport.pdf"))

    assert window.status_label.get_text() == "Erreur PDF : echec pipeline pdf"


def test_on_pdf_done_et_on_pdf_error_mettent_a_jour_le_statut(window):
    window._on_pdf_done("/tmp/rapport.pdf")
    assert window.status_label.get_text() == "PDF ecrit : /tmp/rapport.pdf"

    window._on_pdf_error("boum")
    assert window.status_label.get_text() == "Erreur PDF : boum"


# ============================= export JSON =============================


def test_on_export_json_sans_analyse_ne_fait_rien(window, monkeypatch):
    """Sans analyse (last_mode None), aucun dialogue n'est ouvert -- meme
    verification que pour on_export_security ci-dessous."""
    window.last_mode = None
    appels = {"n": 0}

    def _fake_dialog():
        appels["n"] += 1
        return _FakeSaveDialog("/tmp/inutilise")

    monkeypatch.setattr(app_module.Gtk, "FileDialog", _fake_dialog)

    window.on_export_json(None)

    assert appels["n"] == 0


def test_on_export_json_declenche_lexport_reel(window, monkeypatch, tmp_path):
    """Chaine complete : on_export_json -> _on_json_path_chosen ->
    export_json_to -> _generate_json_thread -> _on_json_done. Le pipeline
    JSON est pur Python (voir netcross_report.json_report) : pas besoin de
    doublure, le vrai `generate_json_report` est utilise."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)

    dest = str(tmp_path / "rapport_analyse.json")
    monkeypatch.setattr(app_module.Gtk, "FileDialog", lambda: _FakeSaveDialog(dest))
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)
    monkeypatch.setattr(app_module.threading, "Thread", _SyncThread)

    window.on_export_json(None)

    assert f"JSON ecrit : {dest}" == window.status_label.get_text()
    assert pathlib.Path(dest).exists()
    assert pathlib.Path(dest).read_text(encoding="utf-8")


def test_on_json_path_chosen_erreur_glib_ne_leve_pas(window, monkeypatch):
    """`dialog.save_finish` peut lever GLib.Error (ex. annulation par
    l'utilisateur) : `_on_json_path_chosen` l'avale sans appeler
    `export_json_to`."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    appele = {"n": 0}
    monkeypatch.setattr(window, "export_json_to", lambda _p: appele.__setitem__("n", appele["n"] + 1))

    class _DialogEnErreur:
        def save_finish(self, result):
            raise GLib.Error("annule par l'utilisateur")

    window._on_json_path_chosen(_DialogEnErreur(), None)

    assert appele["n"] == 0


def test_generate_json_thread_diff_succes(window, monkeypatch, tmp_path):
    window.last_mode = "diff"
    window.last_diff_findings = []
    window.last_baseline_report = Report(points=["A"])
    window.last_current_report = Report(points=["B"])
    window.last_diff_tls_findings_baseline = None
    window.last_diff_tls_findings_current = None
    window.last_diff_quic_findings_baseline = None
    window.last_diff_quic_findings_current = None
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)

    dest = str(tmp_path / "comparaison.json")
    appele = {}

    def _fake_generate_json_diff(findings, baseline, current, path, **kwargs):
        appele["path"] = path
        pathlib.Path(path).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(netcross_report, "generate_json_diff", _fake_generate_json_diff)

    window._generate_json_thread(dest)

    assert appele["path"] == dest
    assert f"JSON ecrit : {dest}" == window.status_label.get_text()


def test_generate_json_thread_erreur_appelle_on_json_error(window, monkeypatch, tmp_path):
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)

    def _boom(*_a, **_k):
        raise ValueError("echec pipeline json")

    monkeypatch.setattr(netcross_report, "generate_json_report", _boom)

    window._generate_json_thread(str(tmp_path / "rapport.json"))

    assert window.status_label.get_text() == "Erreur JSON : echec pipeline json"


def test_generate_json_thread_appelle_session_objects(window, monkeypatch, tmp_path):
    """Ne duplique pas tests/test_gui_json_parity.py : verifie seulement
    que le thread JSON passe bien par `_session_objects()`, pas la parite
    des cles qu'il produit."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    monkeypatch.setattr(app_module.GLib, "idle_add", _run_idle_now)

    original = window._session_objects
    appels = {"n": 0}

    def _espion():
        appels["n"] += 1
        return original()

    monkeypatch.setattr(window, "_session_objects", _espion)

    window._generate_json_thread(str(tmp_path / "rapport.json"))

    assert appels["n"] == 1
    assert "JSON ecrit" in window.status_label.get_text()


def test_on_json_done_et_on_json_error_mettent_a_jour_le_statut(window):
    window._on_json_done("/tmp/rapport.json")
    assert window.status_label.get_text() == "JSON ecrit : /tmp/rapport.json"

    window._on_json_error("boum")
    assert window.status_label.get_text() == "Erreur JSON : boum"


# ============================= export securite (declenchement) =============================


def test_on_export_security_sans_rapport_ne_fait_rien(window, monkeypatch):
    window.last_security_report = None
    appels = {"n": 0}

    def _fake_dialog():
        appels["n"] += 1
        return _FakeSaveDialog("/tmp/inutilise")

    monkeypatch.setattr(app_module.Gtk, "FileDialog", _fake_dialog)

    window.on_export_security(".html")

    assert appels["n"] == 0


def test_on_export_security_html_declenche_lexport(window, monkeypatch, tmp_path):
    window.last_security_report = SecurityReport()
    dest = str(tmp_path / "rapport_securite.html")
    monkeypatch.setattr(app_module.Gtk, "FileDialog", lambda: _FakeSaveDialog(dest))

    window.on_export_security(".html")

    assert f"Rapport de securite ecrit : {dest}" == window.status_label.get_text()
    assert pathlib.Path(dest).exists()


def test_on_export_security_json_declenche_lexport(window, monkeypatch, tmp_path):
    window.last_security_report = SecurityReport()
    dest = str(tmp_path / "rapport_securite.json")
    monkeypatch.setattr(app_module.Gtk, "FileDialog", lambda: _FakeSaveDialog(dest))

    window.on_export_security(".json")

    assert f"Rapport de securite ecrit : {dest}" == window.status_label.get_text()
    assert pathlib.Path(dest).exists()


def test_on_export_security_nom_initial_selon_le_suffixe(window, monkeypatch):
    window.last_security_report = SecurityReport()
    dialogues = []

    def _fake_dialog():
        d = _FakeSaveDialog("/tmp/x")
        dialogues.append(d)
        return d

    monkeypatch.setattr(app_module.Gtk, "FileDialog", _fake_dialog)

    window.on_export_security(".html")
    window.on_export_security(".json")

    assert dialogues[0].initial_name == "rapport_securite.html"
    assert dialogues[1].initial_name == "rapport_securite.json"
