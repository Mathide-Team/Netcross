"""Traces loguru des dialogues d'export de la fenêtre GTK (issue #245).

Les callbacks ``_on_pdf_path_chosen``, ``_on_json_path_chosen`` et
``_on_security_path_chosen`` journalisent le chemin RÉELLEMENT choisi dans
le dialogue, comme ``_on_csv_path_chosen`` le faisait déjà -- auparavant la
trace se limitait à « chemin choisi », inutile pour diagnostiquer un export
écrit au mauvais endroit (idée reprise de la PR #448).

Sauté si pygobject, GTK4 ou un affichage manquent (voir gtk4_display.py) ;
exécuté par le job CI « Tests GTK4 (Xvfb) ».
"""

import pytest
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()

from loguru import logger  # noqa: E402

from netcross_gtk4.app import MainWindow  # noqa: E402


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test245exports")
    app.register(None)
    return MainWindow(app)


@pytest.fixture
def traces():
    """Messages DEBUG émis par netcross_gtk4.app pendant le test."""
    messages = []
    sink = logger.add(
        lambda m: messages.append(m.record["message"]),
        level="DEBUG",
        filter=lambda r: r["name"] == "netcross_gtk4.app",
    )
    yield messages
    logger.remove(sink)


class _GFileCompte:
    """Gio.File minimal ; compte les appels à get_path()."""

    def __init__(self, path):
        self._path = path
        self.appels = 0

    def get_path(self):
        self.appels += 1
        return self._path


class _DialogueCheminChoisi:
    def __init__(self, gfile):
        self._gfile = gfile

    def save_finish(self, _result):
        return self._gfile


@pytest.mark.parametrize(
    ("callback", "export"),
    [
        ("_on_pdf_path_chosen", "export_pdf_to"),
        ("_on_json_path_chosen", "export_json_to"),
        ("_on_security_path_chosen", "export_security_to"),
    ],
)
def test_le_chemin_choisi_est_journalise_et_transmis(window, monkeypatch, tmp_path, traces, callback, export):
    exports = []
    monkeypatch.setattr(window, export, exports.append)
    chemin = str(tmp_path / "sortie avec espace.bin")
    gfile = _GFileCompte(chemin)

    getattr(window, callback)(_DialogueCheminChoisi(gfile), None)

    assert exports == [chemin]
    assert f"{callback}: chemin choisi {chemin}" in traces
    # un seul get_path() : la trace et l'export portent le même chemin
    assert gfile.appels == 1
