"""Issue #676 : notifications (webhook, Slack, courriel) apres une analyse de
la GUI, equivalent de --notify-on / --notify-webhook / --notify-slack /
--notify-email / --notify-detail. Partie sans GTK : module et pipeline."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from conftest import make_pkt

import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_core.config import NotifyConfig
from netcross_core.notify.dispatch import DeliveryResult
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline
from netcross_gtk4.notifications import (
    THRESHOLD_CHOICES,
    NotifySettings,
    send_notifications,
    settings_from_widgets,
    validate_settings,
)


def test_menu_commence_par_desactive_puis_les_seuils_de_la_cli():
    assert THRESHOLD_CHOICES[0][0] is None
    assert [v for v, _l in THRESHOLD_CHOICES[1:]] == ["critique", "elevee", "moyenne", "faible"]


def test_reglages_depuis_les_widgets():
    s = settings_from_widgets(2, "  https://hook.example/x ", "", " a@b.fr ", True)
    assert s == NotifySettings("elevee", "https://hook.example/x", None, "a@b.fr", "complet")
    assert s.active
    assert not settings_from_widgets(0, "https://x", "", "", False).active
    assert settings_from_widgets(99, "", "", "", False).threshold is None


def test_validation_sans_seuil_toujours_valide():
    assert validate_settings(NotifySettings(), security=False) == []


def test_validation_exige_le_rapport_de_securite():
    erreurs = validate_settings(NotifySettings("critique"), security=False)
    assert any("Rapport de securite" in e for e in erreurs)


def test_validation_refuse_les_url_non_http():
    erreurs = validate_settings(
        NotifySettings("critique", webhook="file:///etc/passwd", slack="ftp://x"), security=True
    )
    assert any(e.startswith("URL webhook invalide") for e in erreurs)
    assert any(e.startswith("URL Slack invalide") for e in erreurs)


def test_validation_seuil_et_detail_inconnus():
    erreurs = validate_settings(NotifySettings("enorme", detail="bavard"), security=True)
    assert "seuil inconnu : enorme" in erreurs
    assert "niveau de detail inconnu : bavard" in erreurs


def test_validation_reglages_corrects():
    s = NotifySettings("moyenne", webhook="https://hook.example/x", slack="https://hooks.slack.com/y")
    assert validate_settings(s, security=True) == []


def _rapports(score=80, level="critique"):
    report = SimpleNamespace(security_findings=[{"severity": "critique", "type": "beaconing", "detail": "x"}])
    security = SimpleNamespace(dashboard=SimpleNamespace(score=score, level=level))
    return report, security


def test_envoi_transmet_les_reglages_et_le_resume():
    appels = {}

    def runner(factory, **kw):
        appels.update(kw)
        appels["summary"] = factory(kw["threshold"])
        return [DeliveryResult("webhook", "envoye")]

    report, security = _rapports()
    settings = NotifySettings("elevee", webhook="https://hook.example/x", email="a@b.fr", detail="complet")
    lignes = send_notifications(
        report, security, settings, runner=runner, config_loader=lambda: SimpleNamespace(notify=NotifyConfig())
    )
    assert [ligne["channel"] for ligne in lignes] == ["webhook"]
    assert "envoyee" in lignes[0]["line"]
    assert appels["threshold"] == "elevee"
    assert appels["webhook"] == "https://hook.example/x"
    assert appels["slack"] is None
    assert appels["email_to"] == "a@b.fr"
    assert appels["summary"].score == 80


def test_envoi_inactif_sans_seuil_ou_sans_rapport():
    report, security = _rapports()
    jamais = pytest.fail
    assert send_notifications(report, security, NotifySettings(), runner=jamais) == []
    assert send_notifications(report, None, NotifySettings("critique"), runner=jamais) == []


def test_envoi_ne_leve_jamais():
    def casse(*a, **k):
        raise RuntimeError("SMTP en panne")

    report, security = _rapports()
    lignes = send_notifications(
        report,
        security,
        NotifySettings("critique", email="a@b.fr"),
        runner=casse,
        config_loader=lambda: SimpleNamespace(notify=NotifyConfig()),
    )
    assert lignes[0]["status"] == "echec"
    assert "SMTP en panne" in lignes[0]["line"]


def test_envoi_avec_la_vraie_configuration_sans_canal(monkeypatch, tmp_path):
    """Seuil sans aucun canal configure : ligne « non configuree », aucun appel reseau."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in ("NETCROSS_SLACK_WEBHOOK", "NETCROSS_SMTP_HOST", "NETCROSS_NOTIFY_WEBHOOK"):
        monkeypatch.delenv(var, raising=False)
    report, security = _rapports()
    lignes = send_notifications(report, security, NotifySettings("critique"))
    assert lignes, "une ligne de tracabilite est attendue"
    assert all(ligne["status"] != "envoye" for ligne in lignes)


# -- pipeline de la GUI --


@pytest.fixture
def _pipeline_securite(monkeypatch):
    pkts = [make_pkt(point="A", sport=1), make_pkt(point="B", sport=1, ts=1000.001)]
    monkeypatch.setattr(pipeline_mod, "parse_capture", lambda label, path: [p for p in pkts if p.point == label])
    sr = SimpleNamespace(dashboard=SimpleNamespace(score=90, level="critique"), notifications=[])
    monkeypatch.setattr(pipeline_mod, "run_security_analysis", lambda *a: sr)
    monkeypatch.setattr(pipeline_mod, "print_security_report", lambda r: print("RAPPORT SECURITE"))
    return sr


def test_pipeline_envoie_et_trace_les_notifications(monkeypatch, _pipeline_securite):
    envoyes = []

    def faux_envoi(report, security_report, settings):
        envoyes.append(settings)
        return [DeliveryResult("slack", "envoye").to_dict()]

    monkeypatch.setattr(pipeline_mod, "send_notifications", faux_envoi)
    journal = []
    settings = NotifySettings("critique", slack="https://hooks.slack.com/x")
    result = run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(parallel=False, security=True, notify=settings),
        on_progress=journal.append,
    )
    assert envoyes == [settings]
    assert result.security_report.notifications[0]["channel"] == "slack"
    assert any("notification slack : envoyee" in ligne for ligne in journal)


def test_pipeline_sans_securite_ignore_les_notifications(monkeypatch, _pipeline_securite):
    monkeypatch.setattr(pipeline_mod, "send_notifications", lambda *a: pytest.fail("aucun envoi attendu"))
    journal = []
    run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(parallel=False, security=False, notify=NotifySettings("critique")),
        on_progress=journal.append,
    )
    assert any("Notifications ignorees" in ligne for ligne in journal)


def test_pipeline_sans_seuil_aucun_envoi(monkeypatch, _pipeline_securite):
    monkeypatch.setattr(pipeline_mod, "send_notifications", lambda *a: pytest.fail("aucun envoi attendu"))
    result = run_analysis_pipeline(
        [("A", "a.pcap"), ("B", "b.pcap")],
        AnalysisOptions(parallel=False, security=True, notify=NotifySettings()),
    )
    assert result.security_report.notifications == []
