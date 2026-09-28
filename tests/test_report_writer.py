"""Issue #695 (suite de #665) : branches restantes de ``netcross_ai.report_writer``.

Complete ``tests/test_ai_module.py`` (qui couvre le chemin nominal) avec les
branches jamais prises : correlations sans hote, evenements de mouvement
lateral, signaux IA, recommandations dedupliquees, resume avec anomalies IA
et reponse vide du modele local. Aucun reseau : ``_post_json`` est remplace.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netcross_ai import report_writer
from netcross_ai.report_writer import llm_generate, template_summary, write_summary


def _ai(anomalies=None, classification=None):
    return {"anomalies": anomalies or [], "classification": classification or []}


# -- _correlations ---------------------------------------------------------------


def test_correlations_ignorent_constats_et_evenements_sans_hote():
    report = SimpleNamespace(
        security_findings=[
            {"severity": "faible", "category": "anomalie"},  # sans hote : ignore
            {"severity": "faible", "category": "anomalie", "host": "10.0.0.9"},
        ],
        lateral_movement_events=[
            {"type": "smb"},  # sans source : ignore
            {"source": "10.0.0.9", "type": "smb"},
            {"source": "10.0.0.8"},  # type absent -> « ? », un seul signal : pas de correlation
        ],
    )
    assert template_summary(report).correlations == ["10.0.0.9 cumule 2 signaux (anomalie, mouvement lateral (smb))."]


def test_correlations_signal_ia_rattache_a_la_source_du_flux():
    report = SimpleNamespace(security_findings=[{"severity": "elevee", "category": "exploit", "host": "10.0.0.66"}])
    ai = _ai(
        anomalies=[
            {"flow": "10.0.0.66 -> 203.0.113.9", "is_anomaly": True},
            {"flow": "10.0.0.1 -> 10.0.0.2", "is_anomaly": False},  # pas une anomalie : ignore
            {"is_anomaly": True},  # flux sans nom : hote vide, un seul signal
        ]
    )
    assert template_summary(report, ai).correlations == ["10.0.0.66 cumule 2 signaux (exploit, flux atypique (IA))."]


def test_correlations_cve_sans_exploit_n_affirme_pas_l_exploitation():
    report = SimpleNamespace(
        security_findings=[{"severity": "critique", "category": "cve", "host": "10.0.0.5", "cve_id": "CVE-2021-1"}],
        lateral_movement_events=[{"source": "10.0.0.5", "type": "rdp"}],
    )
    assert template_summary(report).correlations == [
        "10.0.0.5 cumule 2 signaux (CVE CVE-2021-1, mouvement lateral (rdp))."
    ]


# -- _recommendations -----------------------------------------------------------


def test_recommandations_dedupliquees_et_completes():
    cve = {
        "severity": "critique",
        "category": "cve",
        "host": "10.0.0.5",
        "service": "Apache",
        "version": "2.4.49",
        "cve_id": "CVE-2021-41773",
        "cvss": 7.5,
    }
    report = SimpleNamespace(
        security_findings=[
            cve,
            {**cve},  # doublon exact : une seule recommandation
            {"severity": "elevee", "category": "exploit"},  # sans hote
            {"severity": "moyenne", "category": "cve", "cve_id": "CVE-2020-0001"},  # sans service ni CVSS
            {"severity": "faible", "category": "anomalie"},  # ni CVE ni exploit : rien
        ],
        dga_alerts=[{"domain": "x.example"}],
        lateral_movement_events=[{"source": "10.0.0.7", "type": "rdp"}],
    )
    ai = _ai(
        anomalies=[{"flow": "10.0.0.1 -> 10.0.0.2", "is_anomaly": True}],
        classification=[
            {"flow": "10.0.0.66 -> 203.0.113.9", "label": "c2", "confidence": 0.87},
            {"flow": "10.0.0.1 -> 10.0.0.3", "label": "normal", "confidence": 0.99},  # etiquette sans risque
            {"flow": "10.0.0.1 -> 10.0.0.4", "label": "tunnel", "confidence": 0.3},  # confiance trop faible
            {"flow": "10.0.0.1 -> 10.0.0.5", "label": "exfiltration"},  # confiance absente
        ],
    )
    assert template_summary(report, ai).recommendations == [
        "Mettre a jour Apache 2.4.49 sur 10.0.0.5 (CVE-2021-41773, CVSS 7.5).",
        "Isoler et examiner la machine ciblee : signature d'exploitation observee.",
        "Mettre a jour le service concerne (CVE-2020-0001).",
        "Verifier le flux 10.0.0.66 -> 203.0.113.9 classe « c2 » (confiance 87%).",
        "Bloquer ou surveiller au resolveur les domaines de type DGA releves.",
        "Controler la segmentation et les comptes utilises par les sources de mouvements lateraux.",
        "Examiner les flux signales atypiques par rapport a la baseline (detail dans la section IA).",
    ]


def test_recommandation_ia_absente_sans_anomalie():
    ai = _ai(anomalies=[{"flow": "a -> b", "is_anomaly": False}])
    assert template_summary(SimpleNamespace(), ai).recommendations == []


# -- template_summary -----------------------------------------------------------


def test_resume_signale_les_flux_ecartes_de_la_baseline():
    ai = _ai(anomalies=[{"flow": "a -> b", "is_anomaly": True}, {"flow": "c -> d", "is_anomaly": False}])
    assert template_summary(SimpleNamespace(), ai).text == (
        "Aucun constat de securite n'a ete releve sur cette capture. "
        "1 flux s'ecartent nettement de la baseline de trafic normal."
    )


# -- llm_generate ---------------------------------------------------------------


@pytest.mark.parametrize("kind", ["ollama", "llamacpp"])
@pytest.mark.parametrize("answer", [{}, {"response": "", "content": ""}, {"response": " \n\t", "content": " \n\t"}])
def test_llm_generate_reponse_vide_leve_runtime_error(monkeypatch, kind, answer):
    monkeypatch.setattr(report_writer, "_post_json", lambda url, payload, timeout: answer)
    with pytest.raises(RuntimeError, match="reponse vide du modele"):
        llm_generate(kind, "m", "http://127.0.0.1:1", "prompt")


def test_write_summary_repli_gabarit_sur_reponse_vide(monkeypatch):
    monkeypatch.setattr(report_writer, "_post_json", lambda url, payload, timeout: {"response": "  "})
    s = write_summary(SimpleNamespace(), engine="ollama:llama3", endpoint="http://127.0.0.1:11434")
    assert s.engine == "template"
    assert s.fallback_reason == "modele local indisponible (reponse vide du modele) : resume par gabarit"
