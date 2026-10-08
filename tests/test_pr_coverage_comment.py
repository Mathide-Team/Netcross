"""Tests de scripts/pr_coverage_comment.py (couverture incrementale par PR).

Le script publie un commentaire sur la PR via l'API GitHub -- reseaux
systematiquement exclus des tests (meme convention que le reste du
projet) : on teste la construction du commentaire et la lecture des
totaux, pas les appels REST.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _charger_module():
    """Charge scripts/pr_coverage_comment.py comme module (pas de package)."""
    chemin = REPO_ROOT / "scripts" / "pr_coverage_comment.py"
    spec = importlib.util.spec_from_file_location("pr_coverage_comment", chemin)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr_coverage_comment"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pcc():
    return _charger_module()


TOTAUX_REFERENCE = {
    "percent_covered": 76.742,
    "covered_lines": 9391,
    "num_statements": 12255,
    "covered_branches": 4322,
    "num_branches": 4728,
}


def _ecrire_rapport(tmp_path, totaux, nom):
    chemin = tmp_path / nom
    chemin.write_text(json.dumps({"totals": totaux}), encoding="utf-8")
    return chemin


def test_marqueur_present_le_commentaire_est_identifiable(pcc):
    commentaire = pcc._construire_commentaire(TOTAUX_REFERENCE, TOTAUX_REFERENCE)
    assert pcc.MARQUEUR in commentaire


def test_construire_commentaire_valeurs_et_delta(pcc):
    base = dict(TOTAUX_REFERENCE, percent_covered=76.742, covered_lines=9391, covered_branches=4322)
    pr = dict(TOTAUX_REFERENCE, percent_covered=77.051, covered_lines=9431, covered_branches=4361)
    commentaire = pcc._construire_commentaire(pr, base)
    assert "| Couverture | 76.7 % | 77.1 % | +0.3 pt |" in commentaire
    assert "| Instructions couvertes | 9391/12255 | 9431/12255 | +40 |" in commentaire
    assert "| Branches couvertes | 4322/4728 | 4361/4728 | +39 |" in commentaire


def test_construire_commentaire_delta_negatif(pcc):
    pr = dict(TOTAUX_REFERENCE, percent_covered=75.0)
    commentaire = pcc._construire_commentaire(pr, TOTAUX_REFERENCE)
    assert "-1.7 pt" in commentaire


def test_lire_totaux_lit_le_rapport_coverage(pcc, tmp_path):
    chemin = _ecrire_rapport(tmp_path, TOTAUX_REFERENCE, "coverage-test.json")
    assert pcc._lire_totaux(str(chemin)) == TOTAUX_REFERENCE


def test_lire_totaux_fichier_absent_message_clair(pcc):
    with pytest.raises(FileNotFoundError):
        pcc._lire_totaux("/inexistant/coverage.json")


# -- seuil bloquant (issue #246) -------------------------------------------------


def test_lire_seuil_du_depot(pcc):
    """Le seuil lu par le script est celui qu'applique la CI : un seul chiffre."""
    import tomllib

    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pcc.lire_seuil() == float(config["tool"]["coverage"]["report"]["fail_under"])


def test_lire_seuil_ignore_les_autres_sections(pcc, tmp_path):
    fichier = tmp_path / "pyproject.toml"
    fichier.write_text(
        "[tool.autre]\nfail_under = 99\n\n"
        "[tool.coverage.report]\nprecision = 1\nfail_under = 75.5\n\n"
        "[tool.x]\ny = 1\n",
        encoding="utf-8",
    )
    assert pcc.lire_seuil(str(fichier)) == 75.5


@pytest.mark.parametrize(
    "contenu",
    ["[tool.coverage.report]\nprecision = 1\n", "[tool.autre]\nfail_under = 80\n", ""],
)
def test_lire_seuil_absent(pcc, tmp_path, contenu):
    fichier = tmp_path / "pyproject.toml"
    fichier.write_text(contenu, encoding="utf-8")
    assert pcc.lire_seuil(str(fichier)) is None


def test_lire_seuil_fichier_absent(pcc, tmp_path):
    assert pcc.lire_seuil(str(tmp_path / "absent.toml")) is None


def test_commentaire_au_dessus_du_seuil_indique_la_marge(pcc):
    commentaire = pcc._construire_commentaire(TOTAUX_REFERENCE, TOTAUX_REFERENCE, 70.0)
    assert "Seuil bloquant : 70.0 %" in commentaire
    assert "marge 6.7 pt" in commentaire
    assert "Sous le seuil" not in commentaire


def test_commentaire_sous_le_seuil_annonce_l_echec(pcc):
    commentaire = pcc._construire_commentaire(TOTAUX_REFERENCE, TOTAUX_REFERENCE, 80.0)
    assert "Sous le seuil bloquant" in commentaire
    assert "échouera" in commentaire


def test_commentaire_sans_seuil(pcc):
    assert "Aucun seuil bloquant configuré" in pcc._construire_commentaire(TOTAUX_REFERENCE, TOTAUX_REFERENCE)


def test_les_workflows_de_couverture_restent_coherents():
    """ci.yml doit appliquer le seuil (pas de --cov-fail-under qui le
    contredirait) ; pr-coverage.yml doit le neutraliser, sinon une PR sous le
    seuil ne recevrait jamais le commentaire qui l'explique."""
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    pr = (REPO_ROOT / ".github" / "workflows" / "pr-coverage.yml").read_text(encoding="utf-8")
    assert "uv run pytest --cov " in ci
    assert "--cov-fail-under" not in ci.split("run: uv run pytest --cov", 1)[1].splitlines()[0]
    lancements = [ligne for ligne in pr.splitlines() if "uv run pytest --cov" in ligne]
    assert len(lancements) == 3
    # Les lancements PR et base ont --cov-fail-under=0 ; le run AI extra
    # collecte juste la couverture sans seuil bloquant.


def _arguments_main(tmp_path):
    pr = _ecrire_rapport(tmp_path, TOTAUX_REFERENCE, "pr.json")
    base = _ecrire_rapport(tmp_path, TOTAUX_REFERENCE, "base.json")
    return ["--pr-json", str(pr), "--base-json", str(base), "--pr-number", "7"]


def _environnement(monkeypatch, tmp_path):
    resume = tmp_path / "resume.md"
    monkeypatch.setenv("GITHUB_TOKEN", "jeton")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(resume))
    return resume


def _http_error(pcc, code):
    return pcc.urllib.error.HTTPError("https://api.github.com/x", code, "refus", {}, None)


def test_main_pr_de_fork_403_avertit_sans_echouer(pcc, tmp_path, monkeypatch, capsys):
    """PR depuis un fork : GITHUB_TOKEN en lecture seule, l'API repond 403.
    Le job ne doit pas echouer ; le rapport reste dans le resume du job."""
    resume = _environnement(monkeypatch, tmp_path)

    def refuse(*_a, **_k):
        raise _http_error(pcc, 403)

    monkeypatch.setattr(pcc, "_publier", refuse)
    assert pcc.main(_arguments_main(tmp_path)) == 0
    sortie = capsys.readouterr()
    assert "HTTP 403" in sortie.err
    assert pcc.MARQUEUR in sortie.out
    assert pcc.MARQUEUR in resume.read_text(encoding="utf-8")


def test_main_autre_erreur_http_propagee(pcc, tmp_path, monkeypatch):
    _environnement(monkeypatch, tmp_path)

    def panne(*_a, **_k):
        raise _http_error(pcc, 500)

    monkeypatch.setattr(pcc, "_publier", panne)
    with pytest.raises(pcc.urllib.error.HTTPError):
        pcc.main(_arguments_main(tmp_path))


def test_main_publie_et_ecrit_le_resume(pcc, tmp_path, monkeypatch, capsys):
    resume = _environnement(monkeypatch, tmp_path)
    monkeypatch.setattr(pcc, "_publier", lambda *a: "commentaire cree (url)")
    assert pcc.main(_arguments_main(tmp_path)) == 0
    assert "commentaire cree" in capsys.readouterr().out
    assert pcc.MARQUEUR in resume.read_text(encoding="utf-8")


def test_main_sans_resume_de_job(pcc, tmp_path, monkeypatch, capsys):
    _environnement(monkeypatch, tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY")
    monkeypatch.setattr(pcc, "_publier", lambda *a: "ok")
    assert pcc.main(_arguments_main(tmp_path)) == 0
