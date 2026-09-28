"""
Systeme de plugins (issue #284).

Criteres d'acceptation :
- un plugin installe et non liste dans --plugins ne s'execute pas (ni meme
  n'est importe) ;
- un plugin qui leve laisse l'analyse aboutir, et le rapport dit lequel a
  echoue ;
- un plugin ne peut pas modifier les constats produits par le coeur.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
from netcross_core.models import Report
from netcross_core.plugins import (
    DetectorContext,
    InvalidFindingError,
    PluginAccessError,
    ReadOnlyView,
    discover_installed,
    forbidden_imports,
    list_plugins,
    load_error_runs,
    load_plugins,
    run_detectors,
    run_exporters,
    validate_finding,
)
from netcross_report.security_html import render_security_html
from netcross_report.security_report import (
    build_security_report,
    format_security_report,
    security_report_to_dict,
)

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "plugins" / "detecteur_telnet.py"
CORE_FINDING = {"severity": "critique", "category": "exploit", "detail": "Log4Shell", "point": "LAN"}


def _report():
    r = Report()
    r.security_findings = [dict(CORE_FINDING)]
    return r


class Det:
    def __init__(self, name, result=None, exc=None, hook=None):
        self.name, self.result, self.exc, self.hook = name, result or [], exc, hook

    def analyse(self, contexte):
        if self.hook:
            self.hook(contexte)
        if self.exc:
            raise self.exc
        return self.result


GOOD = {"category": "anomalie", "severity": "elevee", "detail": "protocole maison", "point": "LAN"}


# -- schema des constats -------------------------------------------------------------


def test_validation_du_schema():
    assert validate_finding({**GOOD, "severity": "ELEVEE"})["severity"] == "elevee"
    assert validate_finding({**GOOD, "cves": ("CVE-1",)})["cves"] == ["CVE-1"]
    for bad, motif in [
        ("pas un dict", "dict attendu"),
        ({**GOOD, "detail": ""}, "detail"),
        ({k: v for k, v in GOOD.items() if k != "category"}, "category"),
        ({**GOOD, "severity": "grave"}, "severite"),
        ({**GOOD, "extra": object()}, "non scalaire"),
        ({**GOOD, "cvss": float("inf")}, "non finie"),
        ({**GOOD, "cves": [1]}, "cves"),
    ]:
        with pytest.raises(InvalidFindingError, match=motif):
            validate_finding(bad)


# -- execution et isolation des erreurs -----------------------------------------------


def test_constats_du_plugin_ajoutes_et_marques():
    r = _report()
    runs = run_detectors([Det("maison", [GOOD])], [], r)
    assert runs[0]["status"] == "ok" and runs[0]["line"] == "detecteur maison : ok, 1 constat(s)"
    assert r.security_findings[-1] == {**GOOD, "plugin": "maison"}
    assert r.security_findings[0] == CORE_FINDING


def test_detecteur_muet_se_distingue_d_un_detecteur_plante():
    r = _report()
    runs = run_detectors([Det("muet"), Det("fragile", exc=ValueError("boom")), Det("apres", [GOOD])], [], r)
    assert [x["status"] for x in runs] == ["ok", "erreur", "ok"]
    assert runs[0]["line"] == "detecteur muet : ok, aucun constat"
    assert runs[1]["line"] == "detecteur fragile : erreur, constats absents -- ValueError: boom"
    # le plugin suivant s'est execute malgre l'echec du precedent
    assert r.security_findings[-1]["plugin"] == "apres"


def test_schema_invalide_ignore_et_signale():
    r = _report()
    runs = run_detectors([Det("bavard", [GOOD, {"severity": "grave"}, "texte"])], [], r)
    assert runs[0]["status"] == "partiel"
    assert runs[0]["findings"] == 1 and runs[0]["invalid"] == 2
    assert "2 invalide(s) ignore(s)" in runs[0]["line"]
    assert len(r.security_findings) == 2


def test_valeur_de_retour_non_liste():
    runs = run_detectors([Det("x", result="oups")], [], _report())
    assert runs[0]["status"] == "erreur" and "liste de constats attendue" in runs[0]["reason"]


def test_constats_du_coeur_absents_initialises_en_liste_vide():
    """Un rapport sans `security_findings` (None) reçoit une liste vide, puis les constats du plugin (#745)."""
    r = Report()
    r.security_findings = None
    runs = run_detectors([Det("maison", [GOOD])], [], r)
    assert runs[0]["status"] == "ok"
    assert r.security_findings == [{**GOOD, "plugin": "maison"}]


def test_detecteur_renvoyant_none_equivaut_a_aucun_constat():
    """`analyse` qui renvoie None (aucun return) est traité comme « aucun constat », pas comme une erreur (#745)."""

    class Muet:
        name = "silencieux"

        def analyse(self, contexte):
            return None

    r = _report()
    runs = run_detectors([Muet()], [], r)
    assert runs[0]["status"] == "ok" and runs[0]["findings"] == 0 and runs[0]["invalid"] == 0
    assert runs[0]["line"] == "detecteur silencieux : ok, aucun constat"
    assert r.security_findings == [CORE_FINDING]


# -- lecture seule --------------------------------------------------------------------


def test_contexte_ne_permet_pas_de_modifier_le_coeur():
    pkt = make_pkt(src="10.0.0.1")
    r = _report()
    errors = []

    def attempts(ctx):
        for attempt in (
            lambda: ctx.findings[0].__setitem__("severity", "faible"),
            lambda: ctx.report.security_findings.append({}),
            lambda: setattr(ctx.report, "security_findings", []),
            lambda: setattr(ctx.packets[0], "src", "1.2.3.4"),
            lambda: delattr(ctx.report, "points"),
        ):
            try:
                attempt()
            except (TypeError, AttributeError) as exc:  # noqa: PERF203
                errors.append(type(exc))
        ctx.report.security_findings[0]  # lecture autorisee
        assert ctx.packets[0].src == "10.0.0.1"
        assert len(ctx.packets) == 1 and [p.src for p in ctx.packets] == ["10.0.0.1"]

    runs = run_detectors([Det("curieux", hook=attempts)], [pkt], r)
    assert len(errors) == 5
    assert PluginAccessError in errors
    assert runs[0]["status"] == "ok"
    assert r.security_findings == [CORE_FINDING]
    assert pkt.src == "10.0.0.1"


def test_contournement_de_la_vue_annule():
    """Defense en profondeur : un plugin qui passe outre la vue (acces au
    slot interne) voit sa modification annulee apres execution."""
    r = _report()

    def sneaky(ctx):
        object.__getattribute__(ctx.report, "_target").security_findings.clear()

    run_detectors([Det("sournois", hook=sneaky, result=[GOOD])], [], r)
    assert r.security_findings[0] == CORE_FINDING
    assert r.security_findings[1]["plugin"] == "sournois"


def test_vue_et_contexte():
    r = _report()
    ctx = DetectorContext.build([], r)
    assert isinstance(ctx.report, ReadOnlyView)
    assert ctx.findings[0]["detail"] == "Log4Shell"
    with pytest.raises(AttributeError):
        ctx.findings = ()  # dataclass figee


# -- decouverte et chargement explicite -------------------------------------------------


def _install_fake_dist(tmp_path, monkeypatch, module_source, group="netcross.detectors", name="maison"):
    """Distribution installee factice : un module + un .dist-info avec
    entry_points.txt, sur sys.path."""
    site = tmp_path / "site"
    site.mkdir()
    (site / "plugin_maison.py").write_text(textwrap.dedent(module_source), encoding="utf-8")
    dist = site / "netcross_plugin_maison-1.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: netcross-plugin-maison\nVersion: 1.0\n")
    (dist / "entry_points.txt").write_text(f"[{group}]\n{name} = plugin_maison:Maison\n")
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, "plugin_maison", raising=False)
    return site


MARKER_MODULE = """
    import pathlib
    pathlib.Path(__file__).with_name("IMPORTE").write_text("oui")

    class Maison:
        name = "maison"

        def analyse(self, contexte):
            return [{"category": "anomalie", "severity": "moyenne", "detail": "vu par maison"}]
"""


def test_plugin_installe_non_autorise_jamais_importe(tmp_path, monkeypatch, capsys):
    site = _install_fake_dist(tmp_path, monkeypatch, MARKER_MODULE)
    assert any(i.name == "maison" and i.origin.startswith("entry_point:") for i in discover_installed())
    loaded = load_plugins([])
    assert loaded.detectors == []
    rows = list_plugins([])
    assert next(r for r in rows if r["name"] == "maison")["authorized"] is False
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--list-plugins"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    line = next(x for x in capsys.readouterr().out.splitlines() if x.startswith("maison"))
    assert "non" in line and "entry_point:netcross-plugin-maison" in line
    assert not (site / "IMPORTE").exists()


def test_plugin_installe_autorise_s_execute(tmp_path, monkeypatch):
    site = _install_fake_dist(tmp_path, monkeypatch, MARKER_MODULE)
    loaded = load_plugins(["maison"])
    assert [d.name for d in loaded.detectors] == ["maison"] and loaded.errors == []
    assert (site / "IMPORTE").exists()
    r = _report()
    run_detectors(loaded.detectors, [], r)
    assert r.security_findings[-1]["detail"] == "vu par maison"


def test_plugin_important_netcross_report_refuse_avant_execution(tmp_path, monkeypatch):
    site = _install_fake_dist(
        tmp_path, monkeypatch, "from netcross_report import pdf\n" + textwrap.dedent(MARKER_MODULE)
    )
    loaded = load_plugins(["maison"])
    assert loaded.detectors == []
    assert "netcross_report" in loaded.errors[0]["reason"]
    assert not (site / "IMPORTE").exists()
    line = load_error_runs(loaded.errors)[0]["line"]
    assert line.startswith("plugin maison : refuse -- ")


def test_import_interdit_detecte_par_ast():
    src = (
        "import os\nimport netcross_gtk4.app\nfrom netcross_report.pdf import x\n"
        "from . import y\nimport netcross_core\n"
    )
    assert forbidden_imports(src) == ["netcross_gtk4.app", "netcross_report.pdf"]


def test_plugin_demande_introuvable():
    loaded = load_plugins(["fantome"])
    assert loaded.errors == [{"plugin": "fantome", "reason": "introuvable (ni installe ni dans --plugin-path)"}]


def test_plugin_path_et_autorisation(tmp_path):
    local = tmp_path / "local.py"
    local.write_text(
        textwrap.dedent("""
        class A:
            name = "a"
            def analyse(self, contexte):
                return []

        class B:
            name = "b"
            def analyse(self, contexte):
                return []

        class Exp:
            name = "exp"
            def export(self, report, chemin):
                chemin.write_text(str(len(report.security_findings)))

        DETECTORS = [A, B()]
        EXPORTERS = [Exp]
        """),
        encoding="utf-8",
    )
    loaded = load_plugins(["b", "exp"], [str(local)])
    assert [d.name for d in loaded.detectors] == ["b"]
    assert list(loaded.exporters) == ["exp"]
    rows = {r["name"]: r["authorized"] for r in list_plugins(["b"], [str(local)]) if r["origin"].startswith("fichier:")}
    assert rows == {"a": False, "b": True, "exp": False}


@pytest.mark.parametrize(
    ("source", "motif"),
    [
        ("DETECTORS = []\n", "ni DETECTORS ni EXPORTERS"),
        ("raise RuntimeError('x')\n", "import en erreur"),
        ("def (:\n", "syntaxe"),
        ("class X:\n    name = 'x'\nDETECTORS = [X]\n", "protocole Detector"),
        ("import netcross_gtk4\n", "netcross_gtk4"),
    ],
)
def test_plugin_path_invalide(tmp_path, source, motif):
    bad = tmp_path / "bad.py"
    bad.write_text(source, encoding="utf-8")
    loaded = load_plugins(["x"], [str(bad)])
    assert motif in loaded.errors[0]["reason"]
    assert load_plugins(["x"], [str(tmp_path / "absent.py")]).errors[0]["reason"].endswith("fichier introuvable")


# -- exporteurs -----------------------------------------------------------------------------


class Exp:
    def __init__(self, name, fail=False):
        self.name, self.fail = name, fail

    def export(self, report, chemin):
        if self.fail:
            raise OSError("disque plein")
        report.security_findings.append({})  # tuple : leve


def test_exporteurs_lecture_seule_et_erreurs(tmp_path):
    class Writer:
        name = "json_maison"

        def export(self, report, chemin):
            chemin.write_text(json.dumps([dict(f) for f in report.security_findings]))

    r = _report()
    out = tmp_path / "out.json"
    runs = run_exporters(
        {"json_maison": Writer(), "casse": Exp("casse", fail=True), "mutant": Exp("mutant")},
        [("json_maison", str(out)), ("casse", "x"), ("mutant", "y"), ("absent", "z")],
        r,
    )
    assert [x["status"] for x in runs] == ["ok", "erreur", "erreur", "absent"]
    assert runs[0]["line"] == f"exporteur json_maison : ok, ecrit dans {out}"
    assert "OSError: disque plein" in runs[1]["line"]
    assert json.loads(out.read_text()) == [CORE_FINDING]
    assert r.security_findings == [CORE_FINDING]


# -- tracabilite dans le rapport ------------------------------------------------------------


def test_tracabilite_texte_json_html():
    r = _report()
    r.plugin_runs += run_detectors([Det("fragile", exc=ValueError("boom")), Det("maison", [GOOD])], [], r)
    sr = build_security_report(r)
    text = "\n".join(format_security_report(sr))
    assert "-- Plugins --" in text
    assert "detecteur fragile : erreur, constats absents -- ValueError: boom" in text
    assert "[plugin maison]" in text
    d = security_report_to_dict(sr)
    assert [p["status"] for p in d["plugins"]] == ["erreur", "ok"]
    assert any(a.get("plugin") == "maison" for a in d["anomalies"])
    html = render_security_html(sr)
    assert '<ul id="plugins">' in html and "[plugin maison]" in html
    assert "Plugins" not in "\n".join(format_security_report(build_security_report(_report())))


# -- plugin d'exemple -----------------------------------------------------------------------


def test_plugin_d_exemple_telnet():
    loaded = load_plugins(["telnet_clair"], [str(EXAMPLE)])
    packets = [
        make_pkt(point="LAN", src="10.0.0.9", dst="10.0.0.1", sport=40000, dport=23),
        make_pkt(point="LAN", src="10.0.0.1", dst="10.0.0.9", sport=23, dport=40000),
        make_pkt(point="LAN", dport=443),
    ]
    r = _report()
    runs = run_detectors(loaded.detectors, packets, r)
    assert runs[0]["line"] == "detecteur telnet_clair : ok, 1 constat(s)"
    finding = r.security_findings[-1]
    assert finding["detail"] == "session Telnet en clair 10.0.0.9 -> 10.0.0.1 (2 paquets)"
    assert forbidden_imports(EXAMPLE.read_text(encoding="utf-8")) == []


# -- CLI ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--plugin-path", str(EXAMPLE)], "--plugin-path sans --plugins"),
        (["--plugins", "x", "--plugin-export", "sans_egal"], "NOM=FICHIER"),
        (["--plugins", "x", "--plugin-export", "y=out.txt"], "absent de --plugins"),
        (["--plugins", "telnet_clair", "--plugin-path", str(EXAMPLE)], "--security-report requis"),
    ],
)
def test_cli_validations(monkeypatch, capsys, tmp_path, extra, message):
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"")
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--capture", f"LAN={pcap}", *extra])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert message in capsys.readouterr().err


def test_cli_list_plugins_avec_plugin_path(monkeypatch, capsys):
    argv = ["cross_capture_analyzer_cli.py", "--list-plugins", "--plugin-path", str(EXAMPLE)]
    monkeypatch.setattr(sys, "argv", [*argv, "--plugins", "telnet_clair,fantome"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    line = next(x for x in out.splitlines() if x.startswith("telnet_clair"))
    assert "detector" in line and "oui" in line
    assert "introuvable(s) : fantome" in out
