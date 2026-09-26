"""Issue #299 : internationalisation gettext.

Les verifications de catalogues (synchronisation .po/.pot, en-tetes,
placeholders) sont en Python pur et tournent partout ; celles qui appellent
xgettext/msgfmt sont sautees si gettext n'est pas installe (le workflow
i18n.yml l'installe et les execute)."""

from __future__ import annotations

import ast
import importlib.util
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from netcross_core import i18n

ROOT = Path(__file__).resolve().parent.parent
LANG = ROOT / "lang"

_spec = importlib.util.spec_from_file_location("i18n_report", ROOT / "scripts" / "i18n_report.py")
assert _spec and _spec.loader
report = importlib.util.module_from_spec(_spec)
sys.modules["i18n_report"] = report
_spec.loader.exec_module(report)

LINGUAS = report.read_linguas(LANG)
needs_gettext = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("xgettext", "msgmerge", "msgfmt", "msginit", "msgfilter")),
    reason="gettext non installe",
)

# Modules dont toutes les chaines destinees a l'utilisateur passent par
# gettext : toute nouvelle chaine non marquee y fait echouer le test. La liste
# s'allonge a chaque lot (app.py : voir docs/i18n.md).
GETTEXT_MODULES = ["src/netcross_gtk4/run_outcome.py", "src/netcross_gtk4/stats_view.py"]


def write_mo(path: Path, messages: dict[str, str | list[str]], plural: str = "nplurals=2; plural=(n != 1);") -> None:
    """Ecrit un .mo GNU minimal (format documente de gettext) sans msgfmt.
    Cle ``(singulier, pluriel)`` -> liste de formes."""
    header = f"Content-Type: text/plain; charset=UTF-8\nPlural-Forms: {plural}\nLanguage: xx\n"
    catalog: dict[bytes, bytes] = {b"": header.encode()}
    for key, value in messages.items():
        if isinstance(value, list):
            singular, plural_id = key.split("\x00")
            catalog[f"{singular}\x00{plural_id}".encode()] = "\x00".join(value).encode()
        else:
            catalog[key.encode()] = value.encode()
    keys = sorted(catalog)
    ids = strs = b""
    offsets = []
    for k in keys:
        offsets.append((len(ids), len(k), len(strs), len(catalog[k])))
        ids += k + b"\x00"
        strs += catalog[k] + b"\x00"
    n = len(keys)
    start = 7 * 4 + n * 16
    table_ids = b"".join(struct.pack("<II", ln, start + off) for off, ln, _, _ in offsets)
    table_strs = b"".join(struct.pack("<II", ln, start + len(ids) + off) for _, _, off, ln in offsets)
    head = struct.pack("<Iiiiiii", 0x950412DE, 0, n, 7 * 4, 7 * 4 + n * 8, 0, 0)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(head + table_ids + table_strs + ids + strs)


@pytest.fixture
def xx_locale(tmp_path, monkeypatch):
    write_mo(
        tmp_path / "xx" / "LC_MESSAGES" / "netcross.mo",
        {
            "Analyse terminee.": "Analysis done.",
            "Comparaison terminee -- {n} regression detectee.\x00Comparaison terminee -- {n} regressions detectees.": [
                "{n} regression!",
                "{n} regressions!",
            ],
        },
    )
    monkeypatch.setenv(i18n.ENV_LOCALEDIR, str(tmp_path))
    monkeypatch.delenv(i18n.ENV_LANG, raising=False)
    yield tmp_path
    monkeypatch.setenv(i18n.ENV_LANG, "C")
    i18n.setup()


# -- execution ----------------------------------------------------------------


def test_traduction_et_pluriel(xx_locale):
    i18n.setup("xx")
    assert i18n.active_language() == "xx"
    assert i18n._("Analyse terminee.") == "Analysis done."
    sing, plur = (
        "Comparaison terminee -- {n} regression detectee.",
        "Comparaison terminee -- {n} regressions detectees.",
    )
    assert i18n.ngettext(sing, plur, 1) == "{n} regression!"
    assert i18n.ngettext(sing, plur, 3) == "{n} regressions!"
    assert i18n._("Chaine inconnue") == "Chaine inconnue"
    assert i18n.N_("Analyse terminee.") == "Analyse terminee."
    assert i18n.available_languages(xx_locale) == ["xx"]


def test_langue_par_variable_et_repli(xx_locale, monkeypatch):
    monkeypatch.setenv(i18n.ENV_LANG, "yy:xx")
    i18n.setup()
    assert i18n._("Analyse terminee.") == "Analysis done."
    i18n.setup("zz")
    assert i18n.active_language() is None
    assert i18n._("Analyse terminee.") == "Analyse terminee."


def test_ordre_des_repertoires(tmp_path, monkeypatch):
    monkeypatch.setenv(i18n.ENV_LOCALEDIR, str(tmp_path))
    dirs = i18n.locale_dirs()
    assert dirs[0] == tmp_path and dirs[1] == i18n.PACKAGE_LOCALEDIR
    assert len(dirs) == len(set(dirs))
    assert i18n.requested_languages(" pt_BR : en ") == ["pt_BR", "en"]


def test_modules_gui_traduits(xx_locale):
    from netcross_gtk4.run_outcome import analysis_outcome, diff_status_text

    class _F:
        severity = "regression"

    i18n.setup("xx")
    assert diff_status_text([_F(), _F()]) == "2 regressions!"
    assert analysis_outcome("single", None, None, None, "t").status == "Analysis done."
    i18n.setup("C")
    assert diff_status_text([_F()]) == "Comparaison terminee -- 1 regression detectee."


# -- catalogues (Python pur) ----------------------------------------------------


def test_linguas_unique_et_valide():
    assert len(LINGUAS) == 29
    assert len(set(LINGUAS)) == len(LINGUAS)
    assert all(re.fullmatch(r"[a-z]{2,3}(_[A-Z]{2})?(@\w+)?", loc) for loc in LINGUAS)
    assert {p.stem for p in LANG.glob("*.po")} == set(LINGUAS)


def test_aucune_liste_de_langues_dans_le_code():
    """La liste vit dans lang/LINGUAS : une collection litterale faite
    surtout de codes de locale dans src/ serait une seconde source de verite
    (les bigrammes de dga.py, qui en contiennent par hasard, ne comptent pas)."""
    codes = set(LINGUAS)
    offenders = []
    for path in (ROOT / "src").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                values = {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                common = values & codes
                if len(common) >= 5 and len(common) >= 0.6 * len(values):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert offenders == []


def _entries(path: Path):
    return [e for e in report.parse_po(path.read_text(encoding="utf-8")) if not e.obsolete]


def test_po_synchronises_avec_le_modele():
    template = {(e.msgid, e.msgid_plural) for e in _entries(LANG / "messages.pot") if e.msgid}
    assert template, "lang/messages.pot vide"
    for loc in LINGUAS:
        entries = _entries(LANG / f"{loc}.po")
        assert {(e.msgid, e.msgid_plural) for e in entries if e.msgid} == template, loc
        header = next(e for e in entries if e.msgid == "").msgstr[0]
        assert f"Language: {loc}\n" in header, loc
        assert "charset=UTF-8" in header, loc
        forms = re.search(r"Plural-Forms: nplurals=(\d+); plural=[^;]+;", header)
        assert forms, f"{loc} : Plural-Forms absent ou incomplet"
        for e in entries:
            if e.msgid_plural and any(e.msgstr):
                assert len(e.msgstr) == int(forms.group(1)), f"{loc} : {e.msgid}"


def test_placeholders_conserves():
    """Une traduction qui perd ou renomme un ``{champ}`` ferait lever
    ``str.format`` a l'affichage."""
    fields = re.compile(r"\{([^{}]*)\}")
    for loc in LINGUAS:
        for e in _entries(LANG / f"{loc}.po"):
            if not e.msgid:
                continue
            expected = sorted(fields.findall(e.msgid))
            for msgstr in e.msgstr:
                if msgstr:
                    assert sorted(fields.findall(msgstr)) == expected, f"{loc} : {e.msgid!r} -> {msgstr!r}"


def test_references_vers_des_fichiers_existants():
    for loc in [*LINGUAS, "messages"]:
        path = LANG / (f"{loc}.po" if loc != "messages" else "messages.pot")
        refs = {r for e in _entries(path) for r in e.references}
        assert all((ROOT / r).exists() for r in refs), loc


def _user_strings(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                skip.add(id(first.value))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"_", "N_", "ngettext"}:
            skip.update(id(a) for a in node.args)
        # Messages loguru (logger.debug/info/warning/...) : destines au
        # developpeur, volontairement non traduits (issue #245).
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "logger"
        ):
            skip.update(id(n) for a in node.args for n in ast.walk(a))
        if isinstance(node, ast.Raise) or (isinstance(node, ast.Assign) and _is_all(node)):
            skip.update(id(n) for n in ast.walk(node))
    found = []
    for node in ast.walk(tree):
        is_text = isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip
        if is_text and _looks_like_prose(node.value):
            found.append(node.value)
    return found


def _looks_like_prose(value: str) -> bool:
    return bool(re.search(r"[A-Za-z]{3,}", value)) and (" " in value.strip() or value[:1].isupper())


def _is_all(node: ast.Assign) -> bool:
    return any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)


@pytest.mark.parametrize("module", GETTEXT_MODULES)
def test_chaines_utilisateur_marquees(module):
    assert _user_strings(ROOT / module) == []


# -- rapport --------------------------------------------------------------------

_SAMPLE = r"""
msgid ""
msgstr ""
"Language: xx\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\n"

#: src/netcross_core/i18n.py
msgid "Traduit"
msgstr "Done"

#: src/disparu.py
#, fuzzy, python-brace-format
#| msgid "Ancien"
msgid "Approche {n}"
msgstr "Close {n}"

msgid "Un"
msgid_plural "Plusieurs"
msgstr[0] "One"
msgstr[1] ""

msgid "Long "
"texte"
msgstr ""

#~ msgid "Retire"
#~ msgstr "Removed"
"""


def test_analyse_po():
    entries = report.parse_po(_SAMPLE)
    by_id = {e.msgid: e for e in entries}
    assert by_id["Long texte"].msgstr == [""]
    assert by_id["Un"].msgid_plural == "Plusieurs" and by_id["Un"].msgstr == ["One", ""]
    assert "fuzzy" in by_id["Approche {n}"].flags
    assert by_id["Retire"].obsolete
    stats = report.locale_stats("xx", _SAMPLE, ROOT)
    assert (stats.total, stats.translated, stats.untranslated, stats.fuzzy, stats.obsolete) == (4, 1, 2, 1, 1)
    assert stats.stale_references == ["src/disparu.py"]


def test_rapport_sur_le_depot(capsys):
    assert report.main(["--json", "--strict"]) == 0
    import json

    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["languages"] == len(LINGUAS)
    en = next(s for s in doc["locales"] if s["locale"] == "en")
    assert en["untranslated"] == 0 and en["fuzzy"] == 0
    assert report.main(["--markdown"]) == 0
    assert "| Langues |" in capsys.readouterr().out
    assert report.main([]) == 0
    assert "Locales OK :            29/29" in capsys.readouterr().out


def test_rapport_catalogue_manquant(tmp_path, capsys):
    (tmp_path / "LINGUAS").write_text("# commentaire\nxx\nyy\n")
    (tmp_path / "xx.po").write_text(_SAMPLE)
    assert report.main(["--lang-dir", str(tmp_path)]) == 1
    assert "catalogue manquant" in capsys.readouterr().out


# -- outils gettext -----------------------------------------------------------


@needs_gettext
def test_catalogues_a_jour_avec_les_sources():
    """Echoue si une chaine marquee a ete ajoutee/modifiee sans relancer
    scripts/i18n-update.sh."""
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts" / "i18n-update.sh"), "--check"], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stderr


@needs_gettext
def test_compilation_de_toutes_les_locales(tmp_path, monkeypatch):
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts" / "i18n-update.sh"), "--compile", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert i18n.available_languages(tmp_path) == sorted(LINGUAS)
    monkeypatch.setenv(i18n.ENV_LOCALEDIR, str(tmp_path))
    try:
        i18n.setup("en")
        from netcross_gtk4.stats_view import format_bytes

        assert format_bytes(2048) == "2.0 KB"
    finally:
        i18n.setup("C")
