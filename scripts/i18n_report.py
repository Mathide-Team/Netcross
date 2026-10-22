#!/usr/bin/env python3
"""scripts/i18n_report.py -- etat des traductions (issue #299).

Lit lang/LINGUAS, lang/messages.pot et lang/*.po sans dependance (ni gettext
ni polib) et affiche, par locale et au total : messages traduits, non
traduits, fuzzy, obsoletes, references vers des fichiers supprimes, et les
chaines nouvelles/supprimees du modele par rapport a une revision git
(``--since REV``). ``--compiled DIR`` compte les .mo presents.

    python3 scripts/i18n_report.py                   # texte
    python3 scripts/i18n_report.py --markdown        # pour $GITHUB_STEP_SUMMARY
    python3 scripts/i18n_report.py --json
    python3 scripts/i18n_report.py --strict          # code 1 si fuzzy/refs mortes

Le code de retour vaut 1 si une locale de LINGUAS n'a pas de .po, ou, avec
``--strict``, si un catalogue contient des references vers des fichiers
supprimes.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from loguru import logger
except ImportError:  # invoqué par la CI avec le python système, sans loguru
    class _logger:  # noqa: N801 -- repli muet, mêmes méthodes que loguru
        def _mute(self, *_args, **_kwargs):
            pass

        trace = debug = info = success = warning = error = exception = critical = log = _mute

    logger = _logger()

ROOT = Path(__file__).resolve().parent.parent
LANG_DIR = ROOT / "lang"
DOMAIN = "netcross"


@dataclass
class Entry:
    msgid: str = ""
    msgid_plural: str | None = None
    msgstr: list[str] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    references: list[str] = field(default_factory=list)
    obsolete: bool = False


def _unquote(text: str) -> str:
    return ast.literal_eval(text) if text else ""


def parse_po(text: str) -> list[Entry]:
    """Analyse minimale d'un catalogue PO (entrees, drapeaux, references,
    pluriels, entrees obsoletes ``#~``). L'en-tete (msgid vide) est inclus."""
    entries: list[Entry] = []
    cur = Entry()
    field_name: str | None = None
    started = False

    def flush() -> None:
        nonlocal cur, started, field_name
        if started:
            entries.append(cur)
        cur, started, field_name = Entry(), False, None

    for raw in text.splitlines():
        line = raw.strip()
        obsolete = line.startswith("#~")
        if obsolete:
            line = line[2:].strip()
            if line.startswith("|"):
                continue
        elif line.startswith("#,"):
            if started:
                flush()
            cur.flags.update(f.strip() for f in line[2:].split(","))
            continue
        elif line.startswith("#:"):
            if started:
                flush()
            cur.references += [ref.rsplit(":", 1)[0] if ref[-1:].isdigit() else ref for ref in line[2:].split()]
            continue
        elif line.startswith("#") or not line:
            if not line and started:
                flush()
            continue
        if line.startswith("msgid_plural "):
            cur.msgid_plural, field_name = _unquote(line[13:]), "msgid_plural"
        elif line.startswith("msgid "):
            if started and field_name and field_name.startswith("msgstr"):
                flush()
            cur.msgid, field_name, started = _unquote(line[6:]), "msgid", True
            cur.obsolete = obsolete
        elif line.startswith("msgstr["):
            idx = int(line[7 : line.index("]")])
            while len(cur.msgstr) <= idx:
                cur.msgstr.append("")
            cur.msgstr[idx] = _unquote(line[line.index("]") + 1 :].strip())
            field_name = f"msgstr[{idx}]"
        elif line.startswith("msgstr "):
            cur.msgstr = [_unquote(line[7:])]
            field_name = "msgstr[0]"
        elif line.startswith('"') and field_name:
            value = _unquote(line)
            if field_name == "msgid":
                cur.msgid += value
            elif field_name == "msgid_plural":
                cur.msgid_plural = (cur.msgid_plural or "") + value
            else:
                idx = int(field_name[7:-1])
                cur.msgstr[idx] += value
    flush()
    return entries


def read_linguas(lang_dir: Path = LANG_DIR) -> list[str]:
    """Locales declarees dans lang/LINGUAS (commentaires ignores)."""
    locales = []
    for line in (lang_dir / "LINGUAS").read_text(encoding="utf-8").splitlines():
        code = line.split("#", 1)[0].strip()
        if code:
            locales.append(code)
    return locales


@dataclass
class LocaleStats:
    locale: str
    total: int = 0
    translated: int = 0
    untranslated: int = 0
    fuzzy: int = 0
    obsolete: int = 0
    stale_references: list[str] = field(default_factory=list)
    compiled: bool = False
    missing: bool = False


def locale_stats(locale: str, po_text: str | None, root: Path = ROOT) -> LocaleStats:
    stats = LocaleStats(locale)
    if po_text is None:
        stats.missing = True
        return stats
    stale: set[str] = set()
    for e in parse_po(po_text):
        if e.msgid == "" and not e.obsolete:
            continue  # en-tete
        if e.obsolete:
            stats.obsolete += 1
            continue
        stats.total += 1
        stale.update(ref for ref in e.references if not (root / ref).exists())
        if "fuzzy" in e.flags:
            stats.fuzzy += 1
        elif e.msgstr and all(e.msgstr):
            stats.translated += 1
        else:
            stats.untranslated += 1
    stats.stale_references = sorted(stale)
    return stats


def template_ids(text: str) -> set[str]:
    return {e.msgid for e in parse_po(text) if e.msgid and not e.obsolete}


def template_changes(since: str, lang_dir: Path = LANG_DIR) -> tuple[list[str], list[str]]:
    """Chaines ajoutees/supprimees dans messages.pot depuis la revision git."""
    rel = (lang_dir / "messages.pot").relative_to(ROOT).as_posix()
    try:
        old = subprocess.run(
            ["git", "show", f"{since}:{rel}"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        logger.debug("ancien pot indisponible : {}", exc)
        old = ""
    new = (lang_dir / "messages.pot").read_text(encoding="utf-8")
    before, after = template_ids(old), template_ids(new)
    return sorted(after - before), sorted(before - after)


def collect(lang_dir: Path = LANG_DIR, compiled: Path | None = None, root: Path = ROOT) -> list[LocaleStats]:
    result = []
    for loc in read_linguas(lang_dir):
        po = lang_dir / f"{loc}.po"
        stats = locale_stats(loc, po.read_text(encoding="utf-8") if po.exists() else None, root)
        if compiled is not None:
            stats.compiled = (compiled / loc / "LC_MESSAGES" / f"{DOMAIN}.mo").exists()
        result.append(stats)
    return result


def summary(stats: list[LocaleStats]) -> dict[str, int]:
    present = [s for s in stats if not s.missing]
    messages = max((s.total for s in present), default=0)
    return {
        "languages": len(stats),
        "messages": messages,
        "translated": sum(s.translated for s in present),
        "untranslated": sum(s.untranslated for s in present),
        "fuzzy": sum(s.fuzzy for s in present),
        "locales_ok": sum(1 for s in present if not s.stale_references),
        "compiled": sum(1 for s in stats if s.compiled),
    }


def render_text(stats: list[LocaleStats], compiled: bool, added: list[str], removed: list[str]) -> str:
    tot = summary(stats)
    n = tot["languages"]
    lines = [
        "Internationalisation",
        "-" * 30,
        f"Langues :               {n}",
        f"Messages (modele) :     {tot['messages']}",
        f"Traduits :              {tot['translated']}",
        f"Non traduits :          {tot['untranslated']}",
        f"Fuzzy :                 {tot['fuzzy']}",
        "",
        f"Locales OK :            {tot['locales_ok']}/{n}",
    ]
    if compiled:
        lines.append(f"Catalogues compiles :   {tot['compiled']}/{n}")
    if added or removed:
        lines += ["", f"Nouvelles chaines :     {len(added)}", f"Chaines supprimees :    {len(removed)}"]
    lines += ["", f"{'locale':<8}{'traduits':>10}{'non trad.':>11}{'fuzzy':>7}{'obsol.':>8}  %"]
    for s in stats:
        if s.missing:
            lines.append(f"{s.locale:<8}  catalogue manquant")
            continue
        pct = 100 * s.translated // s.total if s.total else 100
        lines.append(f"{s.locale:<8}{s.translated:>10}{s.untranslated:>11}{s.fuzzy:>7}{s.obsolete:>8}  {pct}%")
        lines += [f"          reference morte : {ref}" for ref in s.stale_references]
    return "\n".join(lines)


def render_markdown(stats: list[LocaleStats], compiled: bool, added: list[str], removed: list[str]) -> str:
    tot = summary(stats)
    n = tot["languages"]
    out = [
        "## Internationalisation",
        "",
        "| Langues | Messages | Traduits | Non traduits | Fuzzy | Locales OK |" + (" Compiles |" if compiled else ""),
        "|---:|---:|---:|---:|---:|---:|" + ("---:|" if compiled else ""),
        f"| {n} | {tot['messages']} | {tot['translated']} | {tot['untranslated']} | {tot['fuzzy']} "
        f"| {tot['locales_ok']}/{n} |" + (f" {tot['compiled']}/{n} |" if compiled else ""),
        "",
    ]
    if added or removed:
        out += [f"Nouvelles chaines : **{len(added)}** · supprimees : **{len(removed)}**", ""]
        out += [f"- ajoutee : `{m}`" for m in added[:50]] + [f"- supprimee : `{m}`" for m in removed[:50]] + [""]
    out += ["<details><summary>Detail par locale</summary>", "", "| Locale | Traduits | Non traduits | Fuzzy | % |"]
    out.append("|---|---:|---:|---:|---:|")
    for s in stats:
        if s.missing:
            out.append(f"| {s.locale} | catalogue manquant | | | |")
            continue
        pct = 100 * s.translated // s.total if s.total else 100
        out.append(f"| {s.locale} | {s.translated} | {s.untranslated} | {s.fuzzy} | {pct} % |")
    out += ["", "</details>"]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--markdown", action="store_true")
    fmt.add_argument("--json", action="store_true")
    parser.add_argument("--compiled", type=Path, help="repertoire des .mo compiles a compter")
    parser.add_argument("--since", help="revision git de reference pour les chaines nouvelles/supprimees")
    parser.add_argument("--strict", action="store_true", help="echoue sur les references vers des fichiers supprimes")
    parser.add_argument("--lang-dir", type=Path, default=LANG_DIR)
    args = parser.parse_args(argv)

    stats = collect(args.lang_dir, args.compiled)
    added, removed = template_changes(args.since, args.lang_dir) if args.since else ([], [])
    if args.json:
        doc = {"summary": summary(stats), "locales": [asdict(s) for s in stats], "added": added, "removed": removed}
        print(json.dumps(doc, indent=2, ensure_ascii=False))
    elif args.markdown:
        print(render_markdown(stats, args.compiled is not None, added, removed))
    else:
        print(render_text(stats, args.compiled is not None, added, removed))

    if any(s.missing for s in stats):
        return 1
    if args.strict and any(s.stale_references for s in stats):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
