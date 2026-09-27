"""
netcross_report.security_html -- rendu HTML du rapport de securite
(issue #218, troisieme sortie apres le texte et le JSON).

Trois partis pris, tous dictes par le contexte d'usage :

1. **Fichier unique, aucune ressource externe.** CSS et JavaScript sont
   inlines. Un rapport d'incident est lu sur un poste d'analyse parfois
   isole, archive dans un ticket, transmis par courriel : une dependance
   a un CDN en ferait une page cassee six mois plus tard, au moment
   precis ou on la ressort.

2. **Aucune donnee interpolee dans du JavaScript.** Tout passe par du
   HTML echappe. Un rapport de securite contient par construction des
   chaines hostiles -- banniere de service forgee, detail de tentative
   d'exploitation, nom d'hote controle par l'attaquant. Injecter cela
   dans un `<script>` transformerait le rapport lui-meme en vecteur.
   Le filtrage cote client ne lit que le DOM deja rendu.

3. **Les sections vides sont ecrites, pas omises.** « aucune tentative
   d'exploitation detectee » et « section absente » ne disent pas la meme
   chose au lecteur : la premiere est un resultat d'analyse, la seconde
   un doute sur l'outil. Meme regle que le rendu texte.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize
from netcross_report.security_report import (
    SEVERITIES,
    SecurityReport,
    asset_os_label,
    asset_ports_label,
    group_by_detector,
    is_expert_info,
    security_report_to_dict,
)

logger = get_logger(__name__)

# Teintes de severite. Choisies pour rester distinguables en niveaux de
# gris (un rapport finit imprime) et lisibles par un daltonien : la
# luminosite du fond varie en meme temps que la teinte, et le libelle
# textuel de la severite est toujours present a cote de la couleur.
_SEVERITY_COLORS = {
    "critique": ("#7f1d1d", "#fee2e2"),
    "elevee": ("#9a3412", "#ffedd5"),
    "moyenne": ("#854d0e", "#fef9c3"),
    "faible": ("#1e40af", "#dbeafe"),
}
_NEUTRAL = ("#374151", "#f3f4f6")

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.5rem 4rem;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #111827; background: #ffffff; max-width: 1200px; margin-inline: auto;
}
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2.5rem 0 .75rem; padding-bottom: .35rem; border-bottom: 2px solid #e5e7eb; }
.sous-titre { color: #6b7280; font-size: .875rem; margin: 0 0 2rem; }
.cartes { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .75rem; }
.carte { border: 1px solid #e5e7eb; border-radius: 8px; padding: .85rem 1rem; }
.carte .valeur { font-size: 1.75rem; font-weight: 650; line-height: 1.1; }
.carte .etiquette { color: #6b7280; font-size: .8rem; margin-top: .2rem; }
.jauge { height: 9px; border-radius: 99px; background: #e5e7eb; overflow: hidden; margin-top: .6rem; }
.jauge > span { display: block; height: 100%; background: currentColor; }
table { width: 100%; border-collapse: collapse; font-size: .875rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
th { background: #f9fafb; font-weight: 600; font-size: .78rem; text-transform: uppercase;
     letter-spacing: .03em; color: #4b5563; position: sticky; top: 0; }
tbody tr:hover { background: #fafafa; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8125rem; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 99px;
         font-size: .75rem; font-weight: 600; white-space: nowrap; }
.vide { color: #6b7280; font-style: italic; padding: .85rem 0; margin: 0; }
.filtre { margin: 0 0 .75rem; display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
.filtre input { padding: .4rem .6rem; border: 1px solid #d1d5db; border-radius: 6px;
                font: inherit; font-size: .875rem; min-width: 16rem; }
.filtre .compte { color: #6b7280; font-size: .8rem; }
.lisible { color: #4b5563; word-break: break-all; }
.pied { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e5e7eb;
        color: #6b7280; font-size: .8rem; }
@media print {
  body { padding: 0; max-width: none; }
  .filtre { display: none; }
  h2 { break-after: avoid; }
  tr { break-inside: avoid; }
}
@media (prefers-color-scheme: dark) {
  body { color: #e5e7eb; background: #0b0f19; }
  h2 { border-color: #1f2937; }
  .carte { border-color: #1f2937; }
  th { background: #111827; color: #9ca3af; }
  th, td { border-color: #1f2937; }
  tbody tr:hover { background: #111827; }
  .jauge { background: #1f2937; }
  .filtre input { background: #111827; border-color: #374151; color: inherit; }
}
"""

# Le filtrage ne lit que le texte deja rendu dans le DOM : aucune donnee
# du rapport ne transite par du JavaScript (voir l'entete du module).
_JS = """
document.querySelectorAll('[data-filtre-pour]').forEach(function (champ) {
  var table = document.getElementById(champ.dataset.filtrePour);
  if (!table) { return; }
  var compte = champ.parentElement.querySelector('.compte');
  var lignes = Array.prototype.slice.call(table.tBodies[0].rows);
  function appliquer() {
    var q = champ.value.toLowerCase().trim();
    var visibles = 0;
    lignes.forEach(function (tr) {
      var ok = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
      tr.hidden = !ok;
      if (ok) { visibles++; }
    });
    if (compte) {
      compte.textContent = visibles === lignes.length
        ? lignes.length + ' ligne(s)'
        : visibles + ' / ' + lignes.length + ' ligne(s)';
    }
  }
  champ.addEventListener('input', appliquer);
  appliquer();
});
"""


def _e(valeur) -> str:
    """Echappe pour insertion dans du CONTENU TEXTUEL HTML.

    `None` devient un tiret plutot qu'une cellule vide : une cellule vide
    laisse croire a un bug de rendu, un tiret dit « pas de valeur » (regle
    de tracabilite du projet).

    `quote=False` est volontaire. Toutes les valeurs du rapport sont
    inserees entre balises, jamais dans un attribut (les seuls attributs
    dynamiques du document sont des couleurs et des largeurs calculees en
    interne). Avec `quote=True`, chaque apostrophe francaise devenait
    `&#x27;` : une source illisible, et surtout une sortie qui ne
    correspondait plus au rendu texte -- « aucune tentative
    d&#x27;exploitation detectee » au lieu du message attendu, ce qui
    casse toute recherche naive dans le fichier. `<`, `>` et `&` restent
    echappes, ce qui suffit en contenu textuel.

    Si un jour une valeur doit aller dans un attribut, elle passera par un
    helper dedie -- pas par celui-ci.
    """
    if valeur is None or valeur == "":
        return "&ndash;"
    return html.escape(str(valeur), quote=False)


def _badge(severite: str | None) -> str:
    if not severite:
        return '<span class="badge" style="color:#374151;background:#f3f4f6">aucune CVE connue</span>'
    avant, fond = _SEVERITY_COLORS.get(severite, _NEUTRAL)
    return f'<span class="badge" style="color:{avant};background:{fond}">{_e(severite)}</span>'


def _cible(host, port) -> str:
    if not host:
        return "&ndash;"
    return _e(f"{host}:{port}") if port is not None else _e(host)


def _table(id_table: str, entetes: list[str], lignes: list[str], message_vide: str) -> str:
    """Un tableau filtrable, ou le message explicite qu'il n'y a rien --
    jamais un tableau vide sans explication."""
    if not lignes:
        return f'<p class="vide">{_e(message_vide)}</p>'
    champ_filtre = (
        f'<div class="filtre"><input type="search" data-filtre-pour="{id_table}" '
        f'placeholder="Filtrer&hellip;" aria-label="Filtrer le tableau">'
        f'<span class="compte"></span></div>'
        if len(lignes) > 5
        else ""
    )
    th = "".join(f"<th>{_e(h)}</th>" for h in entetes)
    return f"{champ_filtre}<table id={id_table!r}><thead><tr>{th}</tr></thead><tbody>{''.join(lignes)}</tbody></table>"


def _ligne_service(s: dict) -> str:
    empreinte = (
        f"<code>{_e(s['fingerprint'])}</code>" if s.get("fingerprint") else '<span class="lisible">&ndash;</span>'
    )
    lisible = (
        f'<div class="lisible mono">{_e(s["fingerprint_readable"])}</div>' if s.get("fingerprint_readable") else ""
    )
    cves = ", ".join(s.get("cve_ids") or []) or None
    return (
        "<tr>"
        f"<td>{_badge(s.get('severity'))}</td>"
        f"<td><strong>{_e(s['service'])}</strong> {_e(s.get('version'))}</td>"
        f'<td class="mono">{_cible(s.get("host"), s.get("port"))}</td>'
        f"<td>{empreinte}{lisible}</td>"
        f"<td>{_e(cves)}</td>"
        f"<td>{_e(', '.join(s.get('points') or []) or None)}</td>"
        "</tr>"
    )


def _ligne_constat(i: dict, avec_cve: bool, detecteur: str | None = None) -> str:
    colonnes_cve = (
        f'<td class="mono">{_e(i.get("cve_id"))}</td><td class="mono">{_e(i.get("cvss"))}</td>' if avec_cve else ""
    )
    service = i.get("service")
    if service and i.get("version"):
        service = f"{service} {i['version']}"
    plugin = f' <span class="mono">[plugin {_e(i["plugin"])}]</span>' if i.get("plugin") else ""
    return (
        "<tr>"
        f"<td>{_badge(i.get('severity'))}</td>"
        f"{colonnes_cve}"
        + (f"<td>{_e(detecteur)}</td>" if detecteur is not None else "")
        + f"<td>{_e(i.get('detail'))}{plugin}</td>"
        f"<td>{_e(service)}</td>"
        f'<td class="mono">{_cible(i.get("host"), i.get("port"))}</td>'
        f"<td>{_e(i.get('point'))}</td>"
        "</tr>"
    )


def _cartes(d: dict) -> str:
    logger.debug("_cartes: d={}", summarize(d, "d"))
    couleur = _SEVERITY_COLORS.get(d["level"] or "", _NEUTRAL)[0]
    niveau = d["level"] or "aucun constat"
    cartes = [
        f'<div class="carte" style="color:{couleur}">'
        f'<div class="valeur">{d["score"]}<span style="font-size:1rem;font-weight:400">/100</span></div>'
        f'<div class="etiquette" style="color:inherit">score de risque &mdash; {_e(niveau)}</div>'
        f'<div class="jauge"><span style="width:{d["score"]}%"></span></div>'
        "</div>",
        f'<div class="carte"><div class="valeur">{d["services_total"]}</div>'
        f'<div class="etiquette">services detectes, dont {d["services_vulnerable"]} vulnerable(s)</div></div>',
        f'<div class="carte"><div class="valeur">{d["exploits"]}</div>'
        '<div class="etiquette">tentatives d\'exploitation</div></div>',
        f'<div class="carte"><div class="valeur">{d["anomalies_netcross"]}</div>'
        '<div class="etiquette">constats des detecteurs Netcross</div></div>',
        f'<div class="carte"><div class="valeur">{d["anomalies_expert_info"]}</div>'
        '<div class="etiquette">alertes Expert Info correlees</div></div>',
        f'<div class="carte"><div class="valeur">{d["cves"]}</div><div class="etiquette">CVE confirmees</div></div>',
        f'<div class="carte"><div class="valeur">{d.get("assets_total", 0)}</div>'
        f'<div class="etiquette">hotes inventories, dont {d.get("assets_new", 0)} nouveau(x)</div></div>',
    ]
    repartition = " &middot; ".join(f"{_e(sev)} <strong>{d['by_severity'].get(sev, 0)}</strong>" for sev in SEVERITIES)
    cartes.append(
        f'<div class="carte"><div class="etiquette" style="margin:0 0 .35rem">'
        f"repartition par severite</div><div>{repartition}</div></div>"
    )
    return f'<div class="cartes">{"".join(cartes)}</div>'


def _ligne_actif(a: dict) -> str:
    avant, fond = _SEVERITY_COLORS.get("moyenne", _NEUTRAL)
    nouveau = f'<span class="badge" style="color:{avant};background:{fond}">nouveau</span>' if a.get("is_new") else ""
    return (
        "<tr>"
        f'<td class="mono">{_e(a.get("ip"))} {nouveau}</td>'
        f'<td class="mono">{_e(a.get("mac"))}</td>'
        f"<td>{_e(asset_os_label(a))}</td>"
        f'<td class="mono">{_e(asset_ports_label(a) or None)}</td>'
        f"<td>{_e(a.get('packet_count', 0))}</td>"
        f"<td>{_e(', '.join(a.get('points') or []) or None)}</td>"
        "</tr>"
    )


def render_security_html(
    sr: SecurityReport,
    title: str = "Rapport de securite Netcross",
    meta: dict | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Rend le rapport en un document HTML autonome (chaine complete).

    `meta` : metadonnees libres reportees telles quelles (ticket, auteur),
    meme convention que `generate_pdf()` / `generate_json_report()`.
    `generated_at` : horodatage injectable, pour que les tests puissent
    comparer deux rendus a l'octet pres.
    """
    logger.debug(
        "render_security_html: sr={} title={} meta={} generated_at={}",
        summarize(sr, "sr"),
        summarize(title, "title"),
        summarize(meta, "meta"),
        summarize(generated_at, "generated_at"),
    )
    data = security_report_to_dict(sr)
    horodatage = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")

    lignes_meta = "".join(
        f'<div class="carte"><div class="etiquette">{_e(cle)}</div><div><strong>{_e(val)}</strong></div></div>'
        for cle, val in (meta or {}).items()
    )
    bloc_meta = f'<h2>Metadonnees</h2><div class="cartes">{lignes_meta}</div>' if lignes_meta else ""

    corps = [
        f"<h1>{_e(title)}</h1>",
        f'<p class="sous-titre">Detection passive de vulnerabilites &mdash; genere le {_e(horodatage)}</p>',
        bloc_meta,
        "<h2>Tableau de bord</h2>",
        _cartes(data["dashboard"]),
        "<h2>Services detectes</h2>",
        _table(
            "t-services",
            ["Criticite", "Service", "Cible", "Empreinte JA4/HASSH", "CVE", "Points"],
            [_ligne_service(s) for s in data["services"]],
            "aucun service identifie dans cette capture",
        ),
        "<h2>Tentatives d'exploitation detectees</h2>",
        _table(
            "t-exploits",
            ["Severite", "Detail", "Service", "Cible", "Point"],
            [_ligne_constat(i, avec_cve=False) for i in data["exploits"]],
            "aucune tentative d'exploitation detectee",
        ),
        # Issue #348 : detecteurs Netcross et Expert Info separes ; #347 :
        # colonne Detecteur et tri par groupe (le HTML garde tout, filtrable).
        "<h2>Anomalies (detecteurs Netcross)</h2>",
        _table(
            "t-anomalies",
            ["Severite", "Detecteur", "Detail", "Service", "Cible", "Point"],
            [
                _ligne_constat(i, avec_cve=False, detecteur=g.label)
                for g in group_by_detector([i for i in data["anomalies"] if not is_expert_info(i)])
                for i in g.items
            ],
            "aucun constat des detecteurs Netcross",
        ),
        "<h2>Anomalies (alertes Expert Info correlees)</h2>",
        _table(
            "t-expert-info",
            ["Severite", "Detail", "Service", "Cible", "Point"],
            [_ligne_constat(i, avec_cve=False) for i in data["anomalies"] if is_expert_info(i)],
            "aucune alerte Expert Info correlee",
        ),
        "<h2>CVE confirmees</h2>",
        _table(
            "t-cves",
            ["Severite", "CVE", "CVSS", "Detail", "Service", "Cible", "Point"],
            [_ligne_constat(i, avec_cve=True) for i in data["cves"]],
            "aucune CVE confirmee",
        ),
        # Issue #350 : inventaire d'actifs passif, nouveaux hotes en tete.
        "<h2>Inventaire d'actifs (decouverte passive)</h2>",
        _table(
            "t-actifs",
            ["Hote", "MAC", "OS deduit", "Ports exposes", "Paquets", "Points"],
            [
                _ligne_actif(a)
                for a in sorted(data.get("assets") or [], key=lambda a: (not a.get("is_new"), a.get("ip", "")))
            ],
            "aucun hote observe dans cette capture",
        ),
        _notifications(data.get("notifications") or []),
        _plugins(data.get("plugins") or []),
        '<p class="pied">Netcross &mdash; analyse passive : aucun paquet n\'a ete emis vers les '
        "hotes listes. Une empreinte ou une banniere peut etre forgee&nbsp;; un service absent de "
        "ce rapport n'est pas un service absent du reseau, seulement un service qui n'a pas parle "
        "pendant la capture.</p>",
    ]

    return (
        "<!DOCTYPE html>\n"
        '<html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(title)}</title><style>{_CSS}</style></head><body>\n"
        + "\n".join(p for p in corps if p)
        + f"\n<script>{_JS}</script></body></html>\n"
    )


def _notifications(items: list[dict]) -> str:
    """Tracabilite des notifications sortantes (issue #280) ; rien si aucune
    notification n'a ete demandee."""
    logger.debug("_notifications: items={}", summarize(items, "items"))
    if not items:
        return ""
    lignes = "".join(f"<li>{_e(i.get('line', ''))}</li>" for i in items)
    return f'<h2>Notifications</h2><ul id="notifications">{lignes}</ul>'


def _plugins(items: list[dict]) -> str:
    """Tracabilite des plugins (issue #284) ; rien si aucun plugin demande."""
    logger.debug("_plugins: items={}", summarize(items, "items"))
    if not items:
        return ""
    lignes = "".join(f"<li>{_e(i.get('line', ''))}</li>" for i in items)
    return f'<h2>Plugins</h2><ul id="plugins">{lignes}</ul>'


def generate_security_html(
    sr: SecurityReport,
    output_path,
    title: str = "Rapport de securite Netcross",
    meta: dict | None = None,
) -> str:
    """Ecrit le rendu HTML dans `output_path` et renvoie ce chemin."""
    logger.debug(
        "generate_security_html: sr={} output_path={} title={} meta={}",
        summarize(sr, "sr"),
        summarize(output_path, "output_path"),
        summarize(title, "title"),
        summarize(meta, "meta"),
    )
    chemin = Path(output_path)
    chemin.write_text(render_security_html(sr, title=title, meta=meta), encoding="utf-8")
    return str(chemin)
