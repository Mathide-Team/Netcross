"""
netcross_report.security_report -- rapport de securite consolide et
tableau de bord (CVE-5, issue #139, parent #133).

Regroupe les constats produits par les modules de detection passive de
vulnerabilites (CVE-1 fingerprinting de versions, CVE-2 signatures
d'exploits, CVE-3 alertes Expert Info, CVE-4 correlation CVE) en un seul
rapport : services detectes classes par criticite, exploits, anomalies,
CVE confirmees, plus une synthese chiffree.

Ce module ne DETECTE rien : il lit `Report.service_fingerprints` et
`Report.security_findings` (voir `netcross_core.models.Report` pour le
format des dicts), les regroupe, les classe par severite et les met en
forme. Un `Report` sans constat amont donne donc un rapport vide -- la
garantie "aucun faux positif sur trafic normal" repose sur les
detecteurs amont, celle de ce module est de ne jamais en ajouter :

- un service n'est marque vulnerable que si un constat CVE le designe
  explicitement (meme service ET meme version, et meme hote/port quand le
  constat les precise) -- jamais par simple ressemblance de nom ;
- aucune severite n'est inventee : elle vient du constat, sinon du score
  CVSS quand il existe, sinon "faible" (valeur la plus basse, un constat
  mal renseigne reste visible sans peser dans le score).

Rendu texte uniquement pour l'instant (`format_security_report` /
`print_security_report`, meme separation que `netcross_report.
session_objects`) ; une sortie HTML/PDF consommera le meme
`SecurityReport`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

# Du plus grave au moins grave : l'indice sert de rang de tri.
SEVERITIES: tuple[str, ...] = ("critique", "elevee", "moyenne", "faible")

# Poids d'un constat dans le score de risque global (0-100, plafonne).
SEVERITY_WEIGHTS: dict[str, int] = {"critique": 40, "elevee": 20, "moyenne": 8, "faible": 2}

CATEGORY_EXPLOIT = "exploit"
CATEGORY_ANOMALY = "anomalie"
CATEGORY_CVE = "cve"

# Plafond d'affichage par section du rendu texte (meme esprit que les
# "... N supplementaires" de netcross_core.report_text).
MAX_ROWS_PER_SECTION = 50

# Issue #347 : un plafond GLOBAL par section masquait des detections graves
# (60 domaines DGA suffisaient a pousser exfiltration et beaconing hors des
# 50 lignes affichees). Les constats des detecteurs sont desormais regroupes
# par detecteur : chaque detecteur ayant produit un constat a sa ligne de
# synthese, suivie d'au plus MAX_ROWS_PER_DETECTOR exemples.
MAX_ROWS_PER_DETECTOR = 3

# Identifiant du detecteur (cle `detector` des constats, issue #348) ->
# libelle affiche. L'ordre sert de departage metier entre deux groupes de
# meme gravite : une fuite de donnees passe avant un certificat expire.
DETECTOR_EXPERT_INFO = "expert_info"
DETECTOR_LABELS: dict[str, str] = {
    "exfiltration": "Exfiltration de donnees",
    "beaconing": "Beaconing C2",
    "dns_tunnel": "Tunnel DNS",
    "lateral_movement": "Mouvement lateral",
    "fast_flux": "Fast flux",
    "protocol_mismatch": "Incoherence de protocole",
    "dga": "Domaines generes (DGA)",
    "tls_audit": "Audit des certificats TLS",
    "flow_stats": "Statistiques de flux",
    "asset_inventory": "Inventaire d'actifs (nouveaux hotes)",
    DETECTOR_EXPERT_INFO: "Alertes Expert Info correlees (Wireshark)",
}
_DETECTOR_PRIORITY = list(DETECTOR_LABELS)

_SEVERITY_ALIASES = {
    "critique": "critique",
    "critical": "critique",
    "elevee": "elevee",
    "elevée": "elevee",
    "élevee": "elevee",
    "élevée": "elevee",
    "haute": "elevee",
    "high": "elevee",
    "moyenne": "moyenne",
    "medium": "moyenne",
    "faible": "faible",
    "low": "faible",
}

_CATEGORY_ALIASES = {
    "exploit": CATEGORY_EXPLOIT,
    "exploits": CATEGORY_EXPLOIT,
    "anomalie": CATEGORY_ANOMALY,
    "anomalies": CATEGORY_ANOMALY,
    "anomaly": CATEGORY_ANOMALY,
    "cve": CATEGORY_CVE,
    "cves": CATEGORY_CVE,
}


@dataclass(slots=True)
class SecurityItem:
    """Un constat de securite normalise (exploit, anomalie ou CVE).

    `source` distingue, pour les anomalies, un detecteur Netcross natif
    ("netcross", valeur par defaut) d'une alerte Expert Info de Wireshark
    correlee ("expert_info", CVE-3, voir `security.findings.anomaly_findings`)
    -- issue #348 : ce ne sont pas les memes alertes et le rapport ne doit
    pas laisser croire le contraire."""

    category: str
    severity: str
    detail: str
    cve_id: str | None = None
    cvss: float | None = None
    service: str | None = None
    version: str | None = None
    host: str | None = None
    port: int | None = None
    point: str | None = None
    # Issue #343 : liste de tous les points ou ce constat a ete observe
    # (un meme evenement vu sur 3 points = 1 constat, 3 points). `point`
    # reste expose comme alias retro-compatible (premier point trie, ou None).
    points: list[str] = field(default_factory=list)
    # Issue #348 : distingue les anomalies d'un detecteur Netcross
    # ("netcross", defaut) d'une alerte Expert Info de Wireshark correlee
    # ("expert_info", CVE-3).
    source: str = "netcross"
    # nom du detecteur tiers qui a produit le constat (issue #284) ; None
    # pour un constat du coeur
    plugin: str | None = None
    # detecteur d'origine (issue #348) : cle de DETECTOR_LABELS,
    # "plugin:<nom>" pour un detecteur tiers, None si non renseigne
    detector: str | None = None


def detector_label(detector: str | None) -> str:
    """Libelle affiche d'un detecteur (issue #348)."""
    if detector is None:
        logger.debug("detector_label: si detector is None -> retour 'Autres constats'")
        return "Autres constats"
    if detector.startswith("plugin:"):
        logger.debug("detector_label: si detector.startswith('plugin:') -> retour chaîne formatée")
        return f"Plugin {detector[len('plugin:') :]}"
    logger.debug("detector_label: retour DETECTOR_LABELS.get(…)")
    return DETECTOR_LABELS.get(detector, detector)


def is_expert_info(item) -> bool:
    """Vrai pour une alerte Expert Info correlee (dict ou SecurityItem)."""
    # Issue #348 : `source` est la reference ; `detector` reste un repli pour
    # les constats plus anciens qui ne portent pas encore `source`.
    if isinstance(item, dict):
        source, det = item.get("source"), item.get("detector")
    else:
        source, det = getattr(item, "source", None), item.detector
    logger.debug("is_expert_info: retour source == 'expert_info' or det == DETECTOR_EXPERT…")
    return source == "expert_info" or det == DETECTOR_EXPERT_INFO


@dataclass(slots=True)
class DetectorGroup:
    """Constats d'un meme detecteur, pour les rendus condenses (#347)."""

    detector: str | None
    label: str
    severity: str
    items: list = field(default_factory=list)


def group_by_detector(items: list) -> list[DetectorGroup]:
    """Regroupe des constats (dicts ou SecurityItem) par detecteur, groupes
    tries par gravite du pire constat, puis par priorite metier du
    detecteur, puis par libelle. L'ordre interne (gravite, CVSS) est
    conserve."""
    logger.debug("group_by_detector: items={}", summarize(items, "items"))
    groups: dict[str | None, DetectorGroup] = {}
    for it in items:
        det = it.get("detector") if isinstance(it, dict) else it.detector
        sev = (it.get("severity") if isinstance(it, dict) else it.severity) or "faible"
        g = groups.get(det)
        if g is None:
            g = groups[det] = DetectorGroup(det, detector_label(det), sev)
        elif SEVERITIES.index(sev) < SEVERITIES.index(g.severity):
            g.severity = sev
        g.items.append(it)

    def rank(g: DetectorGroup):
        prio = _DETECTOR_PRIORITY.index(g.detector) if g.detector in _DETECTOR_PRIORITY else len(_DETECTOR_PRIORITY)
        logger.debug("group_by_detector.rank: retour tuple de 3")
        return (SEVERITIES.index(g.severity), prio, g.label)

    logger.debug("group_by_detector: retour sorted(…)")
    return sorted(groups.values(), key=rank)


@dataclass(slots=True)
class ServiceEntry:
    """Un service detecte, avec sa criticite (None si aucune CVE connue)."""

    service: str
    version: str | None = None
    host: str | None = None
    port: int | None = None
    points: list[str] = field(default_factory=list)
    severity: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    # Issue #259 : le hash JA4/HASSH et sa forme lisible etaient produits
    # par fingerprint.report.build_fingerprint_records puis silencieusement
    # jetes ici -- ServiceEntry n'avait aucun champ pour les porter, et
    # _build_services ne lisait que service/version/host/port/point. La
    # fonctionnalite entiere (issue #143) etait donc invisible de bout en
    # bout malgre 26 tests unitaires verts : ils testaient le calcul, jamais
    # le rendu.
    fingerprint: str | None = None
    fingerprint_readable: str | None = None

    @property
    def vulnerable(self) -> bool:
        logger.debug("ServiceEntry.vulnerable: retour self.severity is not None")
        return self.severity is not None


@dataclass(slots=True)
class SecurityDashboard:
    """Synthese chiffree du rapport.

    `score` : score de risque 0-100 (somme des poids `SEVERITY_WEIGHTS`
    de tous les constats, plafonnee a 100) ; 0 = rien de detecte.
    `level` : severite du pire constat, None s'il n'y en a aucun."""

    services_total: int = 0
    services_vulnerable: int = 0
    exploits: int = 0
    anomalies: int = 0
    # Issue #348 : part des anomalies venant des detecteurs Netcross et part
    # venant des alertes Expert Info de Wireshark (anomalies = la somme).
    anomalies_netcross: int = 0
    anomalies_expert_info: int = 0
    cves: int = 0
    # Issue #350 : inventaire d'actifs passif (hotes vus, dont nouveaux vs
    # la baseline --known-hosts ; baseline_size = 0 si aucune baseline).
    assets_total: int = 0
    assets_new: int = 0
    assets_baseline_size: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: dict.fromkeys(SEVERITIES, 0))
    score: int = 0
    level: str | None = None


@dataclass(slots=True)
class SecurityReport:
    services: list[ServiceEntry] = field(default_factory=list)
    exploits: list[SecurityItem] = field(default_factory=list)
    anomalies: list[SecurityItem] = field(default_factory=list)
    cves: list[SecurityItem] = field(default_factory=list)
    dashboard: SecurityDashboard = field(default_factory=SecurityDashboard)
    # tracabilite des notifications sortantes (issue #280) : une entree par
    # canal -- envoyee / echec + motif / non configuree. Vide = aucune
    # notification demandee (pas de --notify-on).
    notifications: list[dict] = field(default_factory=list)
    # tracabilite des plugins (issue #284) : une ligne par plugin demande
    # (« detecteur x : erreur, constats absents »). Vide = aucun plugin.
    plugins: list[dict] = field(default_factory=list)
    # Issue #350 : Report.asset_inventory tel quel (un dict par hote, voir
    # discovery.assets.AssetInventory.to_records), trie par IP.
    assets: list[dict] = field(default_factory=list)


# -- normalisation -------------------------------------------------------


def _opt_str(value) -> str | None:
    if value is None:
        logger.debug("_opt_str: si value is None -> retour None")
        return None
    text = str(value).strip()
    logger.debug("_opt_str: retour text or None")
    return text or None


def _opt_int(value) -> int | None:
    try:
        logger.debug("_opt_int: retour int(…)")
        return int(value)
    except (TypeError, ValueError):
        logger.exception("échec dans _opt_int")
        logger.debug("_opt_int: except (TypeError, ValueError) -> retour None")
        return None


def _opt_float(value) -> float | None:
    try:
        logger.debug("_opt_float: retour float(…)")
        return float(value)
    except (TypeError, ValueError):
        logger.exception("échec dans _opt_float")
        logger.debug("_opt_float: except (TypeError, ValueError) -> retour None")
        return None


def severity_from_cvss(cvss: float) -> str:
    """Tranches CVSS v3 de la NVD : >=9.0 critique, >=7.0 elevee, >=4.0
    moyenne, sinon faible (0.0 = 'none' inclus)."""
    if cvss >= 9.0:
        logger.debug("severity_from_cvss: si cvss >= 9.0 -> retour 'critique'")
        return "critique"
    if cvss >= 7.0:
        logger.debug("severity_from_cvss: si cvss >= 7.0 -> retour 'elevee'")
        return "elevee"
    if cvss >= 4.0:
        logger.debug("severity_from_cvss: si cvss >= 4.0 -> retour 'moyenne'")
        return "moyenne"
    logger.debug("severity_from_cvss: retour 'faible'")
    return "faible"


def _normalise_severity(raw, cvss: float | None) -> str:
    key = _opt_str(raw)
    if key is not None and key.lower() in _SEVERITY_ALIASES:
        logger.debug(
            "_normalise_severity: si key is not None and key.lower() in _SEVERITY_ALIASES -> retour _SEVERITY_ALIASES…"
        )
        return _SEVERITY_ALIASES[key.lower()]
    if cvss is not None:
        logger.debug("_normalise_severity: si cvss is not None -> retour severity_from_cvss(…)")
        return severity_from_cvss(cvss)
    logger.debug("_normalise_severity: retour 'faible'")
    return "faible"


def _to_item(raw) -> SecurityItem | None:
    """Dict amont -> SecurityItem ; None pour une entree inexploitable
    (pas un dict) plutot que de faire echouer tout le rapport."""
    if not isinstance(raw, dict):
        logger.trace("_to_item: entree de type {} ignoree (dict attendu)", type(raw).__name__)
        logger.debug("_to_item: si not isinstance(raw, dict) -> retour None")
        return None
    cvss = _opt_float(raw.get("cvss"))
    plugin = _opt_str(raw.get("plugin"))
    detector = _opt_str(raw.get("detector")) or (f"plugin:{plugin}" if plugin else None)
    category = _CATEGORY_ALIASES.get((_opt_str(raw.get("category")) or "").lower(), CATEGORY_ANOMALY)
    logger.debug("_to_item: retour SecurityItem(…)")
    return SecurityItem(
        category=category,
        severity=_normalise_severity(raw.get("severity"), cvss),
        detail=_opt_str(raw.get("detail")) or "",
        cve_id=_opt_str(raw.get("cve_id")),
        cvss=cvss,
        service=_opt_str(raw.get("service")),
        version=_opt_str(raw.get("version")),
        host=_opt_str(raw.get("host")),
        port=_opt_int(raw.get("port")),
        point=_opt_str(raw.get("point")),
        points=[str(p) for p in raw.get("points", []) if p] if isinstance(raw.get("points"), list) else [],
        source=_opt_str(raw.get("source")) or "netcross",
        plugin=plugin,
        detector=detector,
    )


def _item_sort_key(item: SecurityItem):
    logger.debug("_item_sort_key: retour tuple de 4")
    return (SEVERITIES.index(item.severity), -(item.cvss or 0.0), item.cve_id or "", item.detail)


def _cve_matches_service(cve: SecurityItem, entry: ServiceEntry) -> bool:
    """Une CVE designe un service detecte ssi meme nom (insensible a la
    casse) ET meme version ; hote/port ne comptent que si la CVE les
    precise. Un constat sans nom de service ou sans version identique ne
    rattache jamais rien (pas de correspondance approximative)."""
    if cve.service is None or cve.service.lower() != entry.service.lower():
        logger.debug(
            "_cve_matches_service: si cve.service is None or cve.service.lower() != entry.service… -> retour False"
        )
        return False
    if cve.version != entry.version:
        logger.debug("_cve_matches_service: si cve.version != entry.version -> retour False")
        return False
    if cve.host is not None and cve.host != entry.host:
        logger.debug("_cve_matches_service: si cve.host is not None and cve.host != entry.host -> retour False")
        return False
    logger.debug("_cve_matches_service: retour not (cve.port is not None and cve.port != entry.p…")
    return not (cve.port is not None and cve.port != entry.port)


def _build_services(fingerprints, cves: list[SecurityItem]) -> list[ServiceEntry]:
    logger.debug(
        "_build_services: fingerprints={} cves={}",
        summarize(fingerprints, "fingerprints"),
        summarize(cves, "cves"),
    )
    merged: dict[tuple, ServiceEntry] = {}
    for raw in fingerprints or []:
        if not isinstance(raw, dict):
            continue
        service = _opt_str(raw.get("service"))
        if service is None:
            continue
        version = _opt_str(raw.get("version"))
        host = _opt_str(raw.get("host"))
        port = _opt_int(raw.get("port"))
        fingerprint = _opt_str(raw.get("fingerprint"))
        readable = _opt_str(raw.get("banner"))
        # L'empreinte fait partie de l'identite de l'entree : deux JA4
        # differents vus sur le meme hote sont deux clients differents, les
        # fusionner effacerait l'information la plus utile de la section.
        key = (host, port, service.lower(), version, fingerprint)
        entry = merged.get(key)
        if entry is None:
            entry = merged[key] = ServiceEntry(
                service=service,
                version=version,
                host=host,
                port=port,
                fingerprint=fingerprint,
                fingerprint_readable=readable,
            )
        point = _opt_str(raw.get("point"))
        if point is not None and point not in entry.points:
            entry.points.append(point)

    for entry in merged.values():
        matching = [c for c in cves if _cve_matches_service(c, entry)]
        if matching:
            entry.severity = min((c.severity for c in matching), key=SEVERITIES.index)
            entry.cve_ids = sorted({c.cve_id for c in matching if c.cve_id})
        entry.points.sort()

    def _rank(e: ServiceEntry):
        sev = SEVERITIES.index(e.severity) if e.severity else len(SEVERITIES)
        logger.debug("_build_services._rank: retour tuple de 7")
        return (
            sev,
            -len(e.cve_ids),
            e.service.lower(),
            e.version or "",
            e.host or "",
            e.port or 0,
            e.fingerprint or "",
        )

    logger.debug("_build_services: retour sorted(…)")
    return sorted(merged.values(), key=_rank)


# -- construction --------------------------------------------------------


def build_security_report(report) -> SecurityReport:
    """Consolide `report.service_fingerprints` et `report.security_findings`
    en un `SecurityReport` (sections triees par severite decroissante, puis
    CVSS decroissant) et calcule le tableau de bord."""
    items = [i for i in (_to_item(raw) for raw in (report.security_findings or [])) if i is not None]
    exploits = sorted((i for i in items if i.category == CATEGORY_EXPLOIT), key=_item_sort_key)
    anomalies = sorted((i for i in items if i.category == CATEGORY_ANOMALY), key=_item_sort_key)
    cves = sorted((i for i in items if i.category == CATEGORY_CVE), key=_item_sort_key)
    services = _build_services(report.service_fingerprints, cves)

    dash = SecurityDashboard(
        services_total=len(services),
        services_vulnerable=sum(1 for s in services if s.vulnerable),
        exploits=len(exploits),
        anomalies=len(anomalies),
        anomalies_netcross=sum(1 for i in anomalies if not is_expert_info(i)),
        anomalies_expert_info=sum(1 for i in anomalies if is_expert_info(i)),
        cves=len(cves),
    )
    assets = [dict(a) for a in (getattr(report, "asset_inventory", None) or []) if isinstance(a, dict)]
    dash.assets_total = len(assets)
    dash.assets_new = sum(1 for a in assets if a.get("is_new"))
    dash.assets_baseline_size = int(getattr(report, "asset_baseline_size", 0) or 0)
    for item in items:
        dash.by_severity[item.severity] += 1
    dash.score = min(100, sum(SEVERITY_WEIGHTS[sev] * n for sev, n in dash.by_severity.items()))
    dash.level = next((sev for sev in SEVERITIES if dash.by_severity[sev]), None)
    logger.debug(
        "build_security_report: {}/{} constat(s) exploitables, {} exploit(s), {} anomalie(s), {} CVE, "
        "{} service(s) dont {} vulnerable(s), {} actif(s), score {} niveau {}",
        len(items),
        len(report.security_findings or []),
        len(exploits),
        len(anomalies),
        len(cves),
        dash.services_total,
        dash.services_vulnerable,
        dash.assets_total,
        dash.score,
        dash.level,
    )
    return SecurityReport(
        services=services,
        exploits=exploits,
        anomalies=anomalies,
        cves=cves,
        dashboard=dash,
        plugins=[dict(r) for r in (getattr(report, "plugin_runs", None) or [])],
        assets=assets,
    )


# -- rendu texte -----------------------------------------------------------


def _target(host: str | None, port: int | None) -> str:
    if host is None:
        logger.debug("_target: si host is None -> retour ''")
        return ""
    logger.debug("_target: retour f'(host):(port)' if port is not None else host")
    return f"{host}:{port}" if port is not None else host


def _service_label(service: str | None, version: str | None) -> str:
    if service is None:
        logger.debug("_service_label: si service is None -> retour ''")
        return ""
    logger.debug("_service_label: retour f'(service)/(version)' if version else service")
    return f"{service}/{version}" if version else service


def _format_item(item: SecurityItem) -> str:
    parts = [f"[{item.severity}]"]
    if item.cve_id:
        parts.append(item.cve_id + (f" (CVSS {item.cvss:.1f})" if item.cvss is not None else ""))
    label = _service_label(item.service, item.version)
    if label:
        parts.append(label)
    target = _target(item.host, item.port)
    if target:
        parts.append(f"@ {target}")
    line = " ".join(parts)
    if item.detail:
        line += f" -- {item.detail}"
    # Issue #343 : si plusieurs points, tous les lister ; sinon afficher le
    # point unique (compatibilite ascendante).
    shown_points = item.points if item.points else ([item.point] if item.point else [])
    if shown_points:
        if len(shown_points) == 1:
            line += f" (point {shown_points[0]})"
        else:
            line += f" (points {', '.join(shown_points)})"
    if item.plugin:
        line += f" [plugin {item.plugin}]"
    logger.debug("_format_item: retour ' ' + line")
    return "  " + line


# Prefixe d'affichage du hash, par type de service d'empreinte. L'issue
# #143 demandait explicitement la forme "JA4=xy123" / "HASSH=xy123" ; la
# deduire du champ `service` evite de trainer un champ de plus dans le
# dict produit par fingerprint.report.
_FINGERPRINT_PREFIXES = {"tls/ja4": "JA4", "ssh/hassh": "HASSH"}

# La forme lisible (liste complete des ciphers/extensions ou des
# algorithmes negocies) fait plusieurs centaines de caracteres. Elle est
# tronquee a l'affichage : le hash suffit a comparer deux empreintes, la
# chaine sert a comprendre CE QUI a ete propose, et un rapport texte reste
# lisible. La valeur complete demeure dans le champ du dataclass pour les
# consommateurs programmatiques (JSON, API).
MAX_READABLE_LEN = 120


def _format_fingerprint(entry: ServiceEntry) -> str:
    """Rend la partie empreinte d'une ligne de service, ou "" si l'entree
    n'en porte pas (cas des services detectes par banniere, CVE-1)."""
    if not entry.fingerprint:
        logger.debug("_format_fingerprint: si not entry.fingerprint -> retour ''")
        return ""
    prefixe = _FINGERPRINT_PREFIXES.get(entry.service.lower(), "empreinte")
    rendu = f" {prefixe}={entry.fingerprint}"
    lisible = entry.fingerprint_readable
    if lisible:
        if len(lisible) > MAX_READABLE_LEN:
            lisible = lisible[: MAX_READABLE_LEN - 3] + "..."
        rendu += f" [{lisible}]"
    logger.debug("_format_fingerprint: retour rendu={}", summarize(rendu, "rendu"))
    return rendu


def _format_service(entry: ServiceEntry) -> str:
    tag = f"[{entry.severity}]" if entry.severity else "[ok]"
    label = _service_label(entry.service, entry.version)
    target = _target(entry.host, entry.port)
    line = f"  {tag} {label}" + (f" @ {target}" if target else "")
    line += _format_fingerprint(entry)
    if entry.cve_ids:
        line += " -- " + ", ".join(entry.cve_ids)
    elif entry.vulnerable:
        line += " -- CVE non identifiee"
    else:
        line += " -- aucune vulnerabilite connue"
    if entry.points:
        line += f" (point(s) {', '.join(entry.points)})"
    logger.debug("_format_service: retour line={}", summarize(line, "line"))
    return line


def asset_os_label(asset: dict) -> str:
    """OS deduit d'un hote de l'inventaire (TTL, options TCP), ou
    « OS inconnu » -- toujours une hypothese, jamais un diagnostic."""
    os_guess = asset.get("os_guess") or {}
    if not os_guess:
        logger.debug("asset_os_label: si not os_guess -> retour 'OS inconnu'")
        return "OS inconnu"
    logger.debug("asset_os_label: retour chaîne formatée")
    return f"{os_guess.get('family', '?')} (confiance {os_guess.get('confidence', '?')})"


def asset_ports_label(asset: dict) -> str:
    """Ports exposes confirmes (SYN-ACK ou banniere), ex. « tcp/22 ssh »."""
    parts = []
    for p in asset.get("ports") or []:
        label = f"{p.get('transport')}/{p.get('port')}"
        service = " ".join(x for x in (p.get("service"), p.get("version")) if x)
        parts.append(f"{label} {service}" if service else label)
    logger.debug("asset_ports_label: retour ', '.join(…)")
    return ", ".join(parts)


def _format_asset(asset: dict) -> str:
    tag = " [NOUVEAU]" if asset.get("is_new") else ""
    line = f"  {asset.get('ip', '?')}{tag} -- {asset_os_label(asset)}"
    if asset.get("mac"):
        line += f", MAC {asset['mac']}"
    ports = asset_ports_label(asset)
    line += f", ports exposes : {ports}" if ports else ", aucun port expose observe"
    line += f", {asset.get('packet_count', 0)} paquets"
    if asset.get("points"):
        line += f" (point(s) {', '.join(asset['points'])})"
    logger.debug("_format_asset: retour line={}", summarize(line, "line"))
    return line


def _section(title: str, rows: list[str], empty_msg: str) -> list[str]:
    logger.debug(
        "_section: title={} rows={} empty_msg={}",
        summarize(title, "title"),
        summarize(rows, "rows"),
        summarize(empty_msg, "empty_msg"),
    )
    lines = ["", f"-- {title} --"]
    if not rows:
        lines.append(f"  {empty_msg}")
        logger.debug("_section: si not rows -> retour lines={}", summarize(lines, "lines"))
        return lines
    lines.extend(rows[:MAX_ROWS_PER_SECTION])
    if len(rows) > MAX_ROWS_PER_SECTION:
        lines.append(f"  ... {len(rows) - MAX_ROWS_PER_SECTION} ligne(s) supplementaire(s) non affichee(s)")
    logger.debug("_section: retour lines={}", summarize(lines, "lines"))
    return lines


def _detector_rows(items: list[SecurityItem]) -> list[str]:
    """Rendu condense par detecteur (#347) : une ligne de synthese par
    detecteur, puis ses premiers constats. Aucun detecteur n'est masque,
    quel que soit le volume des autres."""
    logger.debug("_detector_rows: items={}", summarize(items, "items"))
    rows: list[str] = []
    for g in group_by_detector(items):
        rows.append(f"  [{g.severity}] {g.label} : {len(g.items)} constat(s)")
        rows.extend("  " + _format_item(i) for i in g.items[:MAX_ROWS_PER_DETECTOR])
        rest = len(g.items) - MAX_ROWS_PER_DETECTOR
        if rest > 0:
            rows.append(f"      ... {rest} autre(s) constat(s) {g.label} (liste complete : --json-report ou HTML)")
    logger.debug("_detector_rows: retour rows={}", summarize(rows, "rows"))
    return rows


def _bar(score: int, width: int = 20) -> str:
    filled = round(width * score / 100)
    logger.debug("_bar: retour '#' * filled + '-' * (width - filled)")
    return "#" * filled + "-" * (width - filled)


def format_security_report(sr: SecurityReport) -> list[str]:
    """Rendu texte du rapport, une chaine par ligne (jamais de `print()`
    ici, meme separation que `netcross_report.session_objects`)."""
    logger.debug("format_security_report: sr={}", summarize(sr, "sr"))
    d = sr.dashboard
    lines = ["=" * 70, "RAPPORT DE SECURITE (detection passive de vulnerabilites)", "=" * 70]

    lines += ["", "-- Tableau de bord securite --"]
    level = d.level or "aucun constat"
    lines.append(f"  score de risque global : {d.score}/100 [{_bar(d.score)}] (niveau : {level})")
    lines.append(f"  services detectes : {d.services_total} (dont {d.services_vulnerable} vulnerable(s))")
    lines.append(f"  exploits detectes : {d.exploits}")
    lines.append(f"  constats des detecteurs Netcross : {d.anomalies_netcross}")
    lines.append(f"  alertes Expert Info correlees : {d.anomalies_expert_info}")
    lines.append(f"  CVE confirmees : {d.cves}")
    baseline = f"baseline de {d.assets_baseline_size} hote(s)" if d.assets_baseline_size else "sans baseline"
    lines.append(f"  hotes inventories : {d.assets_total} (dont {d.assets_new} nouveau(x), {baseline})")
    lines.append("  repartition par severite : " + ", ".join(f"{sev}={d.by_severity[sev]}" for sev in SEVERITIES))

    lines += _section(
        "Services detectes (classes par criticite)",
        [_format_service(s) for s in sr.services],
        "aucun service identifie",
    )
    lines += _section(
        "Tentatives d'exploitation detectees",
        [_format_item(i) for i in sr.exploits],
        "aucune tentative d'exploitation detectee",
    )
    # Issue #348 : deux origines distinctes, jamais melangees -- un
    # detecteur Netcross (DGA, fast flux, mouvements lateraux, tunneling
    # DNS, beaconing, audit TLS, incoherences de protocole) n'est PAS une
    # alerte Expert Info de Wireshark correlee (CVE-3). #347 : les constats
    # Netcross sont regroupes par detecteur, du plus grave au moins grave.
    netcross_anomalies = [i for i in sr.anomalies if i.source != "expert_info"]
    expert_info_anomalies = [i for i in sr.anomalies if i.source == "expert_info"]
    lines += _section(
        "Anomalies (detecteurs Netcross)",
        _detector_rows(netcross_anomalies),
        "aucune anomalie detectee",
    )
    lines += _section(
        "Anomalies (alertes Expert Info correlees)",
        [_format_item(i) for i in expert_info_anomalies],
        "aucune anomalie correlee",
    )
    lines += _section(
        "CVE confirmees (version + CVE-ID + score CVSS)",
        [_format_item(i) for i in sr.cves],
        "aucune CVE confirmee",
    )
    # Issue #350 : inventaire passif -- les nouveaux hotes d'abord.
    lines += _section(
        "Inventaire d'actifs (decouverte passive)",
        [_format_asset(a) for a in sorted(sr.assets, key=lambda a: (not a.get("is_new"), a.get("ip", "")))],
        "aucun hote observe",
    )
    if sr.notifications:
        lines += _section("Notifications", [f"  {n.get('line', '')}" for n in sr.notifications], "")
    if sr.plugins:
        lines += _section("Plugins", [f"  {p.get('line', '')}" for p in sr.plugins], "")
    logger.debug("format_security_report: retour lines={}", summarize(lines, "lines"))
    return lines


def print_security_report(sr: SecurityReport) -> None:
    """Ecrit `format_security_report()` sur stdout."""
    for line in format_security_report(sr):
        print(line)
    logger.debug("print_security_report: fin")


# -- serialisation (socle commun aux sorties JSON, HTML et PDF) -------------


def security_report_to_dict(sr: SecurityReport) -> dict:
    """Represente le rapport en structures Python serialisables.

    Socle unique des trois sorties non textuelles (JSON, HTML, PDF) : sans
    lui, chacune re-parcourrait les dataclasses a sa facon et divergerait
    au premier champ ajoute -- exactement ce qui a produit l'issue #259
    (un champ present dans les donnees, absent d'un rendu).

    Les champs valant None sont CONSERVES plutot que retires. Un
    consommateur doit pouvoir distinguer « non renseigne » de « cle que
    cette version de netcross ne produit pas » ; et la regle de tracabilite
    du projet veut qu'une information absente soit dite, pas passee sous
    silence.
    """
    logger.debug("security_report_to_dict: sr={}", summarize(sr, "sr"))
    return {
        "dashboard": {
            "score": sr.dashboard.score,
            "level": sr.dashboard.level,
            "services_total": sr.dashboard.services_total,
            "services_vulnerable": sr.dashboard.services_vulnerable,
            "exploits": sr.dashboard.exploits,
            "anomalies": sr.dashboard.anomalies,
            "anomalies_netcross": sr.dashboard.anomalies_netcross,
            "anomalies_expert_info": sr.dashboard.anomalies_expert_info,
            "cves": sr.dashboard.cves,
            "assets_total": sr.dashboard.assets_total,
            "assets_new": sr.dashboard.assets_new,
            "assets_baseline_size": sr.dashboard.assets_baseline_size,
            "by_severity": dict(sr.dashboard.by_severity),
        },
        "services": [
            {
                "service": s.service,
                "version": s.version,
                "host": s.host,
                "port": s.port,
                "points": list(s.points),
                "severity": s.severity,
                "vulnerable": s.vulnerable,
                "cve_ids": list(s.cve_ids),
                # Forme lisible NON tronquee, contrairement au rendu texte :
                # une sortie machine n'a pas de contrainte de largeur, et
                # tronquer ici priverait un consommateur de la liste
                # complete des ciphers (issue #259).
                "fingerprint": s.fingerprint,
                "fingerprint_readable": s.fingerprint_readable,
            }
            for s in sr.services
        ],
        **{
            cle: [
                {
                    "category": i.category,
                    "severity": i.severity,
                    "detail": i.detail,
                    "cve_id": i.cve_id,
                    "cvss": i.cvss,
                    "service": i.service,
                    "version": i.version,
                    "host": i.host,
                    "port": i.port,
                    "point": i.point,
                    "points": list(i.points),
                    "source": i.source,
                    "plugin": i.plugin,
                    "detector": i.detector,
                    "detector_label": detector_label(i.detector) if i.category == CATEGORY_ANOMALY else None,
                }
                for i in items
            ]
            for cle, items in (("exploits", sr.exploits), ("anomalies", sr.anomalies), ("cves", sr.cves))
        },
        "notifications": [dict(n) for n in sr.notifications],
        "plugins": [dict(p) for p in sr.plugins],
        "assets": [dict(a) for a in sr.assets],
    }
