"""
netcross_report.synthesis -- transforme un Report en une liste de constats
(Finding) via des regles et seuils explicites. Chaque Finding est
traçable a un chiffre du Report : pas de texte genere librement.

Severites : "anomalie" (a traiter en priorite), "a_surveiller"
(suspect, a confirmer), "info" (contexte utile, pas un probleme en soi).

Score de confiance (sample_size) : un sous-ensemble des findings ci-dessous
porte un `sample_size` -- la taille de l'echantillon sur laquelle repose
une VALEUR ESTIMEE (taux de perte, moyenne, MOS). Volontairement pas
applique aux compteurs bruts d'evenements (1 RST localise, 1 DHCP NAK, 1
handshake avec MSS reduit...) : un evenement observe une seule fois est
une preuve directe et complete, pas une estimation fragile qui aurait pu
changer avec plus de donnees -- rien a "proteger" la de la credibilite
d'un chiffre qui n'estime rien. Seuls les taux/moyennes/MOS, qui PEUVENT
etre trompeurs sur un tout petit echantillon (5% de perte sur 2 paquets
vus n'a pas le meme poids que 5% sur 2000), sont annotes ici : pertes
(base = paquets vus), MOS RTP (base = paquets RTP utilises pour le calcul),
temps de traitement serveur moyen, duree moyenne de resolution DNS.
Premiere passe du sujet (voir FEATURES.md section 5.2/"Score de
confiance") : les autres categories restent sans annotation, a etendre
plus tard si le besoin se confirme -- voir triage.py pour l'usage qui en
est fait (ponderation amortie + marqueur "echantillon faible"). Duree
moyenne de reponse HTTP ajoutee a cette liste en Session 17, meme
raisonnement que la duree DNS (une moyenne sur peu de transactions est
moins fiable qu'une moyenne sur des centaines).

Preuves (evidence, Session 32) : un sous-ensemble des findings ci-dessous
porte desormais une liste `evidence` (EvidenceLink, netcross_core.
expert_model) -- des lignes brutes deja collectees ailleurs dans Report
(champs `*_examples`, ou listes `*_missing`/`*_timeout` elles-memes)
illustrant concretement le constat, jusqu'ici visibles uniquement dans le
detail texte par categorie (netcross_core.report_text) et absentes de
Finding/JSON/GUI. Cablee uniquement la ou une telle preuve existe deja SANS
ambiguite sur le constat qu'elle illustre -- pas de nouvelle collecte, et
pas de doublon quand le message du Finding EST deja la preuve (ex:
sip_failed_calls, un evenement = une ligne, meme raisonnement que
l'absence de sample_size sur un compteur brut ci-dessus). Voir
build_findings() pour le detail categorie par categorie.

Reference paquet (PacketEvidence, Session 35) : sur la categorie PMTUD
UNIQUEMENT (pilote), chaque EvidenceLink de ce fichier gagne desormais un
`packet` (PacketEvidence, netcross_core.expert_model) qui designe le
numero de trame tshark exact (`Pkt.frame_number`) du paquet representatif
-- voir `_evidence()` ci-dessous et `Report.pmtud_blackhole_frames`
(netcross_core.analysis._analyse_pmtud). Les autres categories gardent un
`packet` a `None` (comportement inchange), le cablage des sept autres
etant reporte a une session dediee (voir FEATURES.md/claude.md).

Finding enrichi (ExpertEvent, Session 36) : chaque Finding gagne un champ
`event` (ExpertEvent | None), peuple par `netcross_report.
build_expert_events()` -- PAS par `build_findings()` lui-meme (deux etapes
distinctes, l'appelant choisit s'il a besoin de la vue evenementielle).
Voir `netcross_core.expert_model` pour ce que porte reellement un
ExpertEvent a ce stade (cause/impact toujours None, moteur de causalite
non construit).

`rule_id` (Session 48) : premier cablage reel du catalogue DESCRIPTIF de
`netcross_core.expert_rules` (vingt-trois regles, Sessions 46-47) a un
consommateur -- chaque Finding ci-dessous qui correspond EXACTEMENT a une
regle du catalogue (meme detecteur source, meme signal) porte desormais
l'`id` de cette regle ; `None` sinon (valeur par defaut du champ), jamais
une correspondance approximative par seule `category` -- plusieurs
categories (notamment "TCP", huit regles) couvrent plusieurs signaux
distincts qui n'ont pas tous une regle. Verifie point par point contre
`expert_rules._RULE_CATALOG` avant redaction (meme discipline que la
tracabilite domaine/`Finding.category` de la Session 46) : `get_rule(id)`
existe toujours et `get_rule(id).domain == finding.category` pour tout
Finding qui porte un `rule_id` non None (voir test de tracabilite dans
test_synthesis.py).

`rule_id` (Session 49) : HUIT regles supplementaires (31 au total)
couvrant CINQ des paires signal-voisin-d'une-regle identifiees a la
Session 48 -- `hop_delta_outliers`, `pcp_change`,
`icmp_frag_needed`/`icmpv6_too_big` (fusionnes en une seule regle,
`icmp_fragmentation_needed`), `syn_reply_missing`, et les QUATRE
compteurs DNS bruts (`dns_nxdomain_count`, `dns_servfail_count`,
`dns_timeout`, `dns_missing`, gardes comme quatre regles distinctes vu
leurs severites differentes -- voir docstring de module
d'expert_rules.py pour le detail complet du raisonnement). Ces neuf
sites de construction de `Finding` portent desormais un `rule_id` non
None ; le code de `analysis.py`/`synthesis.py` n'est pas modifie dans sa
logique, seulement annote, meme discipline que la Session 48.

`rule_id` (Session 51) : `server_processing_dominant` -- le seul site de
construction de `Finding` de la categorie "Reseau/Serveur" (decomposition
applicatif/reseau, voir "-- decomposition reseau / serveur --" ci-dessous)
porte desormais un `rule_id` non None. Categorie retenue en priorite
parmi les trois laissees ouvertes par la Session 49 (un seul site, aucun
concept architectural non tranche -- voir docstring de module
d'expert_rules.py pour le detail complet du choix).

`rule_id` (Session 52) : les CINQ sites de construction de `Finding` de
la categorie "HTTP" (codes de statut, Session 17, bloc "-- HTTP --"
ci-dessous : 4xx, 5xx, timeout, message manquant, duree moyenne elevee)
portent desormais chacun un `rule_id` non None
(`http_client_error`/`http_server_error`/`http_timeout`/`http_missing`/
`http_slow_response`, 32 -> 37 regles au catalogue). Deuxieme des trois
categories laissees ouvertes par la Session 49, retenue avant "TLS" car
elle ne recoupe aucune decision architecturale en suspens (contrairement
a "TLS", voir docstring de module d'expert_rules.py) -- son seul cout
etait le NOMBRE de sites (cinq), pas une difficulte de fond, d'ou son
report en Session 51 au profit de "Reseau/Serveur" (un seul site).

`rule_id` (Session 53) : les DEUX sites de construction de `Finding` de
la categorie "TLS" (certificat hors validite/pas encore valide,
certificat substitue entre deux points -- Session 26, bloc "-- certificat
TLS --" ci-dessous) portent desormais chacun un `rule_id` non None
(`tls_cert_invalid_dates`/`tls_cert_mismatch`, 37 -> 39 regles au
catalogue). DERNIERE des trois categories laissees ouvertes par la
Session 49. Contrairement a ce qu'affirmaient CLAUDE.md et les
docstrings des Sessions 51/52, cataloguer ce signal ne "recoupe" PAS la
decision architecturale sur "negociations TLS incompletes" (verifie
dans le code avant redaction, voir docstring de module
d'expert_rules.py pour le detail complet de cette correction) : ce
second signal ne produit aucun `synthesis.Finding` -- il vit
exclusivement dans `TlsFinding` (`netcross_core.tls_diagnostics`, type
jamais relie a `Finding.category`) -- et n'a donc jamais ete un
candidat a une entree de ce catalogue. A l'issue de cette session, plus
aucune categorie de `Finding` n'est entierement sans regle.

`rule_id` (Session 54) : decision architecturale documentee depuis la
Session 49 desormais TRANCHEE -- option (a) retenue (voir docstring de
module d'expert_rules.py et `docs/sessions/session-54.md` pour le detail
complet du raisonnement et des deux options pesees). "negociations TLS
incompletes" (§6.2) rejoint ce pipeline via DEUX nouveaux sites de
construction de `Finding`, categorie "TLS", bloc "-- negociations TLS
incompletes --" ci-dessous : `tls_handshake_no_reply` (ClientHello vu,
aucun ServerHello jamais observe a ce point) et
`tls_handshake_incomplete` (ServerHello vu, aucune donnee applicative
jamais observee ensuite a ce point) -- PAR POINT tous les deux, aucune
correlation entre points necessaire (comme le certificat ci-dessus, pas
comme la comparaison de decalage d'horloge de `_analyse_handshake`).
Detecteur ENTIEREMENT nouveau (`netcross_core.analysis.
_analyse_tls_handshake`, `pcap_parser.protocols.extract_tls_handshake`)
-- PAS une reutilisation de `netcross_core.tls_diagnostics` (qui reste
totalement inchange et independant, voir sa docstring de module) : deux
techniques differentes pour un but voisin, jamais fusionnees de force.
Les deux nouveaux sites portent leur `rule_id` des la creation
(`tls_handshake_no_reply`/`tls_handshake_incomplete`, 39 -> 41 regles au
catalogue) plutot que d'attendre une session de rattrapage ulterieure
(a la difference du certificat, Session 26 -> 53) : cette session
connait deja le catalogue dans son integralite, rien ne justifiait de
rouvrir un ecart deja identifie et corrige. A l'issue de cette session,
TOUTES les categories de `Finding` ont une couverture complete du
catalogue -- et le signal "negociations TLS incompletes" nomme par
§6.2 n'est plus hors du systeme Finding/rule_id.

Consommateurs de `rule_id` a ce jour : uniquement
`netcross_report.json_report` (cle `"rule_id"`, absente plutot que `None`
sur un Finding orphelin -- voir sa docstring) via `ExpertEvent.rule_id`
(`netcross_core.expert_model`, recopie dans
`netcross_report.expert_events.build_expert_events()`). Volontairement
PAS le CLI `--triage` (`netcross_report.triage.print_triage`), ni le PDF
(`netcross_report.pdf`), ni la GTK4 (`netcross_gtk4.app`) : ces trois-la
affichent deja severity/category/segment/message en table lisible par un
humain, et `rule_id` est un identifiant technique destine a un
consommateur PROGRAMMATIQUE (dashboard, pipeline) -- meme raisonnement
que l'absence de sample_size/evidence dans le PDF aujourd'hui, pas un
oubli.
"""

from dataclasses import dataclass, field

from netcross_core.expert_model import EvidenceLink, ExpertEvent, PacketEvidence
from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)
SEVERITY_ORDER = {"anomalie": 0, "a_surveiller": 1, "info": 2}


@dataclass
class Finding:
    severity: str
    category: str
    segment: str
    message: str
    sample_size: int | None = None
    evidence: list[EvidenceLink] = field(default_factory=list)
    # ExpertEvent (Session 36) -- None tant que build_expert_events() n'a
    # pas ete appele sur la liste de Finding (voir docstring de module).
    event: ExpertEvent | None = None
    # Lien vers netcross_core.expert_rules (Session 48) -- id stable d'une
    # Rule du catalogue quand ce Finding lui correspond exactement, None
    # sinon (voir docstring de module pour la liste des Finding
    # volontairement sans correspondance).
    rule_id: str | None = None


def _pct(n, d):
    logger.debug("_pct: retour n / d * 100.0 if d else 0.0")
    return (n / d * 100.0) if d else 0.0


def _evidence(point: str, texts, frames: list[int | None] | None = None) -> list[EvidenceLink]:
    """Construit la liste d'EvidenceLink pour un point/segment donne a
    partir d'une liste de chaines deja collectee dans Report (ex:
    r.pmtud_blackhole_examples.get((a, b), []), ou directement la liste
    `missing`/`timeouts` deja liee dans la boucle appelante). `texts` peut
    etre vide (cle absente du dict, ou aucun exemple retenu) -- produit
    alors une liste vide, comportement identique a l'absence du kwarg
    `evidence` sur Finding.

    `frames` (Session 35, optionnel) : liste parallele de numeros de trame
    (`Report.pmtud_blackhole_frames.get((a, b), [])` par exemple), MEME
    index que `texts` -- chaque `EvidenceLink` gagne alors un `packet`
    (PacketEvidence) plutot que `None`. Absent ou plus court que `texts` :
    aucune erreur, les entrees manquantes restent sans `packet` (zip
    s'arrete au plus court -- voir la garde explicite ci-dessous plutot que
    de lever sur un desalignement, qui ne devrait de toute facon jamais se
    produire puisque les deux listes sont toujours appendees ensemble,
    meme index, cote analysis.py)."""
    if not frames:
        logger.debug("_evidence: si not frames -> retour liste")
        return [EvidenceLink(point, t) for t in texts]
    links = []
    for t, fn in zip(texts, frames):
        packet = PacketEvidence(point, fn) if fn is not None else None
        links.append(EvidenceLink(point, t, packet=packet))
    logger.debug("_evidence: retour links={}", summarize(links, "links"))
    return links


def _http_error_evidence(examples: list[str], status_class: int, frames: list[int | None] | None = None):
    """Filtre http_error_examples (netcross_core.analysis._analyse_http) par
    classe de statut (4 ou 5) : ce champ melange volontairement 4xx et 5xx
    au moment de la collecte (un seul point, voir la boucle dans
    analysis.py), la distinction ne peut donc se faire qu'ici, sur le
    suffixe "-> NNN" de chaque exemple -- plutot que de dupliquer la
    collecte cote analysis.py pour deux compteurs qui restent, eux,
    deja separes (http_client_error_count / http_server_error_count).

    `frames` (Session 37, optionnel) : liste parallele de numeros de
    trame (`Report.http_error_frames`, MEME index que `examples`) --
    filtree avec le meme critere que les textes, pour rester alignee.
    Renvoie (textes_filtres, frames_filtrees) -- frames_filtrees vide si
    `frames` n'est pas fourni."""
    texts = []
    filtered_frames = []
    for i, ex in enumerate(examples):
        try:
            code = int(ex.rsplit(" ", 1)[-1])
        except ValueError:
            logger.exception("échec dans _http_error_evidence")
            continue
        if code // 100 == status_class:
            texts.append(ex)
            if frames is not None and i < len(frames):
                filtered_frames.append(frames[i])
    logger.debug("_http_error_evidence: retour tuple de 2")
    return texts, filtered_frames


def build_findings(r) -> list[Finding]:
    findings: list[Finding] = []

    # -- pertes --
    for p in r.points:
        n = r.loss_count.get(p, 0)
        if n <= 0:
            continue
        raw_base = r.seen_count.get(p, 0)
        rate = _pct(n, raw_base or 1)
        sev = "anomalie" if rate >= 5 else "a_surveiller"
        findings.append(
            Finding(
                sev,
                "Pertes",
                p,
                f"{n} paquets manquants a ce point ({rate:.1f}% des flux vus)",
                sample_size=raw_base,
                rule_id="loss_per_segment",
            )
        )

    # -- saturation / policing / bufferbloat --
    for (a, b), verdict in r.saturation_verdict.items():
        if "NON correlees" in verdict:
            continue
        sev = (
            "anomalie"
            if ("saturation" in verdict or "policing" in verdict or "limitation" in verdict)
            else "a_surveiller"
        )
        findings.append(Finding(sev, "Saturation", f"{a} -> {b}", verdict, rule_id="saturation"))

    for (a, b), (low_lat, high_lat) in r.bufferbloat_hint.items():
        findings.append(
            Finding(
                "a_surveiller",
                "Bufferbloat",
                f"{a} -> {b}",
                f"latence {low_lat:.1f}ms a faible charge vs {high_lat:.1f}ms a forte charge",
                rule_id="bufferbloat",
            )
        )

    # -- TTL / topologie --
    for (a, b), n in r.hop_delta_outliers.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "Routage",
                    f"{a} -> {b}",
                    f"{n} flux avec un nombre de sauts different du chemin majoritaire (ECMP/re-routage)",
                    rule_id="hop_delta_outliers",
                )
            )
    for p, n in r.ttl_unstable.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "Routage",
                    p,
                    f"{n} flux avec TTL variable au meme point (routage asymetrique possible)",
                    rule_id="ttl_variation",
                )
            )

    # -- QoS --
    for (a, b), n in r.qos_change.items():
        if n <= 0:
            continue
        l2 = r.qos_l2_remark.get((a, b), 0)
        l3 = r.qos_l3_remark.get((a, b), 0)
        findings.append(
            Finding(
                "a_surveiller",
                "QoS",
                f"{a} -> {b}",
                f"{n} paquets avec DSCP modifie ({l2} sans saut de routeur -> equipement L2, "
                f"{l3} avec saut -> routeur)",
                rule_id="qos_dscp_remarking",
            )
        )
    for (a, b), n in r.pcp_change.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "QoS",
                    f"{a} -> {b}",
                    f"{n} flux avec priorite 802.1p (PCP) modifiee",
                    rule_id="pcp_change",
                )
            )

    # -- fragmentation / MTU --
    for (a, b), n in r.frag_new.items():
        if n <= 0:
            continue
        correlated = r.encap_frag_correlated.get((a, b), 0)
        if correlated:
            findings.append(
                Finding(
                    "anomalie",
                    "Fragmentation",
                    f"{a} -> {b}",
                    f"{n} datagrammes fragmentes, {correlated} coincident avec l'apparition "
                    f"d'un tunnel -> le tunnel reduit le MTU disponible",
                    rule_id="fragmentation_new",
                )
            )
        else:
            findings.append(
                Finding(
                    "a_surveiller",
                    "Fragmentation",
                    f"{a} -> {b}",
                    f"{n} datagrammes non fragmentes en amont deviennent fragmentes ici",
                    rule_id="fragmentation_new",
                )
            )
    for p, n in r.icmp_frag_needed.items():
        if n > 0:
            findings.append(
                Finding(
                    "info",
                    "Fragmentation",
                    p,
                    f"{n} messages ICMP Fragmentation Needed observes",
                    rule_id="icmp_fragmentation_needed",
                )
            )
    # Equivalent IPv6 (Session 22) -- voir r.icmpv6_too_big dans
    # netcross_core.models pour le detail du rapprochement avec ce compteur.
    # Meme regle du catalogue que ci-dessus (Session 49, icmp_fragmentation_needed) :
    # meme signal fonctionnel, meme severite, seule la famille d'adresse change.
    for p, n in r.icmpv6_too_big.items():
        if n > 0:
            findings.append(
                Finding(
                    "info",
                    "Fragmentation",
                    p,
                    f"{n} messages ICMPv6 Packet Too Big observes",
                    rule_id="icmp_fragmentation_needed",
                )
            )

    # -- PMTUD (noir) --
    # Message volontairement neutre sur la famille d'adresse (IPv4/IPv6) :
    # un meme point-pair (a, b) peut porter des flux des deux familles,
    # et Finding n'a pas de champ dedie pour le distinguer -- voir
    # r.pmtud_blackhole_examples (netcross_core.report_text) pour le
    # detail par tentative, qui precise DF actif (IPv4) vs IPv6 (voir
    # analysis._analyse_pmtud).
    for (a, b), n in r.pmtud_blackhole.items():
        if n <= 0:
            continue
        seg = f"{a} -> {b}"
        findings.append(
            Finding(
                "anomalie",
                "PMTUD",
                seg,
                f"{n} segment(s) TCP retransmis plusieurs fois en {a} sans jamais atteindre "
                f"{b}, aucun signal ICMP(v6) de MTU insuffisant observe en {a} -> noir PMTUD "
                f"probable (RFC 1191 IPv4 / RFC 8201 IPv6), la connexion stagne sans jamais "
                f"reduire la taille de ses segments",
                evidence=_evidence(
                    seg,
                    r.pmtud_blackhole_examples.get((a, b), []),
                    r.pmtud_blackhole_frames.get((a, b), []),
                ),
                rule_id="pmtud_blackhole",
            )
        )

    # -- timeout d'inactivite / coupure NAT-FW silencieuse --
    # Voir r.idle_timeout_examples (netcross_core.report_text) pour le
    # detail par flux (duree du silence observe en amont).
    for (a, b), n in r.idle_timeout_dropped.items():
        if n <= 0:
            continue
        seg = f"{a} -> {b}"
        findings.append(
            Finding(
                "anomalie",
                "NAT/Pare-feu",
                seg,
                f"{n} flux TCP deja etabli(s) entre {a} et {b} ne reprennent jamais en {b} "
                f"apres un long silence en {a} -> coupure NAT/pare-feu silencieuse probable "
                f"(table d'etat expiree pendant l'inactivite, aucun RST observe)",
                evidence=_evidence(
                    seg,
                    r.idle_timeout_examples.get((a, b), []),
                    r.idle_timeout_frames.get((a, b), []),
                ),
                rule_id="nat_fw_silent_drop",
            )
        )

    # -- conflit d'adresse IP (ARP) --
    # Par point (pas par paire), voir Report.arp_ip_conflict.
    for p, n in r.arp_ip_conflict.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                "anomalie",
                "ARP",
                p,
                f"{n} adresse(s) IP revendiquee(s) par plusieurs adresses MAC differentes sur "
                f"ce point -> conflit d'adresse IP probable (deux hotes mal configures, ou "
                f"basculement d'IP flottante VRRP/HA)",
                evidence=_evidence(p, r.arp_ip_conflict_examples.get(p, []), r.arp_ip_conflict_frames.get(p, [])),
                rule_id="arp_ip_conflict",
            )
        )

    # -- instabilite STP (Session 25) --
    # Par point, voir Report.stp_topology_change/stp_root_change.
    for p, n in r.stp_topology_change.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                "anomalie",
                "STP",
                p,
                f"{n} evenement(s) de changement de topologie STP observe(s) sur ce point "
                f"(BPDU TCN ou bit TC actif) -> reseau instable possible (boucle de commutation, "
                f"lien ou port qui flappe)",
                rule_id="stp_instability",
            )
        )
    for p, n in r.stp_root_change.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                "anomalie",
                "STP",
                p,
                f"{n} reelection(s) du pont racine STP observee(s) sur ce point -> reseau instable "
                f"possible (boucle de commutation, lien ou port qui flappe)",
                evidence=_evidence(p, r.stp_root_change_examples.get(p, []), r.stp_root_change_frames.get(p, [])),
                rule_id="stp_instability",
            )
        )

    # -- certificat TLS (Session 26) --
    # Par point pour les dates de validite, par paire pour la
    # substitution -- voir Report.tls_cert_invalid_dates/tls_cert_mismatch.
    for p, n in r.tls_cert_invalid_dates.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                "anomalie",
                "TLS",
                p,
                f"{n} certificat(s) presente(s) hors de leur fenetre de validite sur ce point "
                f"(deja expire, ou pas encore valide)",
                evidence=_evidence(
                    p,
                    r.tls_cert_invalid_dates_examples.get(p, []),
                    r.tls_cert_invalid_dates_frames.get(p, []),
                ),
                rule_id="tls_cert_invalid_dates",
            )
        )
    for (a, b), n in r.tls_cert_mismatch.items():
        if n <= 0:
            continue
        seg = f"{a} -> {b}"
        findings.append(
            Finding(
                "anomalie",
                "TLS",
                seg,
                f"{n} connexion(s) TLS presentent un certificat different entre {a} et {b} "
                f"-> interception/substitution TLS possible en cours de chemin",
                evidence=_evidence(
                    seg,
                    r.tls_cert_mismatch_examples.get((a, b), []),
                    r.tls_cert_mismatch_frames.get((a, b), []),
                ),
                rule_id="tls_cert_mismatch",
            )
        )

    # -- negociations TLS incompletes (Session 54) --
    # PAR POINT pour les deux signaux -- voir Report.tls_handshake_
    # no_reply/tls_handshake_incomplete et _analyse_tls_handshake pour
    # le detail complet, notamment la distinction avec le certificat
    # ci-dessus et avec netcross_core.tls_diagnostics (jamais integre a
    # ce pipeline Finding, voir sa docstring de module).
    for p, n in r.tls_handshake_no_reply.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                "anomalie",
                "TLS",
                p,
                f"{n} negociation(s) TLS sans reponse sur ce point (ClientHello envoye, "
                f"aucun ServerHello jamais observe)",
                evidence=_evidence(
                    p,
                    r.tls_handshake_no_reply_examples.get(p, []),
                    r.tls_handshake_no_reply_frames.get(p, []),
                ),
                rule_id="tls_handshake_no_reply",
            )
        )
    for p, n in r.tls_handshake_incomplete.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                "anomalie",
                "TLS",
                p,
                f"{n} negociation(s) TLS interrompue(s) sur ce point (ServerHello recu, jamais "
                f"suivi de donnees applicatives)",
                evidence=_evidence(
                    p,
                    r.tls_handshake_incomplete_examples.get(p, []),
                    r.tls_handshake_incomplete_frames.get(p, []),
                ),
                rule_id="tls_handshake_incomplete",
            )
        )

    # -- VLAN --
    for (a, b), n in r.vlan_change.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "VLAN",
                    f"{a} -> {b}",
                    f"{n} flux changent d'ID VLAN entre ces deux points",
                    rule_id="vlan_change",
                )
            )

    # -- TCP avance --
    for p, n in r.zero_window.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "TCP",
                    p,
                    f"{n} paquets avec fenetre TCP=0 (recepteur/equipement sature)",
                    rule_id="tcp_zero_window",
                )
            )
    for p, n in r.retrans_rto.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "TCP",
                    p,
                    f"{n} retransmission(s) par expiration de minuteur (RTO) -- recuperation "
                    f"lente, aucun ACK duplique recent n'a declenche de renvoi rapide",
                    rule_id="tcp_retransmission_rto",
                )
            )
    for p, n in r.retrans_spurious.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "TCP",
                    p,
                    f"{n} retransmission(s) inutile(s) (donnee deja acquittee) -- minuteur de "
                    f"retransmission probablement mal calibre par rapport au RTT reel, ou "
                    f"chemin de retour ACK asymetrique",
                    rule_id="tcp_retransmission_spurious",
                )
            )
    for p, n in r.retrans_fast.items():
        if n > 0:
            findings.append(
                Finding(
                    "info",
                    "TCP",
                    p,
                    f"{n} retransmission(s) rapide(s) (reaction a 3 ACK dupliques) -- "
                    f"recuperation normale d'une perte isolee",
                    rule_id="tcp_retransmission_fast",
                )
            )
    for (a, b), n in r.mss_clamped.items():
        if n > 0:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    "info",
                    "TCP",
                    seg,
                    f"MSS reduit pour {n} handshake(s) entre ces deux points -- un "
                    f"equipement intermediaire adapte la taille de segment (souvent pour "
                    f"compenser un tunnel/VPN, protege generalement contre un noir PMTUD)",
                    evidence=_evidence(
                        seg, r.mss_clamped_examples.get((a, b), []), r.mss_clamped_frames.get((a, b), [])
                    ),
                    rule_id="tcp_mss_clamped",
                )
            )
    for (a, b), n in r.wscale_stripped.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "TCP",
                    f"{a} -> {b}",
                    f"option Window Scale retiree pour {n} handshake(s) entre ces deux "
                    f"points -- desactive le window scaling pour la connexion entiere, "
                    f"plafonne la fenetre TCP effective a 65535 octets (limite de debit "
                    f"classique sur un lien a fort produit debit x latence)",
                    rule_id="tcp_options_stripped",
                )
            )
    for (a, b), n in r.sack_stripped.items():
        if n > 0:
            findings.append(
                Finding(
                    "a_surveiller",
                    "TCP",
                    f"{a} -> {b}",
                    f"option SACK Permitted retiree pour {n} handshake(s) entre ces deux "
                    f"points -- recuperation de perte moins efficace en cas de "
                    f"retransmission (renvoi de fenetre entiere plutot que des seuls "
                    f"segments manquants)",
                    rule_id="tcp_options_stripped",
                )
            )
    for p, n in r.rst_localized.items():
        if n > 0:
            findings.append(
                Finding(
                    "anomalie",
                    "TCP",
                    p,
                    f"{n} RST vus a ce seul point -> injection locale probable (firewall/IPS)",
                    rule_id="tcp_rst_localized",
                )
            )
    for p, n in r.syn_no_synack.items():
        if n > 0:
            findings.append(
                Finding(
                    "anomalie",
                    "TCP",
                    p,
                    f"{n} connexions SYN sans aucune reponse SYN-ACK -> bloquees (ACL/service down)",
                    rule_id="tcp_syn_no_synack",
                )
            )
    for p, n in r.syn_reply_missing.items():
        if n > 0:
            findings.append(
                Finding(
                    "anomalie",
                    "TCP",
                    p,
                    f"{n} SYN dont la reponse SYN-ACK ne remonte pas jusqu'a ce point",
                    rule_id="syn_reply_missing",
                )
            )

    # -- RTP / qualite voix --
    for s in r.rtp_streams:
        if s.get("mos") is None:
            continue
        mos = s["mos"]
        if mos < 3.0:
            sev = "anomalie"
        elif mos < 3.6:
            sev = "a_surveiller"
        else:
            continue
        short_label = s["label"].split(" (SSRC=")[0]  # retire le SSRC, garde src:port -> dst:port
        findings.append(
            Finding(
                sev,
                "RTP/Voix",
                short_label,
                f"MOS estime {mos:.2f} (R-factor {s['r_factor']:.0f})",
                sample_size=s.get("sample_count"),
                rule_id="rtp_quality_mos",
            )
        )

    # -- decomposition reseau / serveur --
    if r.server_think_time:
        overall = [t for turns in r.server_think_time.values() for t in turns]
        if overall:
            import statistics

            avg_server = statistics.mean(overall)
            net_pair = (r.points[0], r.points[-1]) if len(r.points) >= 2 else None
            net_lat = r.latency.get(net_pair) if net_pair else None
            if net_lat:
                avg_net = statistics.mean(net_lat)
                if avg_server > 3 * avg_net and avg_server > 20:
                    findings.append(
                        Finding(
                            "a_surveiller",
                            "Reseau/Serveur",
                            "global",
                            f"temps de traitement serveur moyen {avg_server:.0f}ms >> temps "
                            f"reseau {avg_net:.1f}ms -> ralentissement probablement applicatif",
                            sample_size=len(overall),
                            rule_id="server_processing_dominant",
                        )
                    )

    # -- DHCP --
    for p, n in r.dhcp_nak_count.items():
        if n > 0:
            findings.append(
                Finding(
                    "anomalie",
                    "DHCP",
                    p,
                    f"{n} DHCPNAK (demande rejetee par le serveur)",
                    rule_id="dhcp_issues",
                )
            )
    for (a, b), missing in r.dhcp_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    "anomalie",
                    "DHCP",
                    seg,
                    f"{len(missing)} message(s) DHCP manquant(s) sur ce segment (attribution IP a risque)",
                    evidence=_evidence(seg, missing),
                    rule_id="dhcp_issues",
                )
            )

    # -- SIP --
    # sip_failed_calls : pas d'evidence attachee -- le message EST deja la
    # preuve (un appel echoue = une ligne), l'attacher en evidence serait un
    # pur doublon (meme raisonnement que l'absence de sample_size sur un
    # compteur brut, voir docstring en tete de fichier).
    findings.extend(Finding("anomalie", "SIP", "global", f, rule_id="sip_issues") for f in r.sip_failed_calls)
    for (a, b), missing in r.sip_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    "anomalie",
                    "SIP",
                    seg,
                    f"{len(missing)} message(s) de signalisation manquant(s) sur ce segment",
                    evidence=_evidence(seg, missing),
                    rule_id="sip_issues",
                )
            )

    # -- DNS --
    for p, n in r.dns_nxdomain_count.items():
        if n > 0:
            findings.append(
                Finding(
                    "info",
                    "DNS",
                    p,
                    f"{n} reponse(s) NXDOMAIN (domaine inexistant -- pas forcement un probleme reseau)",
                    rule_id="dns_nxdomain",
                )
            )
    for p, n in r.dns_servfail_count.items():
        if n > 0:
            findings.append(
                Finding(
                    "anomalie",
                    "DNS",
                    p,
                    f"{n} reponse(s) SERVFAIL (echec de resolution cote serveur/resolveur -- "
                    f"souvent pris a tort pour un probleme reseau)",
                    rule_id="dns_servfail",
                )
            )
    for p, timeouts in r.dns_timeout.items():
        if timeouts:
            findings.append(
                Finding(
                    "anomalie",
                    "DNS",
                    p,
                    f"{len(timeouts)} requete(s) DNS sans aucune reponse observee dans la "
                    f"capture (timeout applicatif ou serveur/resolveur injoignable)",
                    evidence=_evidence(p, timeouts, r.dns_timeout_frames.get(p, [])),
                    rule_id="dns_timeout",
                )
            )
    for (a, b), missing in r.dns_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    "a_surveiller",
                    "DNS",
                    seg,
                    f"{len(missing)} message(s) DNS manquant(s) sur ce segment",
                    evidence=_evidence(seg, missing),
                    rule_id="dns_missing",
                )
            )
    if r.dns_duration_ms:
        import statistics

        avg = statistics.mean(r.dns_duration_ms)
        if avg > 200:
            findings.append(
                Finding(
                    "a_surveiller",
                    "DNS",
                    "global",
                    f"duree moyenne de resolution DNS {avg:.0f}ms (> 200ms) -- cause frequente "
                    f"de lenteurs percues a tort comme un probleme reseau",
                    sample_size=len(r.dns_duration_ms),
                    rule_id="dns_slow_resolution",
                )
            )

    # -- HTTP -- 4xx = "info" (souvent legitime : cote client/application,
    # cf. NXDOMAIN ci-dessus), 5xx = "anomalie" (echec cote serveur, meme
    # registre que SERVFAIL -- souvent pris a tort pour un probleme reseau
    # alors que les paquets ont bien transite).
    for p, n in r.http_client_error_count.items():
        if n > 0:
            texts, frames = _http_error_evidence(r.http_error_examples.get(p, []), 4, r.http_error_frames.get(p, []))
            findings.append(
                Finding(
                    "info",
                    "HTTP",
                    p,
                    f"{n} reponse(s) HTTP 4xx (erreur cote client -- pas forcement un probleme reseau)",
                    evidence=_evidence(p, texts, frames),
                    rule_id="http_client_error",
                )
            )
    for p, n in r.http_server_error_count.items():
        if n > 0:
            texts, frames = _http_error_evidence(r.http_error_examples.get(p, []), 5, r.http_error_frames.get(p, []))
            findings.append(
                Finding(
                    "anomalie",
                    "HTTP",
                    p,
                    f"{n} reponse(s) HTTP 5xx (echec cote serveur/application -- souvent pris a "
                    f"tort pour un probleme reseau)",
                    evidence=_evidence(p, texts, frames),
                    rule_id="http_server_error",
                )
            )
    for p, timeouts in r.http_timeout.items():
        if timeouts:
            findings.append(
                Finding(
                    "anomalie",
                    "HTTP",
                    p,
                    f"{len(timeouts)} requete(s) HTTP sans aucune reponse observee dans la capture",
                    evidence=_evidence(p, timeouts, r.http_timeout_frames.get(p, [])),
                    rule_id="http_timeout",
                )
            )
    for (a, b), missing in r.http_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    "a_surveiller",
                    "HTTP",
                    seg,
                    f"{len(missing)} message(s) HTTP manquant(s) sur ce segment",
                    evidence=_evidence(seg, missing),
                    rule_id="http_missing",
                )
            )
    if r.http_response_time_ms:
        import statistics

        avg = statistics.mean(r.http_response_time_ms)
        if avg > 500:
            findings.append(
                Finding(
                    "a_surveiller",
                    "HTTP",
                    "global",
                    f"duree moyenne de reponse HTTP {avg:.0f}ms (> 500ms) -- latence applicative "
                    f"perceptible par l'utilisateur",
                    sample_size=len(r.http_response_time_ms),
                    rule_id="http_slow_response",
                )
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.segment))
    logger.debug("build_findings: retour findings={}", summarize(findings, "findings"))
    return findings
