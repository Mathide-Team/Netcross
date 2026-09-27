"""
netcross_report.triage -- agrege les Finding (ou DiffFinding) produits
par ailleurs pour repondre a une question que synthesis.py ne pose pas :
"par ou je commence a regarder ?"

Aujourd'hui, synthesis.build_findings() produit une liste plate de
constats, un par regle declenchee, triee par severite puis categorie.
Un segment touche par 4 categories differentes en meme temps (RST
localise + remarquage DSCP + fragmentation qui apparaît + TTL instable,
par exemple) est une bien meilleure piste qu'un segment avec un seul
indice isole -- mais rien n'agrege ca aujourd'hui, il faut le voir a
l'oeil en parcourant la liste.

Module volontairement duck-type : il ne connait ni synthesis.Finding
ni baseline_diff.DiffFinding, il attend seulement des objets exposant
`.severity`, `.category`, `.segment`, `.message`. Ca lui permet de
fonctionner indifferemment sur les deux (ou sur un melange des deux --
un run d'analyse simple ET un diff avant/apres, agreges ensemble) sans
creer de dependance entre netcross_core et netcross_report ni entre
synthesis.py et baseline_diff.py.

Score de confiance (sample_size) : certains findings portent aussi un
`.sample_size` optionnel (taille de l'echantillon derriere une valeur
ESTIMEE -- taux, moyenne, MOS -- voir synthesis.py/baseline_diff.py pour
le detail de ce qui est annote). Lu ici via `getattr(f, "sample_size",
None)`, meme prudence duck-type que pour severity/category/segment/message
: un objet qui n'a pas cet attribut (ancien code, findings synthetiques
de test) est traite comme un echantillon de taille inconnue -- PAS comme
un echantillon faible, pour ne pas penaliser a tort ce qui n'a jamais ete
annote. Un finding dont l'echantillon est explicitement petit voit son
poids amorti dans le score (pas exclu : reste visible, juste moins
dominant), et le segment est marque `low_confidence` si TOUS ses findings
qui comptent reellement dans le score (poids > 0) reposent sur un petit
echantillon -- objectif : eviter qu'un segment ne remonte en tete du
triage sur la seule foi d'une moyenne calculee sur 2 paquets.

Preuves (evidence, Session 32, etendu a DiffFinding en Session 33) :
print_triage() affiche aussi, sous chaque finding qui en porte, les
lignes de preuve (`.evidence`, liste d'EvidenceLink) deja rattachees par
synthesis.build_findings() ou netcross_core.baseline_diff.diff_reports()
-- meme lecture duck-type prudente que sample_size ci-dessus (`getattr(f,
"evidence", None) or ()`), absente sur les categories sans preuve source
cablee (voir baseline_diff.py/synthesis.py pour le detail par categorie)
et sur les findings synthetiques de test qui n'ont pas cet attribut.
Rien n'est recalcule ici : print_triage() se contente d'afficher une
donnee deja portee par l'objet.

Reference paquet (PacketEvidence, Session 35) : quand une ligne de preuve
porte un `packet` (aujourd'hui uniquement PMTUD, voir synthesis.py), son
numero de trame tshark est affiche entre parentheses a la suite du texte
-- meme prudence duck-type (`e.packet`, `None` par defaut).
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger, summarize
from netcross_report.synthesis import Finding

logger = get_logger(__name__)

# Poids par defaut : couvre a la fois le vocabulaire de synthesis.Finding
# ("anomalie"/"a_surveiller"/"info") et celui de baseline_diff.DiffFinding
# ("regression"/"a_verifier"/"amelioration"/"stable"). Une amelioration ou
# un etat stable n'est pas une preuve de probleme -> poids nul, mais reste
# liste dans les findings du segment pour contexte si besoin.
DEFAULT_SEVERITY_WEIGHTS: dict[str, float] = {
    "anomalie": 3.0,
    "regression": 3.0,
    "a_surveiller": 1.0,
    "a_verifier": 1.0,
    "info": 0.0,
    "stable": 0.0,
    "amelioration": 0.0,
}

# Un echantillon strictement inferieur a ce seuil est juge trop petit pour
# faire pleinement confiance a une valeur estimee (taux/moyenne/MOS) -- le
# finding reste compte, mais avec un poids amorti (voir _finding_weight).
LOW_SAMPLE_THRESHOLD = 3
LOW_SAMPLE_WEIGHT_FACTOR = 0.5


def _finding_weight(f: Finding, weights: dict[str, float]) -> float:
    w = weights.get(f.severity, 0.0)
    sample_size = getattr(f, "sample_size", None)
    if sample_size is not None and sample_size < LOW_SAMPLE_THRESHOLD:
        w *= LOW_SAMPLE_WEIGHT_FACTOR
    logger.debug("_finding_weight: retour w")
    return w


@dataclass
class SegmentScore:
    segment: str
    score: float
    categories: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    low_confidence: bool = False

    @property
    def convergent(self) -> bool:
        """Vrai si au moins 2 categories differentes pointent vers ce segment --
        c'est la signature d'un vrai faisceau de preuves, pas un artefact
        d'une seule regle trop sensible."""
        logger.debug("convergent: retour booleen")
        return len(self.categories) >= 2


def rank_segments(
    findings: Iterable[Finding],
    severity_weights: dict[str, float] | None = None,
    convergence_bonus: float = 1.5,
    min_score: float = 0.0,
) -> list[SegmentScore]:
    """
    Regroupe des findings par segment (point ou "A -> B") et les classe
    par score decroissant.

    score(segment) = somme des poids de severite des findings sur ce
    segment + convergence_bonus * (nombre de categories distinctes - 1)

    Le bonus de convergence recompense explicitement la diversite des
    categories, pas seulement le nombre brut de findings : 4 constats
    "Pertes" sur le meme segment (souvent la meme cause qui se repete)
    pesent moins que 2 constats "TCP" + "Fragmentation" sur ce meme
    segment (deux mecanismes independants qui pointent au meme endroit).

    findings : n'importe quel iterable d'objets avec .severity, .category,
        .segment, .message -- typiquement une liste de synthesis.Finding,
        de baseline_diff.DiffFinding, ou un melange des deux.
    min_score : segments dont le score final est <= min_score ne sont pas
        remontes (defaut 0.0 : un segment sans aucune preuve ponderee,
        uniquement des findings "info"/"stable", n'apparait pas).

    Un finding dont `.sample_size` est renseigne et < LOW_SAMPLE_THRESHOLD
    voit son poids de severite amorti (voir _finding_weight) plutot
    qu'exclu -- protege le classement contre une estimation (taux/moyenne/
    MOS) fragile qui dominerait le score a tort. Le SegmentScore resultant
    est marque `low_confidence=True` si la totalite de ses findings a
    poids non nul en dependent.
    """
    logger.debug(
        "rank_segments: findings={} severity_weights={} convergence_bonus={} min_score={}",
        summarize(findings, "findings"),
        summarize(severity_weights, "severity_weights"),
        summarize(convergence_bonus, "convergence_bonus"),
        summarize(min_score, "min_score"),
    )
    weights = severity_weights or DEFAULT_SEVERITY_WEIGHTS
    by_segment: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_segment[f.segment].append(f)

    scored: list[SegmentScore] = []
    for segment, segment_findings in by_segment.items():
        base_score = sum(_finding_weight(f, weights) for f in segment_findings)
        categories = sorted({f.category for f in segment_findings})
        convergence = convergence_bonus * max(0, len(categories) - 1)
        total = base_score + convergence
        if total <= min_score:
            continue
        segment_findings_sorted = sorted(
            segment_findings,
            key=lambda f: (-_finding_weight(f, weights), f.category),
        )
        # low_confidence : vrai seulement si TOUS les findings qui comptent
        # reellement dans le score (poids de severite > 0 -- anomalie/
        # regression/a_surveiller/a_verifier, pas info/stable/amelioration)
        # reposent sur un echantillon explicitement petit. Un finding sans
        # sample_size (attribut absent -- ancien code, test synthetique) est
        # traite comme "echantillon de confiance inconnue", jamais compte
        # comme faible : evite de marquer a tort un segment ou l'annotation
        # n'a simplement pas encore ete faite (voir synthesis.py/
        # baseline_diff.py pour ce qui est annote a ce jour).
        actionable = [f for f in segment_findings if weights.get(f.severity, 0.0) > 0]
        low_confidence = bool(actionable) and all(
            (ss := getattr(f, "sample_size", None)) is not None and ss < LOW_SAMPLE_THRESHOLD for f in actionable
        )
        scored.append(SegmentScore(segment, total, categories, segment_findings_sorted, low_confidence))

    scored.sort(key=lambda s: (-s.score, s.segment))
    logger.debug("rank_segments: retour scored")
    return scored


def print_triage(ranked: list[SegmentScore], top_n: int = 5) -> None:
    logger.debug("print_triage: ranked={} top_n={}", summarize(ranked, "ranked"), summarize(top_n, "top_n"))
    print("=" * 70)
    print(
        f"TRIAGE -- top {top_n} segments a regarder en premier "
        f"(score = severite ponderee + bonus de convergence inter-categories)"
    )
    print("=" * 70)

    if not ranked:
        print("\nAucun segment avec un score de preuve suffisant.")
        logger.debug("print_triage: retour (None implicite)")
        return

    for rank, s in enumerate(ranked[:top_n], start=1):
        tag = " [CONVERGENT]" if s.convergent else ""
        tag += " [ECHANTILLON FAIBLE]" if s.low_confidence else ""
        print(f"\n{rank}. {s.segment}  -- score {s.score:.1f}{tag}")
        print(f"   categories impliquees : {', '.join(s.categories)}")
        for f in s.findings:
            print(f"     [{f.severity:12s}] {f.category:14s} : {f.message}")
            # evidence (Session 32) : meme prudence duck-type que sample_size
            # ci-dessus -- absent sur DiffFinding et sur les findings qui
            # n'ont pas encore de preuve source cablee, voir synthesis.py.
            for e in getattr(f, "evidence", None) or ():
                packet = getattr(e, "packet", None)
                suffix = f" (trame #{packet.frame_number})" if packet is not None else ""
                print(f"         - {e.text}{suffix}")

    if len(ranked) > top_n:
        print(
            f"\n... {len(ranked) - top_n} autre(s) segment(s) avec un score plus faible "
            f"(non affiches, voir la liste complete des findings pour le detail)"
        )
    logger.debug("print_triage: fin")


# -- Score de sante synthetique (0-100) --
#
# Calculable a partir du triage deja existant (rank_segments) plutot que
# d'un nouveau calcul independant : reflete la MEME evidence ponderee que
# print_triage(), juste condensee en un seul chiffre pour une lecture en
# un coup d'oeil (dashboard, premiere ligne d'un rapport, ticket). Ne
# remplace ni print_triage() ni le detail des findings -- une synthese en
# plus, pas un nouveau niveau de decision. health_score() ne prend QUE la
# sortie de rank_segments() en entree, jamais les findings bruts : garantit
# que le score affiche est toujours coherent avec le triage affiche a cote
# (meme donnee, juste condensee), jamais un calcul parallele qui pourrait
# diverger.
#
# Formule : decroissance exponentielle de la somme des scores de segment
# (deja ponderes par severite + bonus de convergence, voir rank_segments
# ci-dessus) plutot qu'une soustraction lineaire plafonnee a 0 -- une
# dizaine de constats mineurs ne doit pas mecaniquement ecraser le score a
# zero de la meme maniere qu'une grosse anomalie unique, et le resultat
# reste toujours strictement borne dans [0, 100] sans seuil de coupure
# arbitraire a documenter/justifier a part. HEALTH_SCORE_SCALE controle la
# sensibilite (plus petit = decroissance plus rapide) -- choisi
# empiriquement (pas issu d'une norme) pour qu'un seul segment avec 1
# anomalie isolee (score 3.0, voir DEFAULT_SEVERITY_WEIGHTS) fasse deja
# glisser le score hors de la tranche "bon" (voir HEALTH_LABEL_THRESHOLDS),
# sans pour autant l'ecraser a lui seul.
#
# Fonctionne indifferemment sur un triage de Finding (severites
# anomalie/a_surveiller/info -- score de sante "instantane" d'un run) ou de
# DiffFinding (regression/a_verifier/amelioration/stable -- meme
# duck-typing que rank_segments). Pour un diff, le score reflete plutot
# l'AMPLEUR DES REGRESSIONS detectees entre baseline et courant, pas un
# etat absolu de l'un des deux runs : 100 = aucune regression significative
# entre les deux, pas "reseau parfait" -- meme reserve d'interpretation que
# pour tout ce qui est deja produit par ce module sur un diff (voir
# rank_segments/print_triage ci-dessus, deja generiques sur les deux
# vocabulaires).
HEALTH_SCORE_SCALE = 12.0

# Tranches inclusives par le bas, evaluees dans l'ordre -- premier seuil
# atteint (le plus haut) qui gagne. Le dernier (0.0) est un garde-fou
# toujours atteint en dernier recours (health_score() ne renvoie jamais de
# valeur negative).
HEALTH_LABEL_THRESHOLDS: list[tuple[float, str]] = [
    (85.0, "bon"),
    (60.0, "a_surveiller"),
    (35.0, "degrade"),
    (0.0, "critique"),
]

HEALTH_LABELS: dict[str, str] = {
    "bon": "Bon",
    "a_surveiller": "A surveiller",
    "degrade": "Degrade",
    "critique": "Critique",
}


def health_score(ranked: list[SegmentScore], scale: float = HEALTH_SCORE_SCALE) -> int:
    """
    ranked : sortie de rank_segments() -- PAS les findings bruts, voir la
    note de conception ci-dessus. Renvoie un entier dans [0, 100] :
    100 si `ranked` est vide ou si la somme de ses scores est <= 0 (aucune
    preuve ponderee), decroissant ensuite avec le total des scores de
    segment (voir SegmentScore.score).
    """
    total = sum(s.score for s in ranked)
    if total <= 0:
        logger.debug("health_score: retour 100")
        return 100
    logger.debug("health_score: retour round(...)")
    return round(100.0 * math.exp(-total / scale))


def health_label(score: int) -> str:
    """Cle courte identifiant la tranche du score (voir HEALTH_LABELS pour
    le libelle affichable, HEALTH_LABEL_THRESHOLDS pour les bornes)."""
    for threshold, label in HEALTH_LABEL_THRESHOLDS:
        if score >= threshold:
            logger.debug("health_label: retour label")
            return label
    logger.debug("health_label: retour 'critique'")
    return "critique"  # inatteignable en pratique (dernier seuil = 0.0 et
    # health_score() ne renvoie jamais de valeur negative) -- garde-fou.


def format_health_line(score: int) -> str:
    """Rendu texte commun (CLI console + GUI GTK4) -- une seule source pour
    le libelle exact, pour eviter que les deux divergent legerement."""
    logger.debug("format_health_line: retour valeur")
    return f"Score de sante : {score}/100 ({HEALTH_LABELS[health_label(score)]})"
