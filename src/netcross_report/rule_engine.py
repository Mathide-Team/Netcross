"""
netcross_report.rule_engine -- premier PILOTE du moteur d'EXECUTION
evoque comme premier chantier ouvert par CLAUDE.md/`Prochaine feature`
depuis la Session 54 (bibliotheque de regles §6.2 complete, 41 regles) :
faire evaluer une `Rule` du catalogue (`netcross_core.expert_rules`)
contre un `Report` pour PRODUIRE elle-meme un `Finding`, plutot que
`rule_id` se contente d'ANNOTER apres coup un `Finding` deja construit
par le code procedural existant (`synthesis.py::build_findings`,
Sessions 46-54).

Emplacement dans `netcross_report`, PAS `netcross_core` : le contrat de
couches (`pyproject.toml` [tool.importlinter], `netcross_gtk4 ->
netcross_report -> netcross_core -> pcap_parser`) interdit a
`netcross_core` de dependre de `netcross_report` -- or produire un
`Finding` exige d'importer `netcross_report.synthesis.Finding`. Ce
module vit donc au meme niveau que `synthesis.py`, et importe dans le
sens autorise (`netcross_report` -> `netcross_core.expert_rules`), verifie
avec `PYTHONPATH=src lint-imports` (voir Commandes qualite, CLAUDE.md).

Portee VOLONTAIREMENT minimale de ce premier pilote (meme discipline que
le pilote `PacketEvidence`/PMTUD de la Session 35, ou le premier lot de
l'Session 40 sur ExpertEvent) : UNE seule regle evaluee,
`loss_per_segment` (`Report.loss_count`/`Report.seen_count`, la plus
simple du catalogue -- un seul seuil numerique nomme dans
`Rule.thresholds`, aucune correlation entre deux signaux). Les 40 autres
regles du catalogue n'ont PAS d'evaluateur enregistre ici : `evaluate()`
leve `NotImplementedError` pour elles plutot que de deviner un mapping
non verifie (aucun evaluateur invente sans le lire d'abord dans le code
procedural existant -- meme discipline que le catalogue lui-meme, voir
docstring de module d'`expert_rules.py`).

Ce module ne REMPLACE ni ne PILOTE encore `synthesis.py::build_findings`
(qui reste l'unique source de verite en production, cote CLI/GUI,
inchangee par cette session) : `evaluate()` est un CONSOMMATEUR
supplementaire du meme `Report`, produisant un `Finding` INDEPENDANT du
chemin procedural existant, pour verifier par construction que le
catalogue declaratif est capable de PILOTER une detection reelle et pas
seulement de la decrire apres coup. Le test de non-regression associe
(`tests/test_rule_engine.py::test_equivalent_a_build_findings_...`)
compare directement les deux chemins (procedural vs moteur) sur les
memes `Report` que `tests/test_synthesis.py` pour `loss_per_segment` :
memes severites, memes messages, meme `sample_size`. Cablage a un
CLI/GUI reel, extension a d'autres regles, et bascule effective de
`build_findings` vers ce moteur : hors perimetre de ce pilote, a
reconsiderer sessions suivantes (voir CLAUDE.md, section Prochaine
feature).

Portee de la Session 56 : extension du pilote a QUATRE regles
supplementaires (cinq au total) -- les candidats a "seuil unique simple,
sans correlation" nommes explicitement par CLAUDE.md/section "Prochaine
feature" depuis la Session 55 : `tcp_zero_window`, `hop_delta_outliers`,
`dns_nxdomain`, `dns_servfail`. Meme discipline que la Session 55:
chaque evaluateur reproduit EXACTEMENT son bloc source dans
`synthesis.py::build_findings()` -- ces quatre blocs iterent directement
le dict `Report.<compteur>.items()`, PAS `report.points` comme le fait
`loss_per_segment` (verifie bloc par bloc avant redaction, pas suppose
uniforme). Difference avec `loss_per_segment` : aucune de ces quatre
regles ne porte de seuil dans `rule.thresholds` (dict vide dans le
catalogue) -- severite UNIQUE par regle, pas calculee a partir d'un
seuil. Plutot que de la recopier en dur une seconde fois (une fois dans
`expert_rules.py`, une fois ici), chaque evaluateur lit `rule.severity`
directement : c'est la piece PILOTEE par le catalogue pour ce lot, au
meme titre que `rule.thresholds["anomalie_rate_pct"]` pour
`loss_per_segment` -- egalite avec la constante procedurale VERIFIEE par
le test d'equivalence de chaque regle, pas seulement supposee.

Correction apportee cette session : la Session 55 groupait "les
compteurs DNS bruts" comme un candidat homogene unique, mais les QUATRE
compteurs nommes par expert_rules.py ne partagent pas tous la meme
forme -- verifie dans `netcross_core/models.py` avant redaction :
`dns_nxdomain_count`/`dns_servfail_count` sont de simples
`dict[str, int]` (retenus ici), tandis que `dns_timeout`
(`dict[str, list[str]]`) et `dns_missing`
(`dict[tuple[str, str], list[str]]`) portent des LISTES, leur bloc
procedural passant par `_evidence()` (synthesis.py) et comptant
`len(...)` plutot qu'un entier compare directement a 0 -- forme
differente, non retenue dans ce lot (voir "Non traite dans cette passe",
docs/sessions/session-56.md).

`hop_delta_outliers` est cle par une PAIRE de points adjacents
(`(a, b)`, `report.hop_delta_outliers.items()`) et non un point seul --
la seule des quatre dans ce cas, segment forme `f"{a} -> {b}"` comme le
bloc source. Le mode statistique nomme par `Rule.preconditions` (delta
de TTL le plus frequent observe sur la paire) est deja precalcule en
amont (`netcross_core.analysis`, directement dans
`Report.hop_delta_outliers`) : cet evaluateur ne fait QUE lire ce
compteur deja calcule, pas plus complexe a reproduire ici qu'un compteur
simple par point.

Portee de la Session 57 : extension du pilote a DEUX regles
supplementaires (sept au total) -- `dns_timeout` et `dns_missing`, les
deux candidats nommes explicitement par CLAUDE.md/section "Prochaine
feature" depuis la Session 56 comme "premiers candidats naturels si ce
chantier continue", ecartes du lot precedent pour forme differente
(compteurs en LISTES, pas en entiers -- `Report.dns_timeout`
`dict[str, list[str]]`, `Report.dns_missing`
`dict[tuple[str, str], list[str]]`) : leur bloc procedural source passe
par `_evidence()` (`synthesis.py`) pour construire un `Finding.evidence`
non vide, jamais fait jusqu'ici par ce pilote (les sept regles
precedentes -- Session 55/56 -- n'utilisent aucune le kwarg `evidence`
de `Finding`). `_evidence()` est une fonction PRIVEE de `synthesis.py` :
copie locale ci-dessous (`_evidence`), meme discipline deja appliquee a
`_pct` depuis la Session 55 -- jamais importee telle quelle a travers
une frontiere de module, corps verifie ligne a ligne identique a
l'original. `dns_timeout` reste par POINT (`report.dns_timeout.items()`,
comme `dns_nxdomain`/`dns_servfail`), avec en plus `frames` (liste
parallele `report.dns_timeout_frames.get(p, [])`, meme mecanisme que
`PacketEvidence` ailleurs dans le projet depuis la Session 35).
`dns_missing` est clee par une PAIRE de points adjacents (comme
`hop_delta_outliers`), mais SANS `frames` : verifie dans `models.py`
avant redaction -- aucun champ `dns_missing_frames` sur `Report`,
absence volontaire cote source (le bloc procedural appelle
`_evidence(seg, missing)` a deux arguments seulement), pas un oubli de
ce pilote. Severite UNIQUE pour les deux regles (aucun seuil dans
`rule.thresholds`, dict vide dans le catalogue -- verifie), lue depuis
`rule.severity` comme les quatre regles de la Session 56.
`tests/test_rule_engine.py` etend la meme structure par regle
(declenche/silencieux/equivalence avec `build_findings()`, filtre par
`rule_id`) et ajoute un test d'equivalence dedie a la presence
d'`evidence` (Session 55/56 ne le verifiaient jamais, faute de regle
concernee).

Portee de cette session (58) : extension du pilote a SIX regles
supplementaires (treize au total) -- le bloc `-- TCP avance --` de
`synthesis.py::build_findings()` (lignes ~608-722 avant cette session)
regroupe SIX regles consecutives non encore pilotees, toutes de meme
forme que `tcp_zero_window` (Session 56) : compteur `dict[str, int]`
sur `Report`, iteration DIRECTE (`report.<compteur>.items()`, pas
`report.points`), `if n > 0`, severite UNIQUE lue depuis `rule.severity`
(aucune des six ne porte de seuil dans `rule.thresholds` -- dict vide,
verifie dans le catalogue avant redaction), aucune `evidence`. Verifie
bloc par bloc dans `synthesis.py` avant d'ecrire chaque evaluateur,
comme demande par CLAUDE.md/"Prochaine feature" depuis la Session 56
("ne pas supposer qu'elles sont toutes aussi directes... verifier bloc
par bloc") -- les six confirmees identiques en forme a
`tcp_zero_window`, aucune ne cache de correlation ou de seuil
supplementaire : `tcp_retransmission_rto`/`tcp_retransmission_spurious`
(`Report.retrans_rto`/`retrans_spurious`, severite `a_surveiller` les
deux), `tcp_retransmission_fast` (`Report.retrans_fast`, severite
`info` -- seule severite `info` du lot), `tcp_rst_localized`
(`Report.rst_localized`, severite `anomalie`), `tcp_syn_no_synack`
(`Report.syn_no_synack`, severite `anomalie`), `syn_reply_missing`
(`Report.syn_reply_missing`, severite `anomalie`). Les trois
retransmissions partagent la meme discipline de classement mutuellement
exclusif documentee dans `expert_rules.py` (priorite spurious > fast >
simple, un paquet n'est compte que dans une seule des trois categories)
mais cela ne change rien cote evaluateur : chacune lit son propre
compteur deja agrege par `analysis.py`, aucune logique de classement a
reproduire ici. Les DEUX regles restantes du meme bloc source
(`tcp_options_stripped` -- deux sites de construction distincts,
`wscale_stripped`/`sack_stripped`, meme `rule_id` -- et `tcp_mss_clamped`
-- porte une `evidence` non vide via `_evidence()`, cle par PAIRE de
points) ne sont PAS retenues dans ce lot : formes differentes
(respectivement deux compteurs distincts fusionnes sous un seul
`rule_id`, jamais fait jusqu'ici par ce pilote, et une regle a
`evidence` cle par paire — voir "Prochaine feature", CLAUDE.md).
`tests/test_rule_engine.py` etend la meme structure par regle
(declenche/silencieux/equivalence avec `build_findings()`, filtre par
`rule_id` -- categorie "TCP" porte desormais NEUF `rule_id` distincts
dans ce pilote, un filtre par seule categorie fausserait toujours la
comparaison, meme raison que depuis la Session 56). Les ~25 autres
regles du catalogue restent sans evaluateur (NotImplementedError) : non
auditees individuellement pour leur simplicite, meme reserve documentee
depuis la Session 56 (voir CLAUDE.md, section "Prochaine feature").

Portee de cette session (59) : extension du pilote a DEUX regles
supplementaires (quinze au total) -- `tcp_options_stripped` et
`tcp_mss_clamped`, les deux candidats nommes explicitement par
CLAUDE.md/section "Prochaine feature" depuis la Session 58 comme
derniers du meme bloc source `-- TCP avance --` de `synthesis.py`, tous
deux ecartes du lot precedent pour forme differente. `tcp_options_stripped`
est la PREMIERE regle de ce pilote a fusionner DEUX compteurs `Report`
DISTINCTS (`wscale_stripped`, `sack_stripped`, tous deux
`dict[tuple[str, str], int]`) sous un seul `rule_id` catalogue -- verifie
dans `expert_rules.py` : une seule entree `Rule` couvre les deux
compteurs, meme severite ('a_surveiller') pour les deux.
`_evaluate_tcp_options_stripped()` reproduit donc les DEUX boucles
consecutives du bloc source, dans le meme ordre, avec le meme `rule_id`
sur les deux `Finding`. `tcp_mss_clamped` reste plus proche de la forme
deja pilotee (`dns_timeout`/`dns_missing`, Session 57) : compteur
`report.mss_clamped` clee par PAIRE de points (comme
`tcp_options_stripped`), mais `Finding.evidence` non vide via
`_evidence()` (copie locale, meme discipline), `examples`/`frames`
depuis `report.mss_clamped_examples`/`mss_clamped_frames`, meme liste
parallele que cote procedural. Severite UNIQUE 'info' (seule severite
'info' d'un rule_id a evidence de ce pilote). `tests/test_rule_engine.py`
etend la meme structure par regle ; pour `tcp_options_stripped`, tests
dedies aux DEUX compteurs sources separement (un finding wscale seul, un
finding sack seul, les deux ensemble) en plus du test d'equivalence
habituel, jamais fait jusqu'ici pour une regle a deux boucles sources.
Les ~26 autres regles du catalogue restent sans evaluateur
(NotImplementedError) : non auditees individuellement pour leur
simplicite, meme reserve documentee depuis la Session 56 (voir
CLAUDE.md, section "Prochaine feature").

Portee de cette session (60) : extension du pilote a TROIS regles
supplementaires (dix-huit au total) -- `ttl_variation`, `pcp_change` et
`icmp_fragmentation_needed`, trois des TREIZE candidats "de forme
simple mais NON verifies bloc par bloc" nommes explicitement par
CLAUDE.md/section "Prochaine feature" depuis la Session 59. Verifies un par un
dans `synthesis.py` ET `netcross_core/models.py` avant redaction, comme
demande par cette section -- pas supposes simples par ressemblance :
`ttl_variation` (`report.ttl_unstable`, `dict[str, int]` PAR POINT,
confirme dans `models.py`) reproduit exactement la forme deja pilotee
par `tcp_zero_window` (Session 56) -- aucune `evidence`, aucun seuil
dans `rule.thresholds` (dict vide, verifie dans le catalogue), severite
UNIQUE lue depuis `rule.severity` ('a_surveiller'). `pcp_change`
(`report.pcp_change`, `dict[tuple[str, str], int]` PAR PAIRE de points
adjacents, confirme dans `models.py`) reproduit exactement la forme
deja pilotee par `hop_delta_outliers` (Session 56) -- meme absence
d'`evidence`/de seuil, severite UNIQUE 'a_surveiller'.
`icmp_fragmentation_needed` est la DEUXIEME regle de ce pilote (apres
`tcp_options_stripped`, Session 59) a fusionner DEUX compteurs `Report`
DISTINCTS sous un seul `rule_id` catalogue -- `report.icmp_frag_needed`
(IPv4) et `report.icmpv6_too_big` (IPv6), verifies tous deux
`dict[str, int]` PAR POINT dans `models.py` -- mais plus simple que
`tcp_options_stripped` : par point (pas par paire), aucune `evidence`.
Une seule `Rule` du catalogue couvre les deux compteurs (meme severite
'info' pour les deux, verifie dans `expert_rules.py`), donc un seul
`rule_id` sur les DEUX boucles comme cote procedural.

Les DIX autres candidats nommes par la meme section depuis la Session
59 restent volontairement hors de ce lot, formes plus eloignees des
evaluateurs deja ecrits (verifie bloc par bloc cette session, pas
seulement suppose) : `dhcp_issues` et `sip_issues` fusionnent chacune
DEUX a TROIS compteurs `Report` de formes DIFFERENTES entre elles (par
point sans evidence + par paire avec evidence pour `dhcp_issues` ;
`sip_issues` ajoute une troisieme forme, une liste de chaines
deja formatees construisant directement un `Finding` par entree via une
comprehension, jamais fait jusqu'ici par ce pilote) -- contrairement a
`icmp_fragmentation_needed`/`tcp_options_stripped` ci-dessus, dont les
compteurs fusionnes partagent la MEME forme entre eux. `http_client_error`/
`http_server_error` necessitent de copier localement une DEUXIEME
fonction privee de `synthesis.py` (`_http_error_evidence()`, filtrage
des exemples par classe de statut HTTP), jamais fait jusqu'ici pour ce
pilote (une seule fonction privee copiee a ce stade, `_evidence()`).
`tls_cert_invalid_dates`, `tls_cert_mismatch`, `tls_handshake_no_reply`,
`tls_handshake_incomplete`, `http_timeout` et `http_missing` sont en
revanche deja confirmes de forme directement reproductible (compteur
entier ou liste PAR POINT ou PAR PAIRE avec `evidence` via `_evidence()`
deja copiee, meme forme que `tcp_mss_clamped`/`dns_timeout`/
`dns_missing`) -- candidats naturels pour un prochain lot, voir
CLAUDE.md/"Prochaine feature".

Portee de la Session 61 : extension du pilote a ces SIX candidats
(vingt-quatre regles sur 41). Chacun verifie bloc par bloc dans
`synthesis.py` ET `netcross_core/models.py` avant redaction (pas
suppose reproductible par ressemblance malgre l'audit deja fait
Session 60) : `tls_cert_invalid_dates` (`Report.tls_cert_invalid_dates`,
`dict[str, int]` PAR POINT) et `tls_handshake_no_reply`/
`tls_handshake_incomplete` (memes types, memes champs `Report`)
reproduisent exactement la forme deja pilotee par `tcp_mss_clamped`
(Session 59) -- compteur entier, `evidence` a trois arguments.
`tls_cert_mismatch` (`Report.tls_cert_mismatch`,
`dict[tuple[str, str], int]` PAR PAIRE) reproduit la meme forme cote
paire de points. `http_timeout` (`Report.http_timeout`,
`dict[str, list[str]]` PAR POINT, une LISTE de textes deja formates
plutot qu'un entier -- condition `if timeouts:` et non `n > 0`)
reproduit exactement la forme deja pilotee par `dns_timeout` (Session
57). `http_missing` (`Report.http_missing`,
`dict[tuple[str, str], list[str]]` PAR PAIRE, condition `if missing:`)
reproduit la forme de `dns_missing` (Session 57) -- y compris l'absence
de troisieme argument `frames` a `_evidence()` (`Report` n'expose pas
de `http_missing_frames`, verifie dans `models.py`). Severite UNIQUE
lue depuis `rule.severity` pour chacune des six regles : 'anomalie'
pour les CINQ premieres (TLS x4 + `http_timeout`), 'a_surveiller' pour
`http_missing` seule (verifie dans `expert_rules.py`, aucune des six
regles ne porte de seuil dans `rule.thresholds` -- dict vide,
egalement verifie dans le catalogue). `tests/test_rule_engine.py` :
nouveaux tests par regle (voir docstring de `TestRuleEngine` -- au
minimum un test de declenchement, un test de non-declenchement, et un
test dedie a l'`evidence` pour les cinq regles qui en portent une),
plus mise a jour de `test_regle_connue_sans_evaluateur_leve_not_
implemented_error` (l'exemple de « regle connue mais non pilotee »
utilisait potentiellement l'un de ces six ids) et de
`test_available_rule_ids_ne_contient_que_les_regles_pilotees` (etendu
aux six nouveaux ids). Detail complet : `docs/sessions/session-61.md`.

Portee de la Session 62 : extension du pilote a DEUX regles
supplementaires (vingt-six au total, sur 41) -- `http_client_error` et
`http_server_error`, les DEUX derniers candidats deja confirmes de
forme directement reproductible nommes explicitement par CLAUDE.md/
« Prochaine feature » depuis la Session 60, ecartes du lot de la
Session 61 car ils necessitaient de copier une DEUXIEME fonction
privee de `synthesis.py` (`_http_error_evidence()`, jamais fait
jusqu'ici pour ce pilote -- une seule fonction privee copiee jusque-la,
`_evidence()`). Chacune verifiee bloc par bloc dans `synthesis.py` ET
`netcross_core/models.py` avant redaction (pas supposee reproductible
par ressemblance) : les deux reproduisent la forme du bloc `-- HTTP --`
(`Report.http_client_error_count`/`Report.http_server_error_count`,
`dict[str, int]` PAR POINT, condition `n > 0`), mais le texte/`frames`
passes a `_evidence()` sont d'abord FILTRES par `_http_error_evidence()`
depuis le champ PARTAGE `Report.http_error_examples`/
`Report.http_error_frames` (melange volontaire 4xx/5xx a la collecte
cote `analysis.py`, distinction faite uniquement au moment du filtrage
sur le suffixe "-> NNN" de chaque exemple, classe de statut 4 ou 5
selon la regle). Severite UNIQUE lue depuis `rule.severity` pour
chacune ('info' pour `http_client_error`, 'anomalie' pour
`http_server_error`, verifie dans `expert_rules.py`), aucune des deux
ne porte de seuil dans `rule.thresholds` (dict vide, egalement
verifie). `tests/test_rule_engine.py` : 10 nouveaux tests (5 par regle
-- declenche/silencieux/nul/evidence-filtree/equivalence, meme
discipline que `http_timeout`/`http_missing`), plus mise a jour de
`test_available_rule_ids_ne_contient_que_les_regles_pilotees` (etendu
aux deux nouveaux ids ; `test_regle_connue_sans_evaluateur_leve_
not_implemented_error` utilisait deja `dhcp_issues`, aucun changement
necessaire, ce candidat restant hors de ce lot -- voir « Prochaine
feature »). Avec ce lot, TOUS les candidats de forme directement
reproductible identifies depuis la Session 59 sont desormais pilotes :
seuls restent `dhcp_issues`/`sip_issues` (compteurs de formes
heterogenes entre eux, `sip_issues` ajoutant une troisieme forme jamais
pilotee) et les ~13 regles jamais auditees. Detail complet :
`docs/sessions/session-62.md`.

Portee de la Session 63 : extension du pilote aux DEUX DERNIERS
candidats deja audites bloc par bloc (Session 60) et restes en attente
depuis -- `dhcp_issues` et `sip_issues` (**vingt-huit regles au total,
sur 41**). Ce sont les deux seules regles dont les compteurs `Report`
fusionnes sous un meme `rule_id` n'ont PAS la meme forme ENTRE EUX,
contrairement a `tcp_options_stripped` (Session 59) et
`icmp_fragmentation_needed` (Session 60) : c'est cette heterogeneite,
pas une brique manquante, qui les avait ecartees des lots precedents.
Verifie bloc par bloc dans `synthesis.py`, `netcross_core/models.py` ET
`expert_rules.py` avant redaction (pas suppose reproductible par
ressemblance, malgre l'audit deja fait Session 60) :

- `dhcp_issues` fusionne `Report.dhcp_nak_count` (`dict[str, int]` PAR
  POINT, `n > 0`, sans `evidence` -- forme de `tcp_zero_window`) et
  `Report.dhcp_missing` (`dict[tuple[str, str], list[str]]` PAR PAIRE,
  `if missing:`, `evidence` via `_evidence()` a DEUX arguments -- forme
  de `dns_missing`). Les deux formes etant chacune deja pilotee
  ailleurs depuis les Sessions 56/57, AUCUNE brique nouvelle n'a ete
  necessaire ; seul restait un choix de CONCEPTION, tranche ci-dessous.
- `sip_issues` fusionne `Report.sip_failed_calls` et
  `Report.sip_missing`. Le second reprend exactement la forme de
  `dhcp_missing` ; le PREMIER introduit la TROISIEME forme de source de
  tout ce pilote, jamais rencontree en 27 evaluateurs : une `list[str]`
  simple (verifie dans `models.py`), pas un `dict` compteur du tout --
  messages DEJA FORMATES par `analysis.py::_analyse_sip()`, un
  `Finding` par entree via une comprehension, sur le segment litteral
  `"global"`, sans condition de garde (une liste vide ne produit rien
  par construction) et sans `evidence` (choix documente cote
  procedural : le message EST deja la preuve -- reproduit tel quel, ce
  pilote reproduit le chemin procedural, il ne l'ameliore pas).

Choix de conception tranche cette session (le seul restant, nomme comme
tel par CLAUDE.md depuis la Session 60) : UN seul evaluateur par regle
produisant les DEUX formes de `Finding`, plutot que deux entrees
`_EVALUATORS` distinctes. Raison : `_EVALUATORS` est cle par `Rule.id`
et le catalogue ne porte qu'UNE `Rule` pour chacune de ces deux regles
(verifie dans `expert_rules.py` -- pas de seconde entree de severite
differente) ; scinder exigerait d'inventer un `rule_id` absent du
catalogue, exactement ce que ce pilote s'interdit depuis la Session 55.
Meme resolution que `tcp_options_stripped`/`icmp_fragmentation_needed`,
et la seule compatible avec le test d'equivalence (cote procedural, les
deux boucles portent bien le MEME `rule_id`). Severite UNIQUE lue
depuis `rule.severity` ('anomalie' pour les deux regles, sur TOUS leurs
sites de construction), aucune des deux ne portant de seuil dans
`rule.thresholds` (dict vide, verifie dans le catalogue).
`tests/test_rule_engine.py` : tests dedies a CHAQUE compteur source
separement (meme discipline que `tcp_options_stripped`/
`icmp_fragmentation_needed`), plus les tests d'`evidence` et
d'equivalence habituels ; `test_regle_connue_sans_evaluateur_leve_not_
implemented_error` utilisait `dhcp_issues` comme exemple de « regle
connue mais non pilotee » depuis la Session 60 -- remplace cette
session, ce role passant a une regle encore non pilotee (voir le test).
DECOUVERTE de cette session, jamais rencontree par les 26 regles
precedentes et non anticipee par l'audit de la Session 60 :
`build_findings()` TRIE sa liste complete avant de la renvoyer
(`findings.sort(key=(SEVERITY_ORDER, category, segment))`, derniere
ligne de la fonction), alors qu'`evaluate()` renvoie ses `Finding` dans
l'ordre de CONSTRUCTION du bloc source. Pour les 26 regles deja
pilotees les deux ordres coincidaient par hasard (segments deja tries,
ou tous identiques -- cas de `tcp_options_stripped`, tri stable donc
ordre preserve), ce qui rendait les tests d'equivalence positionnels
valables sans qu'aucun ne l'ait jamais explicite. `sip_issues` est la
premiere a les separer : ses deux sites produisent le segment litteral
`"global"` PUIS `"A -> B"`, que le tri final remet dans l'ordre inverse
(`"A"` majuscule < `"g"` minuscule). Decision prise ici : `evaluate()`
ne reproduit deliberement PAS ce tri -- c'est une etape de PRESENTATION
appliquee par `build_findings()` a l'ensemble des 41 regles a la fois,
pas une propriete d'une regle prise isolement (un evaluateur qui
trierait ses propres `Finding` donnerait de toute facon un ordre
different du tri global des que deux regles se melangent). Le test
d'equivalence de `sip_issues` compare donc les deux chemins par
CONTENU, meme cle de tri appliquee aux deux cotes, et un test dedie
(`test_sip_issues_ordre_procedural_differe_de_l_ordre_de_construction`)
fige la divergence d'ordre elle-meme plutot que de la laisser
implicite ; la comparaison positionnelle restee possible pour
`dhcp_issues` est desormais annotee comme une coincidence, pas comme
une garantie. Point a reprendre le jour ou le chantier (c) de CLAUDE.md
sera ouvert (faire BASCULER `build_findings()` vers ce moteur) : c'est
ce tri final, et non les evaluateurs, qui devra alors rester le point
unique d'ordonnancement.

Avec ce lot, PLUS AUCUN candidat audite ne reste en attente : les 13
regles sans evaluateur sont toutes des regles JAMAIS auditees, dont les
CINQ a `correlation_rule` non `None` (voir CLAUDE.md, « Prochaine
feature »). Detail complet : `docs/sessions/session-63.md`.

Portee de la Session 64 : extension du pilote a UNE regle
supplementaire (vingt-neuf au total, sur 41) -- `vlan_change`, premiere
regle AUDITEE parmi les treize jamais couvertes identifiees par la
Session 63 (aucune n'avait ete lue bloc par bloc avant cette session).
Verifiee bloc par bloc dans `synthesis.py` (bloc `-- VLAN --`) ET
`netcross_core/models.py` avant redaction, pas supposee simple par
ressemblance malgre l'absence apparente de seuil dans son entree du
catalogue (`expert_rules.py`) : `report.vlan_change`
(`dict[tuple[str, str], int]` PAR PAIRE de points adjacents, confirme
dans `models.py`) reproduit EXACTEMENT la forme deja pilotee par
`hop_delta_outliers` (Session 56) et `pcp_change` (Session 60) --
condition `n > 0`, segment `f"{a} -> {b}"`, aucune `evidence`, aucun
seuil dans `rule.thresholds` (dict vide, verifie dans le catalogue),
severite UNIQUE lue depuis `rule.severity` ('a_surveiller'). Choisie en
priorite parmi les huit regles sans `correlation_rule` (les cinq
restantes -- `qos_dscp_remarking`, `fragmentation_new`, `saturation`,
`bufferbloat`, `pmtud_blackhole` -- fusionnent chacune DEUX signaux
distincts, forme differente de tout evaluateur deja ecrit, voir
CLAUDE.md/« Prochaine feature ») parce qu'elle s'est reveleee, une fois
lue, de la forme la plus simple deja rencontree par ce pilote --
aucune brique nouvelle necessaire. `test_regle_connue_sans_evaluateur_
leve_not_implemented_error` continue d'utiliser `saturation` (role
inchange depuis la Session 63, `vlan_change` n'etant pas ce role) ;
`test_available_rule_ids_ne_contient_que_les_regles_pilotees` etendu au
nouvel id. Detail complet : `docs/sessions/session-64.md`.

Portee de la Session 65 : extension du pilote a UNE regle
supplementaire (trente au total, sur 41) -- `arp_ip_conflict`, DEUXIEME
regle AUDITEE parmi les douze restees jamais couvertes apres la Session
64. Survolee (pas auditee) en meme temps que `vlan_change` a la Session
64 : son entree catalogue (`expert_rules.py`) porte une `evidence` ET un
seuil (`thresholds={"min_distinct_macs": 2.0}`), signe qu'elle n'etait
PAS de la forme la plus simple -- confirme par la lecture bloc par bloc
de cette session. Verifiee dans `synthesis.py` (bloc `-- conflit
d'adresse IP (ARP) --`), `netcross_core/models.py` ET
`netcross_core/analysis.py::_analyse_arp_ip_conflict` avant redaction :
`report.arp_ip_conflict` (`dict[str, int]` PAR POINT, confirme dans
`models.py`, PAS par paire -- ARP n'est jamais relaye par un routeur,
une comparaison amont/aval n'aurait pas de sens pour ce protocole,
justification explicite du catalogue) reproduit EXACTEMENT la forme
deja pilotee par `tls_cert_invalid_dates` (Session 61) : condition
`n <= 0: continue` (comme `loss_per_segment`, pas `if n > 0:` comme la
plupart des compteurs par point vus depuis), `Finding.evidence` a TROIS
arguments via `_evidence()` (`arp_ip_conflict_examples` +
`arp_ip_conflict_frames`, les deux confirmes presents cote `Report`),
severite UNIQUE lue depuis `rule.severity` ('anomalie', verifie dans le
catalogue). Point notable : le seuil `rule.thresholds
["min_distinct_macs"]` (2.0) N'EST PAS consomme par ce bloc -- verifie
qu'il documente un seuil DEJA applique en amont, cote
`analysis.py::_analyse_arp_ip_conflict` (`len(macs) < 2`, sur les MAC
distinctes vues avant meme la construction de `Report.arp_ip_conflict`),
pas une comparaison que le bloc source de `synthesis.py` refait lui-meme
-- contrairement a `loss_per_segment` (Session 55), seule autre regle a
seuil pilotee a ce jour, dont le bloc source LIT bien
`rule.thresholds["anomalie_rate_pct"]`. Premiere fois que ce pilote
rencontre un seuil catalogue non consomme par son propre evaluateur :
documente explicitement dans la docstring de fonction plutot que
silencieusement ignore. `test_regle_connue_sans_evaluateur_leve_
not_implemented_error` continue d'utiliser `saturation` (role inchange
depuis la Session 63, `arp_ip_conflict` n'etant pas ce role) ;
`test_available_rule_ids_ne_contient_que_les_regles_pilotees` etendu au
nouvel id. Detail complet : `docs/sessions/session-65.md`.

Portee de la Session 66 : extension du pilote a UNE regle
supplementaire (trente et une au total, sur 41) -- `stp_instability`,
candidat le MIEUX CONNU des six regles jamais auditees identifiees par
la Session 63 (survolee Sessions 64-65 en meme temps que
`vlan_change`/`arp_ip_conflict` : son entree catalogue porte deux
`Report.<champ>` distincts dans `required_metrics`, signe deja repere
d'une fusion a deux compteurs -- voir CLAUDE.md, « Prochaine feature »).
Verifiee bloc par bloc dans `synthesis.py` (bloc `-- instabilite STP
(Session 25) --`), `netcross_core/models.py` ET `expert_rules.py` avant
redaction, confirmant l'intuition : QUATRIEME regle de ce pilote a
fusionner DEUX compteurs `Report` DISTINCTS sous un seul `rule_id`
(apres `tcp_options_stripped`, Session 59, `icmp_fragmentation_needed`,
Session 60, et `dhcp_issues`, Session 63) --

- `report.stp_topology_change` : `dict[str, int]` PAR POINT, condition
  `n <= 0: continue` (comme `arp_ip_conflict`, Session 65), AUCUNE
  `evidence` -- forme deja pilotee par `icmp_fragmentation_needed` ;
- `report.stp_root_change` : `dict[str, int]` egalement PAR POINT, meme
  condition `n <= 0: continue`, mais avec `evidence` a TROIS arguments
  via `_evidence()` (`stp_root_change_examples` + `stp_root_change_frames`,
  les deux confirmes presents cote `Report`) -- forme deja pilotee par
  `arp_ip_conflict`.

Nuance par rapport a `dhcp_issues` (verifiee dans `models.py` avant
redaction, pas supposee identique par ressemblance) : `dhcp_issues`
fusionnait deux compteurs de GRANULARITES differentes (par point SANS
evidence, par paire AVEC evidence) -- ici les deux compteurs STP
partagent la MEME granularite (par point) et la MEME condition de
garde ; seule la presence d'`evidence` differe entre les deux boucles.
Une seule `Rule` du catalogue couvre les deux compteurs (verifie dans
`expert_rules.py` -- pas de seconde entree de severite differente),
meme `rule_id` et meme severite UNIQUE lue depuis `rule.severity`
('anomalie') sur les DEUX boucles, aucun seuil dans `rule.thresholds`
(dict vide, egalement verifie dans le catalogue). `tests/
test_rule_engine.py` : nouveaux tests par compteur source separement
(meme discipline que `dhcp_issues`), plus les tests d'`evidence` et
d'equivalence habituels ; `test_regle_connue_sans_evaluateur_leve_not_
implemented_error` continue d'utiliser `saturation` (role inchange) ;
`test_available_rule_ids_ne_contient_que_les_regles_pilotees` etendu au
nouvel id. Detail complet : `docs/sessions/session-66.md`.

Portee de la Session 68 : extension du pilote a `dns_slow_resolution` et
`http_slow_response` (**trente-quatre regles au total, sur 41**), le
lot groupe identifie comme extension (a) la moins couteuse par CLAUDE.md/
"Prochaine feature" depuis la Session 67 -- PREMIERE forme entierement
NOUVELLE pour ce pilote : les 32 regles precedentes lisent toutes un
`dict` `Report.<compteur>` (PAR POINT ou PAR PAIRE), ces deux-la lisent
une LISTE BRUTE (`Report.dns_duration_ms`/`Report.http_response_time_ms`,
`list[float]`) et calculent une moyenne (`statistics.mean()`) comparee a
`rule.thresholds["mean_duration_ms_min"]` -- un seul `Finding` possible
par `Report`, segment fixe `"global"`, aucune iteration sur
`report.points` ni sur un dict, forme confirmee IDENTIQUE entre les deux
regles par l'audit de la Session 67 (meme garde `if report.<liste>:`,
meme comparaison stricte `avg > seuil`, meme `sample_size=len(<liste>)`,
seule differences : le seuil chiffre -- 200.0 vs 500.0 -- et le domaine,
`DNS` vs `HTTP`, tous deux lus depuis la `Rule` plutot que recopies en
dur). `import statistics` remonte en tete de module (import top-level,
`ruff`/`isort` compatible) plutot que l'import local a la fonction du
bloc procedural source -- seule difference deliberee, ne change pas le
comportement. `tests/test_rule_engine.py` : 5 nouveaux tests par regle
(declenche au-dessus du seuil/silencieux au ou sous le seuil/liste
vide/`sample_size`/equivalence), 10 au total pour ce lot -- premieres
regles de ce pilote a NE PAS porter d'`evidence` (segment `"global"`
sans point ni paire associes, aucun champ `*_examples`/`*_frames` de ce
type dans `Report` pour ces deux compteurs, verifie dans `models.py`),
plus mise a jour de `test_available_rule_ids_ne_contient_que_les_regles_
pilotees` (etendue aux deux nouveaux ids ; `test_regle_connue_sans_
evaluateur_leve_not_implemented_error` reste sur `saturation`, role
inchange depuis la Session 63, ni `dns_slow_resolution` ni
`http_slow_response` n'etant ce role). Sept regles restent sans
evaluateur : les CINQ a `correlation_rule` non `None` (`qos_dscp_
remarking`, `fragmentation_new`, `saturation`, `bufferbloat`,
`pmtud_blackhole`, toujours jamais auditees) et DEUX des quatre regles
sans correlation auditees par la Session 67 (`rtp_quality_mos`, forme
nouvelle a source liste de dicts et double seuil ; `server_processing_
dominant`, plus proche des cinq a correlation). Detail complet :
`docs/sessions/session-68.md`.

Portee de la Session 69 : audit bloc par bloc des CINQ regles a
`correlation_rule` non `None`, jamais auditees jusqu'ici -- extension
(a) la moins couteuse par CLAUDE.md/"Prochaine feature" depuis la
Session 67 (`qos_dscp_remarking`, `fragmentation_new`, `saturation`,
`bufferbloat`, `pmtud_blackhole`). Verifie cette fois dans
`synthesis.py`, `netcross_core/models.py` ET `netcross_core/
analysis.py` avant redaction (pas seulement les deux premiers comme les
audits precedents -- necessaire pour trancher, regle par regle, si son
ou ses seuils catalogue sont reellement consommes au point de
construction du `Finding` ou deja entierement appliques en amont).
Contrairement a l'audit symetrique de la Session 67 (quatre des cinq
regles sans correlation exigeaient une forme nouvelle, une seule
directement reproductible), les CINQ se revelent ici directement
reproductibles a partir de briques deja en place (**trente-neuf regles
au total, sur 41** -- `_EVALUATORS` passe de trente-quatre a
trente-neuf entrees) :

- `qos_dscp_remarking` et `pmtud_blackhole` reproduisent une forme deja
  pilotee (compteur par paire + severite UNIQUE lue depuis
  `rule.severity` ; `pmtud_blackhole` avec `evidence` a trois
  arguments, forme de `nat_fw_silent_drop`/`arp_ip_conflict`) ;
- `bufferbloat` est la forme la PLUS SIMPLE rencontree par ce pilote a
  ce jour : ses trois seuils catalogue sont deja entierement appliques
  en amont (`_analyse_bufferbloat()`), donc AUCUNE garde dans la
  boucle -- chaque entree du dict produit un `Finding`, sans
  exception ;
- `fragmentation_new` et `saturation` partagent le schema a DEUX
  severites deja introduit par `loss_per_segment` (Session 55), mais
  sont les PREMIERES regles de ce pilote a produire deux MESSAGES
  distincts (pas seulement une severite variable) selon la branche :
  `fragmentation_new` pilote reellement son seuil catalogue
  (`correlated_encap_change_min_count`, comme `loss_per_segment`),
  tandis que `saturation` decide sa branche par comparaison de
  SOUS-CHAINE sur un verdict deja entierement redige en amont par
  `_analyse_saturation()` (ses cinq seuils catalogue n'y sont donc pas
  consommes) -- premiere fois que ce pilote lit un `dict` dont la
  valeur est une chaine plutot qu'un entier, une liste ou un tuple.

A l'issue de cette session, les CINQ regles a `correlation_rule` non
`None` sont TOUTES couvertes. Il ne reste plus que DEUX regles sans
evaluateur, toutes deux deja auditees par la Session 67 et confirmees
de forme entierement nouvelle : `rtp_quality_mos` (source
`r.rtp_streams`, liste de dicts, deux seuils, severite calculee
dynamiquement) et `server_processing_dominant` (correle deux moyennes
avec un ratio ET un seuil absolu). `tests/test_rule_engine.py` :
nouveaux tests par regle (declenche/absent/nul/equivalence, les DEUX
branches de severite pour `fragmentation_new`/`saturation`, un test
dedie a l'`evidence` de `pmtud_blackhole`) ; mise a jour de
`test_available_rule_ids_ne_contient_que_les_regles_pilotees` (etendue
aux cinq nouveaux ids) ; le role de "regle connue sans evaluateur"
(`test_regle_connue_sans_evaluateur_leve_not_implemented_error`) passe
de `saturation` (desormais pilotee) a `rtp_quality_mos`, `saturation`
n'etant plus disponible pour ce role. Correction mineure, sans rapport
avec le pilote lui-meme, relevee en verifiant `correlation_rule` avant
redaction : la docstring de la dataclass `Rule` (`expert_rules.py`)
affirmait a tort que "quatre regles seulement" portent cette valeur non
`None` -- toujours cinq depuis la Session 47 (PMTUD black hole), deja
verifie par `test_catalogue_cinq_regles_seulement_ont_une_correlation`
(`tests/test_expert_rules.py`) ; corrigee en "cinq". Detail complet :
`docs/sessions/session-69.md`.

Portee de cette session (70, job1) : extension du pilote a UNE regle
supplementaire (quarante au total, sur 41) -- `rtp_quality_mos`,
premiere des deux regles restantes apres la Session 69. Source
`report.rtp_streams` (`list[dict]`), forme entierement nouvelle
confirmee par l'audit de la Session 67 : PREMIERE regle de ce pilote a
lire une LISTE DE DICTS (pas un `dict` de compteurs ni une `list[float]`),
PREMIERE regle ou le segment est derive d'une etiquette de flux (retrait
du suffixe SSRC du champ `label` du dict, ni un point ni une paire), et
PREMIERE regle ou la severite est calculee par comparaison a DEUX seuils
sur une valeur NUMERIQUE continue (le MOS, pas un taux/compteur). Seuils
lus depuis `rule.thresholds` (meme discipline que `loss_per_segment`).
`tests/test_rule_engine.py` : le role de « regle connue sans evaluateur »
(`test_regle_connue_sans_evaluateur_leve_not_implemented_error`) passe de
`rtp_quality_mos` (desormais pilotee) a `server_processing_dominant`,
seule regle restant sans evaluateur ; nouveaux tests (declenche anomalie,
declenche a_surveiller, MOS acceptable pas de finding, mos=None ignore,
liste vide, equivalence avec `build_findings()`).

Portee de cette session (70, job2) : extension du pilote a UNE regle
supplementaire (quarante au total, sur 41) -- `server_processing_dominant`,
derniere regle du catalogue sans evaluateur apres la Session 69. Forme
entierement nouvelle confirmee par l'audit de la Session 67 : PREMIERE
regle de ce pilote a CORRELER DEUX champs de `Report` independants
(`server_think_time` `dict[str, list[float]]` et `latency`
`dict[tuple[str, str], list[float]]`) par comparaison de leurs MOYENNES
avec un RATIO (`avg_server > 3 * avg_net`) ET un SEUIL ABSOLU
(`avg_server > 20`). Segment fixe `"global"` (comme
`dns_slow_resolution`/`http_slow_response`). Seuils lus depuis
`rule.thresholds` (`ratio_serveur_reseau` 3.0, `seuil_serveur_ms` 20.0).
`tests/test_rule_engine.py` : nouveaux tests (declenche, ratio insuffisant,
seuil absolu non atteint, server_think_time vide, latence absente, un
seul point, equivalence avec `build_findings()`) ; mise a jour de
`test_available_rule_ids_ne_contient_que_les_regles_pilotees` (etendue
au nouvel id) ; le role de « regle connue sans evaluateur »
(`test_regle_connue_sans_evaluateur_leve_not_implemented_error`) ne peut
plus etre tenu par `server_processing_dominant` (desormais pilotee) --
les 41 regles du catalogue ont TOUTES un evaluateur enregistre.
"""

from __future__ import annotations

import statistics

from netcross_core.expert_model import EvidenceLink, PacketEvidence
from netcross_core.expert_rules import Rule, get_rule
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Report
from netcross_report.synthesis import Finding

logger = get_logger(__name__)


def _pct(n: int, d: int) -> float:
    """Copie volontaire de `synthesis._pct` (fonction PRIVEE de ce module
    -- jamais importee telle quelle a travers une frontiere de module,
    meme au sein du meme paquet `netcross_report`) : un seul calcul
    trivial (n/d*100), pas une logique de detection dupliquee au sens ou
    la docstring de module met en garde ailleurs dans ce projet."""
    logger.debug("_pct: retour n / d * 100.0 if d else 0.0")
    return (n / d * 100.0) if d else 0.0


def _evidence(point: str, texts, frames: list[int | None] | None = None) -> list[EvidenceLink]:
    """Copie volontaire de `synthesis._evidence` (fonction PRIVEE, meme
    discipline que `_pct` ci-dessus -- jamais importee telle quelle a
    travers une frontiere de module). Necessaire a partir de cette
    session pour `dns_timeout`/`dns_missing` (voir docstring de module) :
    ces deux regles sont les deux premieres piloees par ce moteur dont le
    bloc procedural source construit un `Finding.evidence` non vide,
    contrairement aux cinq regles precedentes (Session 55/56, toutes sans
    kwarg `evidence`). Corps identique a l'original (verifie ligne a
    ligne) : aucune logique de detection, seulement la construction de la
    liste d'`EvidenceLink`/`PacketEvidence` a partir de listes deja
    collectees dans `Report`."""
    if not frames:
        logger.debug("_evidence: si not frames -> retour liste")
        return [EvidenceLink(point, t) for t in texts]
    links = []
    for t, fn in zip(texts, frames):
        packet = PacketEvidence(point, fn) if fn is not None else None
        links.append(EvidenceLink(point, t, packet=packet))
    logger.debug("_evidence: retour links={}", summarize(links, "links"))
    return links


def _http_error_evidence(
    examples: list[str], status_class: int, frames: list[int | None] | None = None
) -> tuple[list[str], list[int | None]]:
    """Copie volontaire de `synthesis._http_error_evidence` (fonction
    PRIVEE, meme discipline que `_pct`/`_evidence` ci-dessus -- jamais
    importee telle quelle a travers une frontiere de module). Necessaire
    a partir de cette session pour `http_client_error`/`http_server_error`
    (voir docstring de module) : `Report.http_error_examples` melange
    volontairement 4xx et 5xx a la collecte (un seul champ, voir
    `analysis.py::_analyse_http`), la distinction se fait donc ici, sur
    le suffixe "-> NNN" de chaque exemple -- DEUXIEME fonction privee
    copiee par ce pilote (apres `_evidence`), jamais fait jusqu'ici.
    Corps identique a l'original (verifie ligne a ligne) : aucune
    logique de detection nouvelle, seulement le filtrage par classe de
    statut d'une liste deja collectee dans `Report`."""
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


def _evaluate_loss_per_segment(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- pertes --` de
    `synthesis.py::build_findings()` (meme seuil, meme message, meme
    `sample_size`), mais en lisant le seuil de severite depuis
    `rule.thresholds["anomalie_rate_pct"]` (5.0 aujourd'hui) plutot que
    la constante `5` codee en dur cote procedural -- seule difference
    volontaire : la regle declarative PILOTE desormais ce seuil."""
    anomalie_rate_pct = rule.thresholds["anomalie_rate_pct"]
    findings: list[Finding] = []
    for p in report.points:
        n = report.loss_count.get(p, 0)
        if n <= 0:
            continue
        raw_base = report.seen_count.get(p, 0)
        rate = _pct(n, raw_base or 1)
        sev = "anomalie" if rate >= anomalie_rate_pct else "a_surveiller"
        findings.append(
            Finding(
                sev,
                rule.domain,
                p,
                f"{n} paquets manquants a ce point ({rate:.1f}% des flux vus)",
                sample_size=raw_base,
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_loss_per_segment: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_zero_window(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- TCP avance --` (fenetres a zero)
    de `synthesis.py::build_findings()` -- meme iteration DIRECTE de
    `report.zero_window.items()` (pas `report.points`, a la difference
    de `_evaluate_loss_per_segment` ci-dessus : le bloc procedural
    source de `loss_per_segment` itere `r.points` explicitement, celui
    de `tcp_zero_window` itere le dict directement). Aucun seuil dans
    `rule.thresholds` pour cette regle (dict vide, verifie dans le
    catalogue) : severite UNIQUE, lue depuis `rule.severity` plutot que
    recopiee en dur -- egalite avec la constante procedurale
    ("a_surveiller") verifiee par le test d'equivalence, pas seulement
    supposee."""
    findings: list[Finding] = []
    for p, n in report.zero_window.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} paquets avec fenetre TCP=0 (recepteur/equipement sature)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_zero_window: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_dns_nxdomain(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc DNS NXDOMAIN de
    `synthesis.py::build_findings()` -- meme iteration directe de
    `report.dns_nxdomain_count.items()`, meme discipline que
    `_evaluate_tcp_zero_window` ci-dessus (severite UNIQUE lue depuis
    `rule.severity`, "info" ici)."""
    findings: list[Finding] = []
    for p, n in report.dns_nxdomain_count.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} reponse(s) NXDOMAIN (domaine inexistant -- pas forcement un probleme reseau)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_dns_nxdomain: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_dns_servfail(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc DNS SERVFAIL de
    `synthesis.py::build_findings()` -- meme iteration directe de
    `report.dns_servfail_count.items()`, meme discipline que
    `_evaluate_tcp_zero_window` ci-dessus (severite UNIQUE lue depuis
    `rule.severity`, "anomalie" ici)."""
    findings: list[Finding] = []
    for p, n in report.dns_servfail_count.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} reponse(s) SERVFAIL (echec de resolution cote serveur/resolveur -- "
                    f"souvent pris a tort pour un probleme reseau)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_dns_servfail: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_hop_delta_outliers(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- TTL / topologie --` (delta de
    sauts hors norme) de `synthesis.py::build_findings()` -- seule des
    quatre regles de ce lot clee par une PAIRE de points adjacents
    (`(a, b)`, `report.hop_delta_outliers.items()`) plutot qu'un point
    seul, segment forme `f"{a} -> {b}"` comme le bloc source. Le mode
    statistique nomme par `Rule.preconditions` (delta de TTL le plus
    frequent observe sur la paire) est deja precalcule en amont
    (`netcross_core.analysis`, directement dans
    `Report.hop_delta_outliers`) : cet evaluateur ne fait QUE lire ce
    compteur deja calcule, meme discipline que les trois autres
    evaluateurs de ce lot (severite UNIQUE lue depuis `rule.severity`,
    "a_surveiller" ici)."""
    findings: list[Finding] = []
    for (a, b), n in report.hop_delta_outliers.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    f"{a} -> {b}",
                    f"{n} flux avec un nombre de sauts different du chemin majoritaire (ECMP/re-routage)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_hop_delta_outliers: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_dns_timeout(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- requetes DNS sans reponse --` de
    `synthesis.py::build_findings()` -- premiere regle pilotee par ce
    moteur dont le compteur source (`Report.dns_timeout`) porte des
    LISTES (`dict[str, list[str]]`) et non des entiers : `if timeouts`
    (troncation de liste), pas `if n > 0`, et `len(timeouts)` dans le
    message plutot que le compteur directement. Le bloc source construit
    aussi un `Finding.evidence` non vide via `_evidence()` (copie locale
    ci-dessus), a la difference des quatre regles pilotees Session 56 :
    `frames` provient de `report.dns_timeout_frames.get(p, [])`, meme
    liste parallele que cote procedural. Severite UNIQUE lue depuis
    `rule.severity` ('anomalie'), meme discipline que les autres regles
    sans seuil de ce pilote."""
    findings: list[Finding] = []
    for p, timeouts in report.dns_timeout.items():
        if timeouts:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{len(timeouts)} requete(s) DNS sans aucune reponse observee dans la "
                    f"capture (timeout applicatif ou serveur/resolveur injoignable)",
                    evidence=_evidence(p, timeouts, report.dns_timeout_frames.get(p, [])),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_dns_timeout: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_dns_missing(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- messages DNS perdus entre deux
    points --` de `synthesis.py::build_findings()` -- comme
    `hop_delta_outliers` (Session 56), clee par une PAIRE de points
    adjacents (`(a, b)`, `report.dns_missing.items()`), segment forme
    `f"{a} -> {b}"` comme le bloc source. Comme `dns_timeout` ci-dessus :
    compteur source en LISTE (`dict[tuple[str, str], list[str]]`),
    `if missing`/`len(missing)` plutot qu'un entier compare a 0, et
    `Finding.evidence` non vide via `_evidence()` -- mais SANS `frames`
    ici (le bloc procedural source appelle `_evidence(seg, missing)` a
    deux arguments seulement, pas de liste `dns_missing_frames` dans
    `Report` : verifie dans `models.py`, absence volontaire du cote
    source, pas un oubli de ce pilote). Severite UNIQUE lue depuis
    `rule.severity` ('a_surveiller')."""
    findings: list[Finding] = []
    for (a, b), missing in report.dns_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    seg,
                    f"{len(missing)} message(s) DNS manquant(s) sur ce segment",
                    evidence=_evidence(seg, missing),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_dns_missing: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_retransmission_rto(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc RTO du meme `-- TCP avance --` de
    `synthesis.py::build_findings()` -- meme forme que
    `_evaluate_tcp_zero_window` (Session 56) : iteration directe de
    `report.retrans_rto.items()`, severite UNIQUE lue depuis
    `rule.severity` ('a_surveiller'), aucune `evidence`."""
    findings: list[Finding] = []
    for p, n in report.retrans_rto.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} retransmission(s) par expiration de minuteur (RTO) -- recuperation "
                    f"lente, aucun ACK duplique recent n'a declenche de renvoi rapide",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_retransmission_rto: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_retransmission_spurious(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc spurious du meme `-- TCP avance --` --
    meme forme que `_evaluate_tcp_retransmission_rto` ci-dessus,
    iteration directe de `report.retrans_spurious.items()`, severite
    UNIQUE 'a_surveiller'."""
    findings: list[Finding] = []
    for p, n in report.retrans_spurious.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} retransmission(s) inutile(s) (donnee deja acquittee) -- minuteur de "
                    f"retransmission probablement mal calibre par rapport au RTT reel, ou "
                    f"chemin de retour ACK asymetrique",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_retransmission_spurious: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_retransmission_fast(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc fast retransmission du meme
    `-- TCP avance --` -- iteration directe de `report.retrans_fast.items()`,
    severite UNIQUE 'info' (seule severite 'info' de ce lot de six,
    verifie dans le catalogue avant redaction)."""
    findings: list[Finding] = []
    for p, n in report.retrans_fast.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} retransmission(s) rapide(s) (reaction a 3 ACK dupliques) -- "
                    f"recuperation normale d'une perte isolee",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_retransmission_fast: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_rst_localized(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc RST du meme `-- TCP avance --` --
    iteration directe de `report.rst_localized.items()`, severite UNIQUE
    'anomalie'."""
    findings: list[Finding] = []
    for p, n in report.rst_localized.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} RST vus a ce seul point -> injection locale probable (firewall/IPS)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_rst_localized: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_syn_no_synack(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc SYN sans SYN-ACK du meme
    `-- TCP avance --` -- iteration directe de
    `report.syn_no_synack.items()`, severite UNIQUE 'anomalie'."""
    findings: list[Finding] = []
    for p, n in report.syn_no_synack.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} connexions SYN sans aucune reponse SYN-ACK -> bloquees (ACL/service down)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_syn_no_synack: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_syn_reply_missing(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc SYN-ACK qui n'atteint pas un point
    precis, dernier du meme `-- TCP avance --` -- iteration directe de
    `report.syn_reply_missing.items()`, severite UNIQUE 'anomalie'."""
    findings: list[Finding] = []
    for p, n in report.syn_reply_missing.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} SYN dont la reponse SYN-ACK ne remonte pas jusqu'a ce point",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_syn_reply_missing: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_options_stripped(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT les DEUX blocs sources de
    `synthesis.py::build_findings()` qui partagent ce `rule_id` --
    premiere regle de ce pilote a fusionner deux compteurs `Report`
    DISTINCTS (`report.wscale_stripped`, `report.sack_stripped`) sous
    un seul `rule_id` catalogue (`tcp_options_stripped`), exactement
    comme cote procedural (memes deux boucles consecutives, meme
    `rule_id=\"tcp_options_stripped\"` sur les deux `Finding`). Chaque
    boucle reste par PAIRE de points adjacents (`(a, b)`, comme
    `dns_missing`), segment forme `f\"{a} -> {b}\"`, `if n > 0` (compteurs
    entiers, pas des listes -- contrairement a `dns_missing`), aucune
    `evidence`. Severite UNIQUE lue depuis `rule.severity`
    ('a_surveiller') pour les DEUX boucles -- une seule `Rule` dans le
    catalogue couvre les deux compteurs, verifie dans `expert_rules.py`
    (pas de seconde entree `tcp_options_stripped` avec une severite
    differente)."""
    findings: list[Finding] = []
    for (a, b), n in report.wscale_stripped.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    f"{a} -> {b}",
                    f"option Window Scale retiree pour {n} handshake(s) entre ces deux "
                    f"points -- desactive le window scaling pour la connexion entiere, "
                    f"plafonne la fenetre TCP effective a 65535 octets (limite de debit "
                    f"classique sur un lien a fort produit debit x latence)",
                    rule_id=rule.id,
                )
            )
    for (a, b), n in report.sack_stripped.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    f"{a} -> {b}",
                    f"option SACK Permitted retiree pour {n} handshake(s) entre ces deux "
                    f"points -- recuperation de perte moins efficace en cas de "
                    f"retransmission (renvoi de fenetre entiere plutot que des seuls "
                    f"segments manquants)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_options_stripped: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tcp_mss_clamped(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- MSS clamped --` de
    `synthesis.py::build_findings()`, dernier candidat nomme
    explicitement par CLAUDE.md/'Prochaine feature' depuis la Session
    58, aux cotes de `tcp_options_stripped` ci-dessus (meme fonction
    source `analysis.py::_analyse_tcp_options()`, meme paire de points
    adjacents `report.mss_clamped.items()`, `(a, b)` -> `dict[str, int]`
    contrairement a `report.wscale_stripped`/`sack_stripped` qui sont
    des `dict[tuple[str, str], int]` -- verifie dans `models.py`).
    Contrairement a `tcp_options_stripped`, construit une `evidence`
    non vide via `_evidence()` (copie locale ci-dessus, meme discipline
    que `dns_timeout`/`dns_missing` -- Session 57) : `examples` depuis
    `report.mss_clamped_examples.get((a, b), [])`, `frames` depuis
    `report.mss_clamped_frames.get((a, b), [])`, meme liste parallele
    que cote procedural. Severite UNIQUE lue depuis `rule.severity`
    ('info')."""
    findings: list[Finding] = []
    for (a, b), n in report.mss_clamped.items():
        if n > 0:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    seg,
                    f"MSS reduit pour {n} handshake(s) entre ces deux points -- un "
                    f"equipement intermediaire adapte la taille de segment (souvent pour "
                    f"compenser un tunnel/VPN, protege generalement contre un noir PMTUD)",
                    evidence=_evidence(
                        seg, report.mss_clamped_examples.get((a, b), []), report.mss_clamped_frames.get((a, b), [])
                    ),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tcp_mss_clamped: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_nat_fw_silent_drop(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- timeout d'inactivite / coupure
    NAT-FW silencieuse --` de `synthesis.py::build_findings()`, PREMIERE
    des cinq regles sans `correlation_rule` restant jamais auditees
    (Session 63) a recevoir un evaluateur, choisie en priorite car
    verifiee, une fois lue bloc par bloc, de forme DIRECTEMENT
    reproductible avec les briques deja en place -- exactement celle
    deja pilotee par `tcp_mss_clamped` (Session 59) : `report.
    idle_timeout_dropped` est un `dict[tuple[str, str], int]` PAR PAIRE
    de points adjacents (verifie dans `models.py`), condition `n <= 0:
    continue` (forme inverse de `if n > 0:` mais logiquement
    equivalente, comme `loss_per_segment`/`arp_ip_conflict`), `evidence`
    a TROIS arguments via `_evidence()` (`idle_timeout_examples` +
    `idle_timeout_frames`, meme paire de champs paralleles que
    `mss_clamped_examples`/`mss_clamped_frames`), severite UNIQUE lue
    depuis `rule.severity` ('anomalie'). Point notable, comme
    `arp_ip_conflict` (Session 65) : le seuil `rule.thresholds[
    'idle_timeout_seconds']` (60.0) declare au catalogue n'est PAS
    consomme par ce bloc -- il documente un seuil deja applique en
    amont, cote `analysis.py::_analyse_idle_timeout` (parametre
    `idle_timeout_seconds`, jamais relu ici), pas une comparaison que
    cet evaluateur referait lui-meme."""
    findings: list[Finding] = []
    for (a, b), n in report.idle_timeout_dropped.items():
        if n <= 0:
            continue
        seg = f"{a} -> {b}"
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                seg,
                f"{n} flux TCP deja etabli(s) entre {a} et {b} ne reprennent jamais en {b} "
                f"apres un long silence en {a} -> coupure NAT/pare-feu silencieuse probable "
                f"(table d'etat expiree pendant l'inactivite, aucun RST observe)",
                evidence=_evidence(
                    seg,
                    report.idle_timeout_examples.get((a, b), []),
                    report.idle_timeout_frames.get((a, b), []),
                ),
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_nat_fw_silent_drop: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_ttl_variation(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- TTL / topologie --` (TTL variable
    au meme point) de `synthesis.py::build_findings()` -- meme iteration
    DIRECTE de `report.ttl_unstable.items()` (`dict[str, int]` PAR
    POINT, confirme dans `models.py`), meme forme que
    `_evaluate_tcp_zero_window` (Session 56) : aucune `evidence`, aucun
    seuil dans `rule.thresholds` (dict vide, verifie dans le catalogue),
    severite UNIQUE lue depuis `rule.severity` ('a_surveiller')."""
    findings: list[Finding] = []
    for p, n in report.ttl_unstable.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} flux avec TTL variable au meme point (routage asymetrique possible)",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_ttl_variation: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_pcp_change(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- QoS --` (priorite 802.1p
    modifiee) de `synthesis.py::build_findings()` -- cle par PAIRE de
    points adjacents (`(a, b)`, `report.pcp_change.items()`,
    `dict[tuple[str, str], int]` confirme dans `models.py`), segment
    forme `f"{a} -> {b}"` comme `_evaluate_hop_delta_outliers` (Session
    56). Aucune `evidence`, aucun seuil dans `rule.thresholds` (dict
    vide, verifie dans le catalogue), severite UNIQUE lue depuis
    `rule.severity` ('a_surveiller')."""
    findings: list[Finding] = []
    for (a, b), n in report.pcp_change.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    f"{a} -> {b}",
                    f"{n} flux avec priorite 802.1p (PCP) modifiee",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_pcp_change: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_icmp_fragmentation_needed(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT les DEUX blocs sources de
    `synthesis.py::build_findings()` qui partagent ce `rule_id` --
    DEUXIEME regle de ce pilote (apres `tcp_options_stripped`, Session
    59) a fusionner DEUX compteurs `Report` DISTINCTS
    (`report.icmp_frag_needed` pour IPv4, `report.icmpv6_too_big` pour
    IPv6, tous deux `dict[str, int]` PAR POINT -- confirme dans
    `models.py`) sous un seul `rule_id` catalogue, mais plus simple que
    `tcp_options_stripped` : par POINT (pas par paire), aucune
    `evidence`. Une seule `Rule` du catalogue couvre les deux compteurs
    (verifie dans `expert_rules.py` -- pas de seconde entree avec une
    severite differente), meme `rule_id` et meme severite UNIQUE lue
    depuis `rule.severity` ('info') sur les DEUX boucles."""
    findings: list[Finding] = []
    for p, n in report.icmp_frag_needed.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} messages ICMP Fragmentation Needed observes",
                    rule_id=rule.id,
                )
            )
    for p, n in report.icmpv6_too_big.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} messages ICMPv6 Packet Too Big observes",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_icmp_fragmentation_needed: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tls_cert_invalid_dates(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le premier bloc `-- certificat TLS (Session
    26) --` de `synthesis.py::build_findings()` -- PREMIER des SIX
    candidats confirmes de forme directement reproductible nommes par
    CLAUDE.md/'Prochaine feature' depuis la Session 60. PAR POINT
    (`report.tls_cert_invalid_dates`, `dict[str, int]`, confirme dans
    `models.py`), meme forme que `_evaluate_tcp_mss_clamped` (compteur
    entier + `evidence` via `_evidence()` a trois arguments -- `examples`
    depuis `report.tls_cert_invalid_dates_examples.get(p, [])`, `frames`
    depuis `report.tls_cert_invalid_dates_frames.get(p, [])`). Severite
    UNIQUE lue depuis `rule.severity` ('anomalie', verifie dans
    `expert_rules.py`), aucun seuil dans `rule.thresholds` (dict vide,
    verifie dans le catalogue)."""
    findings: list[Finding] = []
    for p, n in report.tls_cert_invalid_dates.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} certificat(s) presente(s) hors de leur fenetre de validite sur ce point "
                    f"(deja expire, ou pas encore valide)",
                    evidence=_evidence(
                        p,
                        report.tls_cert_invalid_dates_examples.get(p, []),
                        report.tls_cert_invalid_dates_frames.get(p, []),
                    ),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tls_cert_invalid_dates: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tls_cert_mismatch(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le second bloc `-- certificat TLS (Session
    26) --` de `synthesis.py::build_findings()` -- DEUXIEME des SIX
    candidats confirmes, aux cotes de `tls_cert_invalid_dates`
    ci-dessus (meme commentaire source, meme section). PAR PAIRE de
    points adjacents (`report.tls_cert_mismatch`, `(a, b)` ->
    `dict[tuple[str, str], int]`, confirme dans `models.py`), segment
    forme `f\"{a} -> {b}\"` comme `_evaluate_tcp_mss_clamped`, `evidence`
    via `_evidence()` a trois arguments (`examples`/`frames` depuis
    `report.tls_cert_mismatch_examples`/`_frames.get((a, b), [])`).
    Severite UNIQUE lue depuis `rule.severity` ('anomalie'), aucun
    seuil dans `rule.thresholds` (dict vide, verifie dans le
    catalogue)."""
    findings: list[Finding] = []
    for (a, b), n in report.tls_cert_mismatch.items():
        if n > 0:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    seg,
                    f"{n} connexion(s) TLS presentent un certificat different entre {a} et {b} "
                    f"-> interception/substitution TLS possible en cours de chemin",
                    evidence=_evidence(
                        seg,
                        report.tls_cert_mismatch_examples.get((a, b), []),
                        report.tls_cert_mismatch_frames.get((a, b), []),
                    ),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tls_cert_mismatch: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tls_handshake_no_reply(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le premier bloc `-- negociations TLS
    incompletes (Session 54) --` de `synthesis.py::build_findings()` --
    TROISIEME des SIX candidats confirmes. PAR POINT
    (`report.tls_handshake_no_reply`, `dict[str, int]`, confirme dans
    `models.py`), meme forme que `tls_cert_invalid_dates` ci-dessus
    (compteur entier + `evidence` via `_evidence()` a trois arguments).
    Severite UNIQUE lue depuis `rule.severity` ('anomalie'), aucun
    seuil dans `rule.thresholds` (dict vide, verifie dans le
    catalogue)."""
    findings: list[Finding] = []
    for p, n in report.tls_handshake_no_reply.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} negociation(s) TLS sans reponse sur ce point (ClientHello envoye, "
                    f"aucun ServerHello jamais observe)",
                    evidence=_evidence(
                        p,
                        report.tls_handshake_no_reply_examples.get(p, []),
                        report.tls_handshake_no_reply_frames.get(p, []),
                    ),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tls_handshake_no_reply: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_tls_handshake_incomplete(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le second bloc `-- negociations TLS
    incompletes (Session 54) --` de `synthesis.py::build_findings()` --
    QUATRIEME des SIX candidats confirmes, aux cotes de
    `tls_handshake_no_reply` ci-dessus (meme section source). PAR POINT
    (`report.tls_handshake_incomplete`, `dict[str, int]`, confirme dans
    `models.py`), meme forme que les trois evaluateurs TLS precedents.
    Severite UNIQUE lue depuis `rule.severity` ('anomalie'), aucun
    seuil dans `rule.thresholds` (dict vide, verifie dans le
    catalogue)."""
    findings: list[Finding] = []
    for p, n in report.tls_handshake_incomplete.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} negociation(s) TLS interrompue(s) sur ce point (ServerHello recu, jamais "
                    f"suivi de donnees applicatives)",
                    evidence=_evidence(
                        p,
                        report.tls_handshake_incomplete_examples.get(p, []),
                        report.tls_handshake_incomplete_frames.get(p, []),
                    ),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_tls_handshake_incomplete: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_http_timeout(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- HTTP --`/`http_timeout` de
    `synthesis.py::build_findings()` -- CINQUIEME des SIX candidats
    confirmes, meme forme que `dns_timeout` (Session 57) : PAR POINT
    (`report.http_timeout`, `dict[str, list[str]]`, confirme dans
    `models.py` -- une LISTE de textes deja formates, pas un entier),
    condition `if timeouts:` (liste non vide, pas `n > 0`), message
    construit avec `len(timeouts)`, `evidence` via `_evidence()` a
    trois arguments (`timeouts` directement comme `texts`, `frames`
    depuis `report.http_timeout_frames.get(p, [])`). Severite UNIQUE
    lue depuis `rule.severity` ('anomalie'), aucun seuil dans
    `rule.thresholds` (dict vide, verifie dans le catalogue)."""
    findings: list[Finding] = []
    for p, timeouts in report.http_timeout.items():
        if timeouts:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{len(timeouts)} requete(s) HTTP sans aucune reponse observee dans la capture",
                    evidence=_evidence(p, timeouts, report.http_timeout_frames.get(p, [])),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_http_timeout: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_http_missing(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- HTTP --`/`http_missing` de
    `synthesis.py::build_findings()` -- SIXIEME et dernier des candidats
    confirmes cette session, meme forme que `dns_missing` (Session 57) :
    PAR PAIRE de points adjacents (`report.http_missing`, `(a, b)` ->
    `dict[tuple[str, str], list[str]]`, confirme dans `models.py`),
    condition `if missing:` (liste non vide), segment forme
    `f\"{a} -> {b}\"`, message construit avec `len(missing)`, `evidence`
    via `_evidence(seg, missing)` a DEUX arguments seulement -- pas de
    troisieme argument `frames` (contrairement a `http_timeout`
    ci-dessus) : `Report` n'expose aucun `http_missing_frames`, verifie
    dans `models.py`, meme absence deja documentee pour `dns_missing`.
    Severite UNIQUE lue depuis `rule.severity` ('a_surveiller' --
    contrairement aux CINQ autres candidats de ce lot, tous
    'anomalie'), aucun seuil dans `rule.thresholds` (dict vide, verifie
    dans le catalogue)."""
    findings: list[Finding] = []
    for (a, b), missing in report.http_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    seg,
                    f"{len(missing)} message(s) HTTP manquant(s) sur ce segment",
                    evidence=_evidence(seg, missing),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_http_missing: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_http_client_error(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- HTTP --`/`http_client_error` de
    `synthesis.py::build_findings()` -- PREMIER des DEUX derniers
    candidats de la Session 62 (`Report.http_client_error_count`,
    `dict[str, int]` PAR POINT, confirme dans `models.py`), condition
    `n > 0` (compteur entier, pas une liste comme `http_timeout`/
    `http_missing`). Difference avec les compteurs entiers deja pilotes
    (`tcp_zero_window` et consorts, Session 56) : `evidence` non vide via
    `_evidence()`, mais les textes/frames passes a `_evidence()` sont
    d'abord FILTRES par `_http_error_evidence()` (copie locale
    ci-dessus) depuis le champ PARTAGE `Report.http_error_examples`
    (melange 4xx/5xx a la collecte, filtre uniquement ici sur le
    suffixe "-> NNN", classe de statut 4). Severite UNIQUE lue depuis
    `rule.severity` ('info' -- meme registre que `dns_nxdomain`, erreur
    cote client pas forcement un probleme reseau), aucun seuil dans
    `rule.thresholds` (dict vide, verifie dans le catalogue)."""
    findings: list[Finding] = []
    for p, n in report.http_client_error_count.items():
        if n > 0:
            texts, frames = _http_error_evidence(
                report.http_error_examples.get(p, []), 4, report.http_error_frames.get(p, [])
            )
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} reponse(s) HTTP 4xx (erreur cote client -- pas forcement un probleme reseau)",
                    evidence=_evidence(p, texts, frames),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_http_client_error: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_http_server_error(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- HTTP --`/`http_server_error` de
    `synthesis.py::build_findings()` -- SECOND et dernier candidat
    confirme de la Session 62 (`Report.http_server_error_count`,
    `dict[str, int]` PAR POINT, confirme dans `models.py`), meme forme
    que `http_client_error` ci-dessus (condition `n > 0`, `evidence` via
    `_evidence()` apres filtrage par `_http_error_evidence()` sur le
    meme champ partage `Report.http_error_examples`, classe de statut 5
    cette fois). Severite UNIQUE lue depuis `rule.severity` ('anomalie'
    -- meme registre que `dns_servfail`, echec cote serveur souvent pris
    a tort pour un probleme reseau), aucun seuil dans `rule.thresholds`
    (dict vide, verifie dans le catalogue). Avec cette regle, le pilote
    couvre desormais les DEUX fonctions privees de `synthesis.py`
    utilisees par le bloc `-- HTTP --` (`_evidence`, `_http_error_evidence`)."""
    findings: list[Finding] = []
    for p, n in report.http_server_error_count.items():
        if n > 0:
            texts, frames = _http_error_evidence(
                report.http_error_examples.get(p, []), 5, report.http_error_frames.get(p, [])
            )
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} reponse(s) HTTP 5xx (echec cote serveur/application -- souvent pris a "
                    f"tort pour un probleme reseau)",
                    evidence=_evidence(p, texts, frames),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_http_server_error: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_dhcp_issues(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- DHCP --` de
    `synthesis.py::build_findings()` -- TROISIEME regle de ce pilote a
    fusionner DEUX compteurs `Report` DISTINCTS sous un seul `rule_id`
    catalogue (apres `tcp_options_stripped`, Session 59, et
    `icmp_fragmentation_needed`, Session 60), mais PREMIERE dont les
    deux compteurs fusionnes n'ont PAS la meme forme entre eux -- c'est
    precisement ce qui l'avait ecartee des lots precedents (voir
    CLAUDE.md/"Prochaine feature" depuis la Session 60) :

    - `report.dhcp_nak_count` : `dict[str, int]` PAR POINT, condition
      `n > 0`, AUCUNE `evidence` -- forme deja pilotee par
      `tcp_zero_window` (Session 56) ;
    - `report.dhcp_missing` : `dict[tuple[str, str], list[str]]` PAR
      PAIRE de points adjacents, condition `if missing:` (liste non
      vide, pas `n > 0`), `len(missing)` dans le message et `evidence`
      non vide via `_evidence(seg, missing)` a DEUX arguments seulement
      -- forme deja pilotee par `dns_missing` (Session 57) ; absence du
      troisieme argument `frames` verifiee dans `models.py` avant
      redaction (aucun champ `dhcp_missing_frames` sur `Report`, absence
      volontaire cote source comme pour `dns_missing`/`http_missing`,
      pas un oubli de ce pilote).

    Les deux formes etant chacune deja pilotee ailleurs, aucune brique
    nouvelle n'est necessaire ici : la seule question ouverte etait de
    conception (un seul evaluateur produisant DEUX formes de `Finding`,
    ou deux entrees `_EVALUATORS` distinctes ?). Tranchee en faveur d'UN
    seul evaluateur, comme `tcp_options_stripped`/
    `icmp_fragmentation_needed` : le catalogue ne porte qu'UNE `Rule`
    `dhcp_issues` (verifie dans `expert_rules.py` -- pas de seconde
    entree avec une severite differente), et `_EVALUATORS` est cle par
    `Rule.id` ; deux entrees exigeraient d'inventer un id absent du
    catalogue, exactement ce que ce pilote s'interdit. Severite UNIQUE
    lue depuis `rule.severity` ('anomalie') pour les DEUX boucles,
    aucun seuil dans `rule.thresholds` (dict vide, egalement verifie
    dans le catalogue)."""
    findings: list[Finding] = []
    for p, n in report.dhcp_nak_count.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} DHCPNAK (demande rejetee par le serveur)",
                    rule_id=rule.id,
                )
            )
    for (a, b), missing in report.dhcp_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    seg,
                    f"{len(missing)} message(s) DHCP manquant(s) sur ce segment (attribution IP a risque)",
                    evidence=_evidence(seg, missing),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_dhcp_issues: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_sip_issues(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- SIP --` de
    `synthesis.py::build_findings()` -- derniere des deux regles a
    compteurs fusionnes HETEROGENES nommees par CLAUDE.md/"Prochaine
    feature" depuis la Session 60, et la seule des 41 a introduire une
    TROISIEME forme de source jamais pilotee jusqu'ici :

    - `report.sip_failed_calls` : `list[str]` (verifie dans
      `models.py`), PAS un `dict` compteur du tout -- une liste de
      messages DEJA FORMATES par `analysis.py::_analyse_sip()`, chaque
      entree produisant directement un `Finding` via une comprehension,
      sur le segment litteral `"global"` (constante du bloc source, pas
      un point du `Report` ni un champ de la `Rule` -- recopiee telle
      quelle, comme le sont les messages). Aucune condition de garde
      n'est necessaire : une liste vide ne produit aucun `Finding` par
      construction, la ou les autres formes exigent `n > 0`/`if missing:`.
      Aucune `evidence` non plus -- choix documente cote procedural (le
      message EST deja la preuve, l'attacher en `evidence` serait un pur
      doublon), reproduit ici plutot que "corrige" : ce pilote reproduit
      le chemin procedural, il ne l'ameliore pas.
    - `report.sip_missing` : `dict[tuple[str, str], list[str]]` PAR
      PAIRE, condition `if missing:`, `evidence` via `_evidence(seg,
      missing)` a deux arguments -- strictement la meme forme que
      `report.dhcp_missing` ci-dessus (aucun champ `sip_missing_frames`
      sur `Report`, verifie dans `models.py`).

    Severite UNIQUE lue depuis `rule.severity` ('anomalie') pour les
    DEUX sites, une seule `Rule` `sip_issues` au catalogue couvrant les
    deux signaux (verifie dans `expert_rules.py`), aucun seuil dans
    `rule.thresholds` (dict vide). Meme choix de conception qu'au-dessus :
    un seul evaluateur, cle par l'unique `Rule.id` du catalogue."""
    findings: list[Finding] = []
    findings.extend(Finding(rule.severity, rule.domain, "global", f, rule_id=rule.id) for f in report.sip_failed_calls)
    for (a, b), missing in report.sip_missing.items():
        if missing:
            seg = f"{a} -> {b}"
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    seg,
                    f"{len(missing)} message(s) de signalisation manquant(s) sur ce segment",
                    evidence=_evidence(seg, missing),
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_sip_issues: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_vlan_change(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- VLAN --` de
    `synthesis.py::build_findings()` -- cle par PAIRE de points
    adjacents (`(a, b)`, `report.vlan_change.items()`,
    `dict[tuple[str, str], int]` confirme dans `models.py`), segment
    forme `f"{a} -> {b}"` comme `_evaluate_hop_delta_outliers` (Session
    56) et `_evaluate_pcp_change` (Session 60). Aucune `evidence`, aucun
    seuil dans `rule.thresholds` (dict vide, verifie dans le catalogue),
    severite UNIQUE lue depuis `rule.severity` ('a_surveiller'). Premiere
    regle PILOTEE parmi les treize jamais auditees identifiees par la
    Session 63 (voir docstring de module, Session 64)."""
    findings: list[Finding] = []
    for (a, b), n in report.vlan_change.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    f"{a} -> {b}",
                    f"{n} flux changent d'ID VLAN entre ces deux points",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_vlan_change: retour findings={}", summarize(findings, "findings"))
    return findings


# Vingt-neuf evaluateurs enregistres a l'issue de cette session
# (vingt-huit apres la Session 63) -- voir docstring de module. Cle :
# `Rule.id`, meme vocabulaire que `Finding.rule_id`.
def _evaluate_arp_ip_conflict(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- conflit d'adresse IP (ARP) --` de
    `synthesis.py::build_findings()` -- PAR POINT (`report.arp_ip_conflict`,
    `dict[str, int]`, confirme dans `models.py`), PAS par paire comme la
    plupart des autres detecteurs de ce module (ARP n'est jamais relaye
    par un routeur, voir `analysis.py::_analyse_arp_ip_conflict`).
    Condition `n <= 0: continue` (meme forme que `loss_per_segment`, pas
    `if n > 0:` comme la plupart des compteurs par point pilotes depuis).
    `Finding.evidence` a TROIS arguments via `_evidence()`
    (`arp_ip_conflict_examples` + `arp_ip_conflict_frames`, les deux
    presents cote `Report`). Severite UNIQUE lue depuis `rule.severity`
    ('anomalie'). Le seuil `rule.thresholds["min_distinct_macs"]` (2.0)
    N'EST PAS consomme ici : il documente un seuil DEJA applique en
    amont, cote `analysis.py::_analyse_arp_ip_conflict` (`len(macs) < 2`,
    sur les MAC distinctes vues avant meme la construction de
    `Report.arp_ip_conflict`) -- pas une comparaison que ce bloc refait
    lui-meme, contrairement a `loss_per_segment` dont le bloc source LIT
    bien `rule.thresholds["anomalie_rate_pct"]`."""
    findings: list[Finding] = []
    for p, n in report.arp_ip_conflict.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                p,
                f"{n} adresse(s) IP revendiquee(s) par plusieurs adresses MAC differentes sur "
                f"ce point -> conflit d'adresse IP probable (deux hotes mal configures, ou "
                f"basculement d'IP flottante VRRP/HA)",
                evidence=_evidence(
                    p,
                    report.arp_ip_conflict_examples.get(p, []),
                    report.arp_ip_conflict_frames.get(p, []),
                ),
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_arp_ip_conflict: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_stp_instability(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT les DEUX blocs sources `-- instabilite STP
    (Session 25) --` de `synthesis.py::build_findings()` -- QUATRIEME
    regle de ce pilote a fusionner DEUX compteurs `Report` DISTINCTS sous
    un seul `rule_id` catalogue (apres `tcp_options_stripped`, Session 59,
    `icmp_fragmentation_needed`, Session 60, et `dhcp_issues`, Session 63).
    Contrairement a `dhcp_issues` (seule fusion precedente a compteurs de
    formes differentes), les deux compteurs STP partagent la MEME
    granularite (par point) et la MEME condition de garde `n <= 0:
    continue` (comme `arp_ip_conflict`, Session 65) -- seule la presence
    d'`evidence` differe entre les deux boucles :

    - `report.stp_topology_change` : `dict[str, int]` PAR POINT, AUCUNE
      `evidence` -- forme deja pilotee par `icmp_fragmentation_needed` ;
    - `report.stp_root_change` : `dict[str, int]` PAR POINT, `evidence` a
      TROIS arguments via `_evidence()` (`stp_root_change_examples` +
      `stp_root_change_frames`, confirmes dans `models.py`) -- forme
      deja pilotee par `arp_ip_conflict`.

    Une seule `Rule` du catalogue couvre les deux compteurs (verifie
    dans `expert_rules.py` -- pas de seconde entree de severite
    differente), meme `rule_id` et meme severite UNIQUE lue depuis
    `rule.severity` ('anomalie') sur les DEUX boucles, aucun seuil dans
    `rule.thresholds` (dict vide, egalement verifie dans le catalogue)."""
    findings: list[Finding] = []
    for p, n in report.stp_topology_change.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                p,
                f"{n} evenement(s) de changement de topologie STP observe(s) sur ce point "
                f"(BPDU TCN ou bit TC actif) -> reseau instable possible (boucle de commutation, "
                f"lien ou port qui flappe)",
                rule_id=rule.id,
            )
        )
    for p, n in report.stp_root_change.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                p,
                f"{n} reelection(s) du pont racine STP observee(s) sur ce point -> reseau instable "
                f"possible (boucle de commutation, lien ou port qui flappe)",
                evidence=_evidence(
                    p,
                    report.stp_root_change_examples.get(p, []),
                    report.stp_root_change_frames.get(p, []),
                ),
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_stp_instability: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_dns_slow_resolution(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `duree moyenne de resolution DNS` de
    `synthesis.py::build_findings()` (section `-- DNS --`) -- PREMIERE
    regle de ce pilote a lire une LISTE brute (`report.dns_duration_ms`,
    `list[float]`) plutot qu'un `dict` PAR POINT ou PAR PAIRE : un seul
    Finding possible par `Report`, segment fixe `\"global\"` (pas
    d'iteration sur `report.points`), agrege sur TOUTE la capture --
    forme absente des 32 regles precedentes de ce pilote, confirmee par
    l'audit de la Session 67 (voir CLAUDE.md, \"Prochaine feature\").
    Seuil lu depuis `rule.thresholds[\"mean_duration_ms_min\"]` (200.0
    aujourd'hui) plutot que la constante `200` codee en dur cote
    procedural -- meme discipline que `loss_per_segment` : c'est la
    piece PILOTEE par le catalogue pour cette regle, severite UNIQUE
    ('a_surveiller', pas de second seuil contrairement a
    `loss_per_segment`) lue depuis `rule.severity`, pas recopiee en
    dur. Garde `if report.dns_duration_ms:` reprise a l'identique (liste
    vide -> pas de division/moyenne tentee, `statistics.mean([])` leve
    `StatisticsError`)."""
    mean_duration_ms_min = rule.thresholds["mean_duration_ms_min"]
    if not report.dns_duration_ms:
        logger.debug("_evaluate_dns_slow_resolution: si not report.dns_duration_ms -> retour liste vide")
        return []
    avg = statistics.mean(report.dns_duration_ms)
    if avg <= mean_duration_ms_min:
        logger.debug("_evaluate_dns_slow_resolution: si avg <= mean_duration_ms_min -> retour liste vide")
        return []
    logger.debug("_evaluate_dns_slow_resolution: retour liste")
    return [
        Finding(
            rule.severity,
            rule.domain,
            "global",
            f"duree moyenne de resolution DNS {avg:.0f}ms (> {mean_duration_ms_min:.0f}ms) -- cause "
            f"frequente de lenteurs percues a tort comme un probleme reseau",
            sample_size=len(report.dns_duration_ms),
            rule_id=rule.id,
        )
    ]


def _evaluate_http_slow_response(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `duree moyenne de reponse HTTP
    elevee` de `synthesis.py::build_findings()` (section `-- HTTP --`)
    -- DEUXIEME regle de ce pilote a lire une liste brute
    (`report.http_response_time_ms`), forme identique a
    `_evaluate_dns_slow_resolution` ci-dessus (meme garde, meme absence
    d'iteration sur `report.points`, meme segment fixe `\"global\"`),
    confirme par l'audit de la Session 67 qui avait identifie les deux
    regles comme partageant `statistics.mean()` sur une liste plate et
    un seuil unique. Seule difference : le seuil
    (`rule.thresholds[\"mean_duration_ms_min\"]`, 500.0 aujourd'hui) et
    le domaine (`HTTP` plutot que `DNS`, lu depuis `rule.domain` comme
    toutes les regles de ce pilote)."""
    mean_duration_ms_min = rule.thresholds["mean_duration_ms_min"]
    if not report.http_response_time_ms:
        logger.debug("_evaluate_http_slow_response: si not report.http_response_time_ms -> retour liste vide")
        return []
    avg = statistics.mean(report.http_response_time_ms)
    if avg <= mean_duration_ms_min:
        logger.debug("_evaluate_http_slow_response: si avg <= mean_duration_ms_min -> retour liste vide")
        return []
    logger.debug("_evaluate_http_slow_response: retour liste")
    return [
        Finding(
            rule.severity,
            rule.domain,
            "global",
            f"duree moyenne de reponse HTTP {avg:.0f}ms (> {mean_duration_ms_min:.0f}ms) -- latence "
            f"applicative perceptible par l'utilisateur",
            sample_size=len(report.http_response_time_ms),
            rule_id=rule.id,
        )
    ]


def _evaluate_qos_dscp_remarking(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le premier bloc `-- QoS --` (remarquage DSCP)
    de `synthesis.py::build_findings()` -- PREMIERE des cinq regles a
    `correlation_rule` non `None` du catalogue (`expert_rules.py`) a
    recevoir un evaluateur, toutes les cinq jamais auditees avant cette
    session (69). Cle par PAIRE de points adjacents (`(a, b)`,
    `report.qos_change.items()`, `dict[tuple[str, str], int]` confirme
    dans `models.py`), condition `n <= 0: continue` -- meme forme de
    garde que `loss_per_segment`/`arp_ip_conflict`. La `correlation_rule`
    du catalogue (delta de TTL entre les deux points -> attribution
    L2/equipement sans saut vs L3/routeur) est deja ENTIEREMENT resolue
    en amont par `analysis.py` (boucle principale : `qos_l2_remark`/
    `qos_l3_remark` incrementes au meme moment que `qos_change`, selon
    le delta de TTL, verifie ligne a ligne) -- cet evaluateur ne fait
    QUE lire les deux compteurs deja calcules (`report.qos_l2_remark`/
    `qos_l3_remark`, memes cles `(a, b)`, memes types
    `dict[tuple[str, str], int]`, confirmes dans `models.py`) pour
    composer le message, exactement comme le bloc source -- aucune
    correlation recalculee ici. Premiere regle de ce pilote dont le
    message lit DEUX compteurs `Report` supplementaires au-dela du
    compteur principal de la boucle, sans que cela change la forme de
    base (compteur par paire + garde + severite UNIQUE, deja pilotee
    par `pcp_change`/`vlan_change`/`hop_delta_outliers`) : simple
    detail de formatage du message, pas une nouvelle brique de logique.
    Aucune `evidence`, aucun seuil dans `rule.thresholds` (dict vide,
    verifie dans le catalogue -- la `correlation_rule` documente une
    attribution, pas un palier numerique), severite UNIQUE lue depuis
    `rule.severity` ('a_surveiller')."""
    findings: list[Finding] = []
    for (a, b), n in report.qos_change.items():
        if n <= 0:
            continue
        l2 = report.qos_l2_remark.get((a, b), 0)
        l3 = report.qos_l3_remark.get((a, b), 0)
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                f"{a} -> {b}",
                f"{n} paquets avec DSCP modifie ({l2} sans saut de routeur -> equipement L2, "
                f"{l3} avec saut -> routeur)",
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_qos_dscp_remarking: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_fragmentation_new(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le premier bloc `-- fragmentation / MTU --`
    de `synthesis.py::build_findings()` -- DEUXIEME des cinq regles a
    `correlation_rule` non `None`, jamais auditee avant cette session.
    Cle par PAIRE de points adjacents (`(a, b)`, `report.frag_new.items()`,
    `dict[tuple[str, str], int]` confirme dans `models.py`), condition
    `n <= 0: continue`. La `correlation_rule` du catalogue (le meme
    datagramme croise avec un changement de pile d'encapsulation sur le
    meme segment) est deja PARTIELLEMENT resolue en amont : verifie dans
    `analysis.py` (boucle fragmentation/MTU) que `report.
    encap_frag_correlated` n'est incremente QUE si le datagramme correle
    a aussi change de pile d'encapsulation, sans aucun filtrage de seuil
    a cet endroit (contrairement a `arp_ip_conflict`/`pmtud_blackhole`,
    ce compteur n'est jamais compare a rien avant d'etre incremente).
    PREMIERE regle de ce pilote dont le bloc source produit DEUX
    MESSAGES DIFFERENTS selon la meme branche que la severite (les
    regles a deux severites deja pilotees, `loss_per_segment` Session
    55, partagent un seul gabarit de message quelle que soit la
    branche) : reproduit ici par un if/else complet sur les DEUX
    `Finding`, pas seulement une variable `sev`. Le seuil
    `rule.thresholds["correlated_encap_change_min_count"]` (1.0) EST
    consomme par ce bloc, comme celui de `loss_per_segment` -- verifie
    dans `analysis.py` que `correlated` n'est jamais filtre en amont (a
    la difference de `arp_ip_conflict`/`pmtud_blackhole` ci-dessous) :
    le test truthy `if correlated:` du bloc procedural EST la
    comparaison au seuil (1.0, sur un entier jamais negatif), remplace
    ici par `correlated >= <seuil>` explicite plutot que recopie en dur
    -- meme discipline que `loss_per_segment` (Session 55), premiere
    fois appliquee a une regle a deux MESSAGES distincts (pas seulement
    deux severites). Severites 'anomalie'/'a_surveiller' recopiees a
    l'identique du bloc source (aucun `rule.severity` unique possible
    ici, exactement comme `loss_per_segment`), aucune `evidence`."""
    findings: list[Finding] = []
    correlated_min = rule.thresholds["correlated_encap_change_min_count"]
    for (a, b), n in report.frag_new.items():
        if n <= 0:
            continue
        correlated = report.encap_frag_correlated.get((a, b), 0)
        if correlated >= correlated_min:
            findings.append(
                Finding(
                    "anomalie",
                    rule.domain,
                    f"{a} -> {b}",
                    f"{n} datagrammes fragmentes, {correlated} coincident avec l'apparition "
                    f"d'un tunnel -> le tunnel reduit le MTU disponible",
                    rule_id=rule.id,
                )
            )
        else:
            findings.append(
                Finding(
                    "a_surveiller",
                    rule.domain,
                    f"{a} -> {b}",
                    f"{n} datagrammes non fragmentes en amont deviennent fragmentes ici",
                    rule_id=rule.id,
                )
            )
    logger.debug("_evaluate_fragmentation_new: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_saturation(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le premier bloc `-- saturation / policing /
    bufferbloat --` (verdict de saturation) de
    `synthesis.py::build_findings()` -- TROISIEME des cinq regles a
    `correlation_rule` non `None`, jamais auditee avant cette session.
    Cle par PAIRE de points adjacents (`(a, b)`,
    `report.saturation_verdict.items()`, `dict[tuple[str, str], str]` --
    PREMIERE fois que ce pilote lit une valeur de dict qui est une
    CHAINE deja entierement REDIGEE, confirme dans `models.py` : pas un
    entier, pas une liste, pas un tuple de flottants comme
    `bufferbloat_hint` ci-dessous). La `correlation_rule` du catalogue
    (buckets de perte croises avec la serie de debit, CINQ seuils
    `rule.thresholds` -- frac_high/rel_stdev/mean_loss_ratio) est
    ENTIEREMENT resolue en amont par
    `analysis.py::_analyse_saturation()` : verifie ligne a ligne que les
    cinq valeurs numeriques (0.7/0.15/0.85/0.6/0.3, memes valeurs que le
    catalogue) y sont deja comparees et absorbees dans le texte du
    `verdict` avant meme d'atteindre `Report.saturation_verdict` --
    aucun des cinq seuils declares au catalogue n'est donc consomme ici,
    meme pattern que `arp_ip_conflict` (Session 65)/`nat_fw_silent_drop`
    (Session 67) (seuil catalogue non consomme par l'evaluateur), mais
    premiere fois avec CINQ seuils a la fois plutot qu'un seul. Garde
    `if "NON correlees" in verdict: continue` -- correspond au cas
    frac_high <= 0.3 (aucune correlation, verdict deja tranche en
    amont) : reproduite ici par une comparaison de SOUS-CHAINE plutot
    qu'un entier/une liste, forme jamais rencontree par ce pilote
    jusqu'ici. Severite ensuite determinee par une SECONDE comparaison
    de sous-chaines ("saturation"/"policing"/"limitation" presents dans
    `verdict` -> 'anomalie', sinon 'a_surveiller') -- memes DEUX
    severites hardcodees que `loss_per_segment`/`fragmentation_new`
    ci-dessus (aucun `rule.severity` unique possible), le message du
    `Finding` etant le `verdict` deja redige lui-meme, repris tel quel
    (pas de nouveau gabarit -- deja le cas cote procedural). Aucune
    `evidence` (aucun champ `*_examples`/`*_frames` associe a
    `saturation_verdict` dans `models.py`)."""
    findings: list[Finding] = []
    for (a, b), verdict in report.saturation_verdict.items():
        if "NON correlees" in verdict:
            continue
        sev = (
            "anomalie"
            if ("saturation" in verdict or "policing" in verdict or "limitation" in verdict)
            else "a_surveiller"
        )
        findings.append(Finding(sev, rule.domain, f"{a} -> {b}", verdict, rule_id=rule.id))
    logger.debug("_evaluate_saturation: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_bufferbloat(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le second bloc `-- saturation / policing /
    bufferbloat --` de `synthesis.py::build_findings()` -- QUATRIEME des
    cinq regles a `correlation_rule` non `None`, jamais auditee avant
    cette session. Cle par PAIRE de points adjacents (`(a, b)`,
    `report.bufferbloat_hint.items()`, `dict[tuple[str, str],
    tuple[float, float]]` confirme dans `models.py` -- PREMIERE fois que
    ce pilote deballe un TUPLE de deux flottants directement dans
    l'en-tete de boucle, `for (a, b), (low_lat, high_lat) in ...`,
    plutot qu'un entier ou une liste). La `correlation_rule` du
    catalogue (latence par bucket croisee avec le debit, TROIS seuils
    `rule.thresholds` -- ratio/delta absolu/buckets communs minimum)
    est ENTIEREMENT resolue en amont par
    `analysis.py::_analyse_bufferbloat()` : verifie que les trois
    seuils (1.5/5.0/4.0, memes valeurs que le catalogue) y filtrent
    deja les paires AVANT toute ecriture dans `Report.bufferbloat_hint`
    -- seules les paires ayant deja franchi les trois seuils y
    figurent, aucun des trois n'est donc consomme ici (meme pattern non
    consomme que `saturation` ci-dessus). Consequence directe, verifiee
    dans le bloc source avant redaction : AUCUNE garde/condition dans
    cette boucle (ni `if n > 0`, ni `if n <= 0: continue`, ni test de
    sous-chaine) -- chaque entree presente dans le dict est deja
    qualifiee par construction, PREMIERE regle de ce pilote a emettre
    un `Finding` pour CHAQUE entree du dict sans aucun filtre local.
    Severite UNIQUE lue depuis `rule.severity` ('a_surveiller'), aucune
    `evidence` (aucun champ `*_examples`/`*_frames` associe a
    `bufferbloat_hint` dans `models.py`)."""
    findings: list[Finding] = []
    for (a, b), (low_lat, high_lat) in report.bufferbloat_hint.items():
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                f"{a} -> {b}",
                f"latence {low_lat:.1f}ms a faible charge vs {high_lat:.1f}ms a forte charge",
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_bufferbloat: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_pmtud_blackhole(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- PMTUD (noir) --` de
    `synthesis.py::build_findings()` -- DERNIERE des cinq regles a
    `correlation_rule` non `None` ; a l'issue de cette regle, les CINQ
    sont couvertes (voir CLAUDE.md, "Prochaine feature"). Cle par PAIRE
    de points adjacents (`(a, b)`, `report.pmtud_blackhole.items()`,
    `dict[tuple[str, str], int]` confirme dans `models.py`), condition
    `n <= 0: continue` -- forme DEJA pilotee par `nat_fw_silent_drop`
    (Session 67)/`arp_ip_conflict` (Session 65) : compteur par paire +
    `evidence` a TROIS arguments via `_evidence()`
    (`pmtud_blackhole_examples`/`pmtud_blackhole_frames`, memes listes
    paralleles, memes types confirmes dans `models.py`). La
    `correlation_rule` du catalogue (retransmissions amont sans reponse
    aval, croisees avec l'ABSENCE de signal ICMP(v6) sur toute la
    capture) ainsi que les DEUX seuils declares (`min_segment_bytes`=
    512.0, `min_upstream_attempts`=2.0) sont ENTIEREMENT resolus en
    amont par `analysis.py::_analyse_pmtud()` -- verifie ligne a
    ligne : `_PMTUD_MIN_SEGMENT_BYTES` (512, meme valeur que
    `min_segment_bytes`) et `len(data_pkts_a) < 2` (meme valeur que
    `min_upstream_attempts`) y filtrent deja avant tout increment de
    `report.pmtud_blackhole` -- aucun des deux seuils n'est donc
    consomme ici, meme pattern non consomme que
    `arp_ip_conflict`/`saturation`/`bufferbloat` ci-dessus. Severite
    UNIQUE lue depuis `rule.severity` ('anomalie')."""
    findings: list[Finding] = []
    for (a, b), n in report.pmtud_blackhole.items():
        if n <= 0:
            continue
        seg = f"{a} -> {b}"
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                seg,
                f"{n} segment(s) TCP retransmis plusieurs fois en {a} sans jamais atteindre "
                f"{b}, aucun signal ICMP(v6) de MTU insuffisant observe en {a} -> noir PMTUD "
                f"probable (RFC 1191 IPv4 / RFC 8201 IPv6), la connexion stagne sans jamais "
                f"reduire la taille de ses segments",
                evidence=_evidence(
                    seg,
                    report.pmtud_blackhole_examples.get((a, b), []),
                    report.pmtud_blackhole_frames.get((a, b), []),
                ),
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_pmtud_blackhole: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_rtp_quality_mos(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- RTP / qualite voix --` de
    `synthesis.py::build_findings()` (lignes ~724-745) -- QUARANTIEME
    evaluateur de ce pilote (40/41), PREMIERE regle a lire une LISTE DE
    DICTS (`report.rtp_streams`, `list[dict]`) plutot qu'un `dict` de
    compteurs ou une `list[float]` : chaque entree est un flux RTP
    individuel decrit par un dict (label, ssrc, r_factor, mos,
    sample_count). Aucune iteration sur `report.points` ni sur un dict
    de compteurs -- forme entierement nouvelle confirmee par l'audit
    de la Session 67.

    DEUX seuils dans `rule.thresholds` (`anomalie_mos_max` 3.0,
    `a_surveiller_mos_max` 3.6) et DEUX severites produites (comme
    `loss_per_segment` Session 55, `fragmentation_new`/`saturation`
    Session 69) -- mais c'est la PREMIERE regle de ce pilote ou la
    severite est calculee par comparaison a DEUX seuils sur une valeur
    NUMERIQUE continue (le MOS), pas un taux ou un compteur : MOS < 3.0
    -> `anomalie`, MOS < 3.6 -> `a_surveiller`, sinon pas de Finding
    (garde `continue` reprise a l'identique). Le bloc procedural source
    compare directement aux constantes 3.0/3.6 ; ici les seuils sont lus
    depuis `rule.thresholds` (meme discipline que `loss_per_segment` : le
    catalogue pilote les seuils, pas de recopie en dur).

    Le segment est derive du `label` du flux (ex: `"10.0.0.1:5004 ->
    10.0.0.2:5006 (SSRC=0x1234ABCD)"`) en retirant le suffixe SSRC --
    PREMIERE regle de ce pilote ou le segment n'est ni un nom de point
    ni une paire de points, mais une etiquette de flux. Aucune
    `evidence` possible : `rtp_streams` est une liste de dicts sans
    champ `*_examples`/`*_frames` associe dans `Report` (verifie dans
    `models.py`), meme absence que `dns_slow_resolution`/`http_slow_response`
    (Session 68) -- `evidence == []` verifie dans le test « declenche ».
    `sample_size` recopie depuis `s.get("sample_count")` (deja annote
    comme score de confiance ailleurs dans le projet, voir
    `synthesis.py`/`triage.py`), meme discipline que le bloc source."""
    anomalie_mos_max = rule.thresholds["anomalie_mos_max"]
    a_surveiller_mos_max = rule.thresholds["a_surveiller_mos_max"]
    findings: list[Finding] = []
    for s in report.rtp_streams:
        if s.get("mos") is None:
            continue
        mos = s["mos"]
        if mos < anomalie_mos_max:
            sev = "anomalie"
        elif mos < a_surveiller_mos_max:
            sev = "a_surveiller"
        else:
            continue
        short_label = s["label"].split(" (SSRC=")[0]
        findings.append(
            Finding(
                sev,
                rule.domain,
                short_label,
                f"MOS estime {mos:.2f} (R-factor {s['r_factor']:.0f})",
                sample_size=s.get("sample_count"),
                rule_id=rule.id,
            )
        )
    logger.debug("_evaluate_rtp_quality_mos: retour findings={}", summarize(findings, "findings"))
    return findings


def _evaluate_server_processing_dominant(rule: Rule, report: Report) -> list[Finding]:
    """Reproduit EXACTEMENT le bloc `-- decomposition reseau / serveur --`
    de `synthesis.py::build_findings()` (lignes ~748-769) -- QUARANTE ET
    UNIEME evaluateur de ce pilote (41/41, DERNIERE regle du catalogue
    encore sans evaluateur). Forme entierement nouvelle confirmee par
    l'audit de la Session 67 : PREMIERE regle de ce pilote a CORRELER
    DEUX champs de `Report` independants (`server_think_time` et
    `latency`), tous deux des `dict[*, list[float]]`, par comparaison
    de leurs MOYENNES avec un RATIO (`avg_server > 3 * avg_net`) ET un
    SEUIL ABSOLU (`avg_server > 20`). Deux gardes successives (`if r.server_think_time:`
    puis `if overall:`) reprises a l'identique du bloc procedural source,
    `import statistics` local au bloc comme dans le source.

    Le segment est fixe `"global"` (comme `dns_slow_resolution`/`http_slow_response`,
    Session 68) : la decomposition est aglegee sur TOUTE la capture, pas par
    point ni par paire. La latence reseau reference le PREMIER et le DERNIER
    point de `report.points` (pas une paire adjacente), verifie dans le
    bloc source. Seuils lus depuis `rule.thresholds` (`ratio_serveur_reseau`
    3.0, `seuil_serveur_ms` 20.0) -- meme discipline que `loss_per_segment` :
    le catalogue pilote les seuils, pas de recopie en dur des constantes 3
    et 20. Severite UNIQUE lue depuis `rule.severity` ('a_surveiller').
    Aucune `evidence` (meme absence que `dns_slow_resolution`/`http_slow_response`).
    `sample_size` = `len(overall)` (nombre de tours requete-reponse mesures),
    meme discipline que le bloc source."""
    if not report.server_think_time:
        logger.debug("_evaluate_server_processing_dominant: si not report.server_think_time -> retour liste vide")
        return []
    overall = [t for turns in report.server_think_time.values() for t in turns]
    if not overall:
        logger.debug("_evaluate_server_processing_dominant: si not overall -> retour liste vide")
        return []
    avg_server = statistics.mean(overall)
    net_pair = (report.points[0], report.points[-1]) if len(report.points) >= 2 else None
    net_lat = report.latency.get(net_pair) if net_pair else None
    if not net_lat:
        logger.debug("_evaluate_server_processing_dominant: si not net_lat -> retour liste vide")
        return []
    avg_net = statistics.mean(net_lat)
    ratio = rule.thresholds["ratio_serveur_reseau"]
    seuil_ms = rule.thresholds["seuil_serveur_ms"]
    if avg_server <= ratio * avg_net or avg_server <= seuil_ms:
        logger.debug(
            "_evaluate_server_processing_dominant: si avg_server <= ratio * avg_net or avg_server <= seuil_ms -> reto…"
        )
        return []
    logger.debug("_evaluate_server_processing_dominant: retour liste")
    return [
        Finding(
            rule.severity,
            rule.domain,
            "global",
            f"temps de traitement serveur moyen {avg_server:.0f}ms >> temps "
            f"reseau {avg_net:.1f}ms -> ralentissement probablement applicatif",
            sample_size=len(overall),
            rule_id=rule.id,
        )
    ]


_EVALUATORS = {
    "loss_per_segment": _evaluate_loss_per_segment,
    "tcp_zero_window": _evaluate_tcp_zero_window,
    "hop_delta_outliers": _evaluate_hop_delta_outliers,
    "dns_nxdomain": _evaluate_dns_nxdomain,
    "dns_servfail": _evaluate_dns_servfail,
    "nat_fw_silent_drop": _evaluate_nat_fw_silent_drop,
    "dns_timeout": _evaluate_dns_timeout,
    "dns_missing": _evaluate_dns_missing,
    "tcp_retransmission_rto": _evaluate_tcp_retransmission_rto,
    "tcp_retransmission_spurious": _evaluate_tcp_retransmission_spurious,
    "tcp_retransmission_fast": _evaluate_tcp_retransmission_fast,
    "tcp_rst_localized": _evaluate_tcp_rst_localized,
    "tcp_syn_no_synack": _evaluate_tcp_syn_no_synack,
    "syn_reply_missing": _evaluate_syn_reply_missing,
    "tcp_options_stripped": _evaluate_tcp_options_stripped,
    "tcp_mss_clamped": _evaluate_tcp_mss_clamped,
    "ttl_variation": _evaluate_ttl_variation,
    "pcp_change": _evaluate_pcp_change,
    "icmp_fragmentation_needed": _evaluate_icmp_fragmentation_needed,
    "tls_cert_invalid_dates": _evaluate_tls_cert_invalid_dates,
    "tls_cert_mismatch": _evaluate_tls_cert_mismatch,
    "tls_handshake_no_reply": _evaluate_tls_handshake_no_reply,
    "tls_handshake_incomplete": _evaluate_tls_handshake_incomplete,
    "http_timeout": _evaluate_http_timeout,
    "http_missing": _evaluate_http_missing,
    "http_client_error": _evaluate_http_client_error,
    "http_server_error": _evaluate_http_server_error,
    "dhcp_issues": _evaluate_dhcp_issues,
    "sip_issues": _evaluate_sip_issues,
    "vlan_change": _evaluate_vlan_change,
    "arp_ip_conflict": _evaluate_arp_ip_conflict,
    "stp_instability": _evaluate_stp_instability,
    "dns_slow_resolution": _evaluate_dns_slow_resolution,
    "http_slow_response": _evaluate_http_slow_response,
    "qos_dscp_remarking": _evaluate_qos_dscp_remarking,
    "fragmentation_new": _evaluate_fragmentation_new,
    "saturation": _evaluate_saturation,
    "bufferbloat": _evaluate_bufferbloat,
    "pmtud_blackhole": _evaluate_pmtud_blackhole,
    "rtp_quality_mos": _evaluate_rtp_quality_mos,
    "server_processing_dominant": _evaluate_server_processing_dominant,
}


def evaluate(rule_id: str, report: Report) -> list[Finding]:
    """Evalue la regle `rule_id` du catalogue (`expert_rules`) contre
    `report` et renvoie les `Finding` produits (liste vide si la regle
    ne se declenche pas sur ce `Report`, jamais `None`).

    Leve `KeyError` si `rule_id` n'existe pas dans le catalogue (voir
    `expert_rules.get_rule`) et `NotImplementedError` s'il existe mais
    n'a pas encore d'evaluateur enregistre ici (2 des 41 regles a ce
    stade -- voir docstring de module) : distinction deliberee entre
    "regle inconnue" (erreur d'appelant) et "regle connue mais pilote
    pas encore etendu jusque-la" (limite documentee -- voir docstring de
    module), plutot qu'une seule exception ambigue pour les deux cas."""
    rule = get_rule(rule_id)
    if rule is None:
        logger.debug("evaluate: regle {!r} inconnue du catalogue, refus", rule_id)
        raise KeyError(f"regle inconnue du catalogue expert_rules : {rule_id!r}")
    evaluator = _EVALUATORS.get(rule_id)
    if evaluator is None:
        logger.debug("evaluate: regle {!r} sans evaluateur enregistre, refus", rule_id)
        raise NotImplementedError(
            f"regle {rule_id!r} presente dans le catalogue mais sans evaluateur "
            "enregistre dans ce pilote (voir _EVALUATORS, netcross_report.rule_engine)"
        )
    findings = evaluator(rule, report)
    # point unique de trace des ~40 evaluateurs _evaluate_* (appeles une fois
    # par regle et par rapport) : regle, resultat, severites produites
    logger.debug(
        "evaluate: regle {!r} -> {} constat(s){}",
        rule_id,
        len(findings),
        f" ({', '.join(sorted({f.severity for f in findings}))})" if findings else "",
    )
    return findings


def available_rule_ids() -> list[str]:
    """Ids des regles du catalogue ayant deja un evaluateur enregistre
    ici -- pour un appelant qui veut savoir ce que ce pilote couvre
    aujourd'hui sans provoquer `NotImplementedError`."""
    logger.debug("available_rule_ids: {} regle(s) avec evaluateur", len(_EVALUATORS))
    return list(_EVALUATORS)


def print_rule_engine(report: Report) -> dict[str, list[Finding]]:
    """Section « MOTEUR DE REGLES DECLARATIF » de ``--rule-engine``, partagee
    par la CLI et la GUI (issue #673) : evalue chaque regle disponible,
    imprime ses Finding et le total ; renvoie les Finding par regle (cle
    ``rule_engine`` du rapport JSON)."""
    findings_by_rule: dict[str, list[Finding]] = {}
    total = 0
    print("\n" + "=" * 70)
    print("MOTEUR DE REGLES DECLARATIF (rule_engine)")
    print("=" * 70)
    rule_ids = available_rule_ids()
    for rule_id in rule_ids:
        rule_findings = evaluate(rule_id, report)
        findings_by_rule[rule_id] = rule_findings
        total += len(rule_findings)
        for f in rule_findings:
            print(f"  [{f.severity}] {f.category} / {f.segment} -- {f.message}")
    print(f"\n{len(rule_ids)} regles evaluees, {total} Finding produits.")
    logger.debug("print_rule_engine: {} Finding", total)
    return findings_by_rule
