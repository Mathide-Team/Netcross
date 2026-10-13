# netcross — CLAUDE.md

Analyse croisée de captures réseau multi-points (`pcap_parser`/`tshark`,
`netcross_core`, `netcross_report`, CLI, export JSON/PDF, GUI GTK4),
développée session par session en comparaison fonctionnalité par
fonctionnalité avec OmniPeek/Wireshark.

Ce fichier est le seul à lire systématiquement en début de session. Pour
le détail des fonctionnalités, de la dette et de la priorisation, voir
@docs/features-backlog.md. Pour le raisonnement détaillé d'une session
passée, voir `docs/sessions/session-NN.md` (une par session) — n'y aller
que pour un contexte spécifique, pas systématiquement.

## État courant

- **Tests** : 4057 collectés au 2026-09-25 (`pytest --collect-only -q`),
  suite complète rejouée à chaque session avant tout nouveau code. Les
  tests sautés dépendent de l'environnement (GTK4, `networkx`, `tshark`,
  modèles IA absents) : relire le résumé `pytest` plutôt qu'un chiffre
  figé ici. Couverture : seuil **bloquant** `fail_under = 80` dans
  `[tool.coverage.report]` de `pyproject.toml`, appliqué par la CI
  (`pytest --cov`, issue #246) ; 82,2 % mesurés sur `dev` le 2026-09-23
  (voir `docs/quality/seuil-couverture.md`). Ce seuil n'existe que sur
  `dev` tant que `dev` n'est pas fusionné dans `main`.
  Outillage qualité : `ruff` (lint + format), `import-linter`, `mypy`
  (configuré dans `pyproject.toml`, job CI « Types », 0 erreur exigée) et
  le diagramme de classes (`scripts/generate_class_diagram.py --check`)
  sont tous bloquants en CI.
- **Job 34 (issue #154)** : fusion de captures PCAP — nouvelle fonction
  `pcap_parser.capture.merge_captures(paths, output_path, dedup=False)`
  (réexportée par `pcap_parser` et `netcross_core`) et flags
  `--merge SORTIE`/`--merge-dedup` de `cross_capture_analyzer_cli.py`.
  Simple enveloppe des outils livrés avec tshark, sans décodage :
  `mergecap` (intercale par timestamp) puis `reordercap` (garantit
  l'ordre global même si une entrée n'était pas ordonnée), et `editcap
  -w 0` seulement si `dedup=True` — fenêtre de temps NULLE, donc seuls
  les paquets de contenu ET de timestamp identiques sont supprimés : une
  retransmission (même contenu, autre instant) et une même trame vue par
  deux horloges (points de capture distincts) sont conservées, ce qui est
  voulu pour l'analyse multi-points. Sortie `.pcap` si le nom finit par
  `.pcap`, pcapng sinon ; écriture atomique (intermédiaires dans un
  répertoire temporaire du dossier de sortie puis `os.replace` — en cas
  d'échec la sortie préexistante est intacte). `--merge` fusionne tous
  les chemins des `--capture` (les `NOM=` sont ignorés) puis s'arrête
  SANS analyser : combiné à une option d'analyse/de rapport (`--pdf-report`,
  `--triage`, `--live`...) il est refusé plutôt que de l'ignorer en
  silence. Distinct de la Session 27 (`NOM=chemin1,chemin2`), qui
  concatène à la lecture sans produire de fichier fusionné.
  `tests/test_merge_captures.py` : 35 tests (unitaires avec outils
  simulés + intégration avec les vrais `mergecap`/`reordercap`/`editcap`,
  sautés s'ils sont absents). `ruff check`/`ruff format --check`/
  `lint-imports` verts ; `mypy` inchangé sur les fichiers de ce Job.
  **Échecs sans lien avec ce Job, constatés sur `main`** :
  `tests/test_live_diff.py::test_evaluate_diff_*` (`monkeypatch.setattr`
  sur `"netcross_core.correlate.correlate"`, que la ré-exportation de la
  fonction `correlate` masque) ; `tests/test_class_diagram.py` (3 tests,
  `docs/class-diagram.md` absent alors que le test de fraîcheur l'exige) ;
  et `uv run pytest` nu échoue à la collecte de `tests/test_application.py`
  (`from tests.conftest import ...`) — `uv run python -m pytest` fonctionne.
  Note : `src/cross_capture_analyzer_cli.py` est passé de `100755` à
  `100644` lors du push par l'API (contenu identique) —
  `git update-index --chmod=+x` pour le rétablir.
- **Session 71** : nettoyage mypy complet (issue #28) — les 49 erreurs
  préexistantes sur 9 fichiers sont TOUTES résolues :
  `PYTHONPATH=src uv run mypy --ignore-missing-imports src/` renvoie
  désormais `Success: no issues found in 36 source files`. Corrections
  par fichier : `analysis.py` (10 — annotations de type sur les
  `defaultdict` imbriqués + import `Pkt`/`Any`), `tls_diagnostics.py`
  (18 — refactoring des appels `TlsEvent(**base)` en arguments
  nommés explicites + `sport or 0`), `triage.py` (9 — import `Finding`
  et typage des `list[Finding]` au lieu de `list[object]`),
  `quic_diagnostics.py` (4 — `sport or 0`), `packet.py` (2 —
  `src or ""`), `history.py` (2 — `points: list[str] | dict[...]`),
  `__init__.py` (2 — `type: ignore` sur repli `reportlab`),
  `ek_source.py` (1 — `assert interface is not None`),
  `parsing.py` (1 — `type: ignore[call-overload]` sur libération
  mémoire). Aucun changement de comportement — corrections de types
  uniquement. `pytest` 1138/1138 inchangé, `ruff`/`lint-imports`
  verts. Détail complet : `docs/sessions/session-71.md`.
- **Session 70** : première briquette du chantier « Alarmes et
  surveillance de seuils » (§6.16, issue #26) — nouveau module
  `src/netcross_core/alarms.py` : `AlarmEngine` consommant des
  `AlarmSignal` (tuples `rule_id`/`segment`/`severity`/`value`
  convertibles depuis un `Finding` par l'appelant, côté
  `netcross_report`/CLI — le contrat de couches interdit à
  `netcross_core` d'importer `Finding`), avec fenêtre glissante
  paramétrable, hystérésis `trigger_threshold`/`clear_threshold`,
  durée minimale de persistance, ratio minimal d'échantillons
  positifs dans la fenêtre, et accumulation d'`AlarmEvent`
  (`raised`/`cleared`) sans livraison externe (callback à brancher par
  l'appelant sur `engine.events`). Critère d'acceptation de l'issue :
  un signal ponctuel isolé au milieu d'une fenêtre calme ne lève
  JAMAIS d'alarme (vérifié par `test_signal_isole_ne_leve_pas_alarme`).
  `tests/test_alarms.py` : 12 nouveaux tests (signal isolé/persistance
  continue/non-re-déclenchement/retour à la normale/hystérésis
  numérique/ratio minimal/fenêtre glissante/segment None/signal non
  configuré/value None/active_alarms/re-lever après clear) :
  `pytest` 1138/1138 → **1150/1150** (+12 net). `ruff check .` propre,
  `ruff format --check .` propre. `lint-imports` : contrat de couches
  respecté (`alarms.py` vit dans `netcross_core`, n'importe que
  `dataclasses` stdlib — aucun nouvel import inter-packages).
  `mypy` sur `alarms.py` : 0 erreur imputable (14 erreurs
  préexistantes visibles sur les autres fichiers du sous-graphe,
  reproduites uniquement SANS `PYTHONPATH=src` — inchangées depuis la
  Session 69). Détail complet : `docs/sessions/session-70.md`.
- **Session 69** : suite du chantier ouvert par les Sessions 55-68
  (moteur d'exécution, `netcross_report/rule_engine.py`) : audit bloc
  par bloc, pour la première fois, des CINQ règles du catalogue à
  `correlation_rule` non `None` (`qos_dscp_remarking`,
  `fragmentation_new`, `saturation`, `bufferbloat`, `pmtud_blackhole`),
  vérifié cette fois dans `synthesis.py`, `netcross_core/models.py` ET
  `netcross_core/analysis.py` (nécessaire pour trancher, règle par
  règle, si son ou ses seuils catalogue sont réellement consommés au
  point de construction du `Finding` ou déjà entièrement appliqués en
  amont). Contrairement à l'audit symétrique de la Session 67 (quatre
  candidats sur cinq exigeaient une forme nouvelle), les CINQ se
  révèlent ici directement reproductibles à partir de briques déjà en
  place (**trente-neuf règles au total, sur 41**) : `qos_dscp_remarking`
  et `pmtud_blackhole` reprennent une forme déjà pilotée (compteur par
  paire + sévérité unique ; `pmtud_blackhole` avec `evidence` à trois
  arguments, forme de `nat_fw_silent_drop`/`arp_ip_conflict`) ;
  `bufferbloat` est la forme la PLUS SIMPLE rencontrée par ce pilote à
  ce jour (ses trois seuils catalogue sont déjà entièrement appliqués
  en amont par `_analyse_bufferbloat()`, donc AUCUNE garde dans la
  boucle) ; `fragmentation_new` et `saturation` partagent le schéma à
  DEUX sévérités déjà introduit par `loss_per_segment` (Session 55),
  mais sont les PREMIÈRES règles de ce pilote à produire deux MESSAGES
  distincts selon la branche — `fragmentation_new` pilote réellement
  son seuil catalogue (`correlated_encap_change_min_count`), tandis que
  `saturation` décide sa branche par comparaison de SOUS-CHAÎNE sur un
  verdict déjà entièrement rédigé en amont par `_analyse_saturation()`
  (ses cinq seuils catalogue n'y sont donc pas consommés — première
  fois que ce pilote lit un `dict` dont la valeur est une chaîne
  plutôt qu'un entier, une liste ou un tuple). À l'issue de cette
  session, les CINQ règles à `correlation_rule` non `None` sont TOUTES
  couvertes ; il ne reste plus que DEUX règles sans évaluateur
  (`rtp_quality_mos`, `server_processing_dominant`, toutes deux déjà
  auditées par la Session 67 — voir Prochaine feature). `tests/
  test_rule_engine.py` : 25 nouveaux tests (5 par règle en moyenne,
  adaptés à chaque forme — les deux branches de sévérité pour
  `fragmentation_new`/`saturation`, un test d'`evidence` dédié pour
  `pmtud_blackhole`, pas de test « nul » pour `bufferbloat` faute de
  garde) ; le rôle de « règle connue sans évaluateur »
  (`test_regle_connue_sans_evaluateur_leve_not_implemented_error`)
  passe de `saturation` (désormais pilotée) à `rtp_quality_mos`.
  Correction mineure sans rapport avec le pilote lui-même, relevée en
  vérifiant `correlation_rule` avant rédaction : la docstring de la
  dataclass `Rule` (`expert_rules.py`) affirmait à tort que « quatre
  règles seulement » portent cette valeur non `None` — toujours cinq
  depuis la Session 47 (PMTUD black hole), déjà vérifié par
  `test_catalogue_cinq_regles_seulement_ont_une_correlation`
  (`tests/test_expert_rules.py`) ; corrigée en « cinq ». Détail complet :
  `docs/sessions/session-69.md`.
- **Session 68** : suite du chantier ouvert par les Sessions 55-67
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` à `dns_slow_resolution` et `http_slow_response`
  (**trente-quatre règles au total, sur 41**) — lot groupé, PREMIÈRE
  forme entièrement NOUVELLE pour ce pilote depuis son ouverture
  Session 55 : les 32 évaluateurs précédents lisent tous un `dict`
  `Report.<compteur>` (par point ou par paire), ces deux-là lisent une
  LISTE BRUTE (`Report.dns_duration_ms`/`Report.http_response_time_ms`,
  `list[float]`) et calculent une moyenne (`statistics.mean()`)
  comparée à `rule.thresholds["mean_duration_ms_min"]` (200.0/500.0) —
  au plus UN seul `Finding` par `Report`, segment fixe `"global"`,
  aucune itération sur `report.points` ni sur un dict, aucune
  `evidence` possible (aucun champ `*_examples`/`*_frames` associé,
  vérifié dans `models.py`). Forme confirmée IDENTIQUE entre les deux
  règles par l'audit de la Session 67 (seules différences : le seuil
  chiffré et le domaine, `DNS` vs `HTTP`, tous deux lus depuis la
  `Rule` plutôt que recopiés en dur — même discipline que
  `loss_per_segment`, seule autre règle à seuil pilotée à ce jour).
  `import statistics` remonté en tête de module (top-level) plutôt que
  l'import local à la fonction du bloc procédural source — seule
  différence délibérée. `tests/test_rule_engine.py` : 10 nouveaux tests
  (5 par règle — déclenche/silencieux/liste vide/`sample_size`/
  équivalence ; premières règles de ce pilote sans test d'`evidence`
  dédié, vérifiées `evidence == []` dans le test « déclenche »), plus
  mise à jour de `test_available_rule_ids_ne_contient_que_les_regles_
  pilotees` (étendue aux deux nouveaux ids ; `test_regle_connue_sans_
  evaluateur_leve_not_implemented_error` reste sur `saturation`, rôle
  inchangé depuis la Session 63, ni l'une ni l'autre des deux nouvelles
  règles n'étant ce rôle) : `pytest` 1103/1103 → **1113/1113** (+10
  net). `ruff check .` propre, `ruff format --check .` propre du
  premier coup. `lint-imports` inchangé en fichiers (66), dépendances
  169 → **170** (`import statistics`, seul nouvel import du lot —
  ajout stdlib top-level, aucun nouvel import inter-packages, contrat
  de couches inchangé). `mypy` sur les deux fichiers modifiés : 0
  erreur imputable (27 erreurs préexistantes visibles sur le même
  sous-ensemble de 7 fichiers, reproduites uniquement SANS
  `PYTHONPATH=src`) ; baseline `src/` entier non re-décomptée cette
  session (aucun des neuf fichiers concernés touché), reconfirmée
  inchangée par construction (49 erreurs/9 fichiers). Détail complet :
  `docs/sessions/session-68.md`.
- **Session 67** : suite du chantier ouvert par les Sessions 55-66
  (moteur d'exécution, `netcross_report/rule_engine.py`) : audit bloc
  par bloc des CINQ règles sans corrélation jamais auditées identifiées
  par la Session 63 (`rtp_quality_mos`, `dns_slow_resolution`,
  `nat_fw_silent_drop`, `server_processing_dominant`,
  `http_slow_response`), aucune n'étant a priori mieux connue qu'une
  autre à ce stade. Résultat de l'audit : `rtp_quality_mos` a une
  source `r.rtp_streams` (liste de dicts, pas un compteur `dict`) avec
  DEUX seuils et une sévérité calculée dynamiquement — forme
  entièrement nouvelle ; `dns_slow_resolution`/`http_slow_response`
  partagent une forme nouvelle mais IDENTIQUE entre elles
  (`statistics.mean()` sur une liste plate, seuil unique, segment fixe
  `"global"`) ; `server_processing_dominant` corrèle deux moyennes avec
  un ratio ET un seuil absolu, plus proche des cinq règles à
  `correlation_rule` non `None` que des candidats simples ;
  `nat_fw_silent_drop` (`Report.idle_timeout_dropped`,
  `dict[tuple[str, str], int]` PAR PAIRE, condition `n <= 0: continue`,
  `evidence` à TROIS arguments via `_evidence()`, sévérité UNIQUE)
  reproduit EXACTEMENT la forme déjà pilotée par `tcp_mss_clamped`
  (Session 59) — seule des cinq directement reproductible sans brique
  nouvelle, retenue en conséquence (`_EVALUATORS` passe de trente et
  une à **trente-deux** entrées sur 41). **Point notable, troisième
  occurrence** (après `arp_ip_conflict` Session 65, `stp_instability`
  Session 66) : le seuil `rule.thresholds["idle_timeout_seconds"]`
  (60.0) déclaré au catalogue n'est PAS consommé par ce bloc — il
  documente un seuil déjà appliqué en amont côté
  `analysis.py::_analyse_idle_timeout`, jamais relu par
  `synthesis.py`. `tests/test_rule_engine.py` : 5 nouveaux tests
  (déclenche/absent/nul/evidence/équivalence, même discipline que
  `tcp_mss_clamped`), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation`, rôle inchangé depuis
  la Session 63, `nat_fw_silent_drop` n'étant pas ce rôle) : `pytest`
  1098/1098 → **1103/1103** (+5 net). `ruff check .` propre, `ruff
  format --check .` propre du premier coup. `lint-imports` inchangé en
  fichiers (66) ET en dépendances (169 — aucun nouvel import, cet
  évaluateur ne consomme que `Report.idle_timeout_dropped` et ses deux
  listes d'accompagnement, déjà exposées). `mypy` sur les deux fichiers
  modifiés : 0 erreur imputable (27 erreurs préexistantes visibles sur
  le même sous-ensemble de 7 fichiers, reproduites uniquement SANS
  `PYTHONPATH=src` — même précision que les Sessions 63-66) ; baseline
  `src/` entier non re-décomptée cette session (aucun des neuf fichiers
  concernés touché), reconfirmée inchangée par construction (49
  erreurs/9 fichiers). Détail complet : `docs/sessions/session-67.md`.
- **Session 66** : suite du chantier ouvert par les Sessions 55-65
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` à `stp_instability` (**trente et une règles au total,
  sur 41**), la TROISIÈME des six règles sans corrélation jamais
  auditées à recevoir un évaluateur (après `vlan_change`, Session 64, et
  `arp_ip_conflict`, Session 65) — désignée depuis la Session 64 comme
  le candidat le mieux connu de ce groupe, confirmé par l'audit bloc par
  bloc de cette session. Vérifiée dans `synthesis.py` (bloc `--
  instabilité STP (Session 25) --`), `netcross_core/models.py` ET
  `netcross_core/expert_rules.py` avant rédaction : QUATRIÈME règle de
  ce pilote à fusionner DEUX compteurs `Report` distincts sous un seul
  `rule_id` (après `tcp_options_stripped`, Session 59,
  `icmp_fragmentation_needed`, Session 60, et `dhcp_issues`, Session
  63) — `Report.stp_topology_change` (`dict[str, int]` PAR POINT,
  condition `n <= 0: continue`, AUCUNE `evidence`, forme déjà pilotée
  par `icmp_fragmentation_needed`) et `Report.stp_root_change` (`dict[str,
  int]` également PAR POINT, même condition, mais `evidence` à TROIS
  arguments via `_evidence()`, forme déjà pilotée par
  `arp_ip_conflict`). **Point notable**, différent de `dhcp_issues`
  (seule fusion précédente à compteurs de formes différentes) : ici les
  deux compteurs STP partagent la MÊME granularité (par point) et la
  MÊME condition de garde — seule la présence d'`evidence` diffère entre
  les deux boucles, donc aucune brique nouvelle n'a été nécessaire (les
  deux formes existaient déjà séparément dans ce pilote, contrairement à
  `dhcp_issues` qui avait dû trancher un choix de conception). Une seule
  `Rule` du catalogue couvre les deux compteurs (vérifié dans
  `expert_rules.py` — pas de seconde entrée de sévérité différente),
  même `rule_id` et même sévérité UNIQUE lue depuis `rule.severity`
  (`anomalie`) sur les deux boucles, aucun seuil dans `rule.thresholds`
  (dict vide, également vérifié dans le catalogue). `tests/
  test_rule_engine.py` : 7 nouveaux tests (déclenche par compteur
  séparément/deux findings/absent/nuls/evidence/équivalence, même
  discipline que `dhcp_issues`), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation`, rôle inchangé depuis la
  Session 63, `stp_instability` n'étant pas ce rôle) : `pytest`
  1091/1091 → **1098/1098** (+7 net). `ruff check .` propre, `ruff
  format --check .` propre du premier coup. `lint-imports` inchangé en
  fichiers (66) ET en dépendances (169 — aucun nouvel import, cet
  évaluateur ne consomme que `Report.stp_topology_change`/
  `stp_root_change` et ses deux listes d'accompagnement, déjà
  exposées). `mypy` sur les deux fichiers modifiés : 0 erreur imputable
  (27 erreurs préexistantes visibles sur le même sous-ensemble de 7
  fichiers, reproduites uniquement SANS `PYTHONPATH=src` — même
  précision que les Sessions 63-65) ; baseline `src/` entier
  reconfirmée inchangée (49 erreurs/9 fichiers). Détail complet :
  `docs/sessions/session-66.md`.
- **Session 65** : suite du chantier ouvert par les Sessions 55-64
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` à `arp_ip_conflict` (**trente règles au total, sur
  41**), la DEUXIÈME des douze règles jamais auditées à recevoir un
  évaluateur (après `vlan_change`, Session 64). Cette règle avait été
  survolée (pas auditée complètement) par la Session 64 en même temps
  que `vlan_change` et `stp_instability` : son entrée catalogue
  (`expert_rules.py`) porte une `evidence` et un seuil
  (`min_distinct_macs`), signe d'une forme plus proche de
  `tls_cert_invalid_dates`/`loss_per_segment` que de `vlan_change` —
  confirmé par l'audit bloc par bloc. Vérifiée dans `synthesis.py`
  (bloc `-- conflit d'adresse IP (ARP) --`), `netcross_core/models.py`
  ET `netcross_core/analysis.py::_analyse_arp_ip_conflict` avant
  rédaction : `Report.arp_ip_conflict` (`dict[str, int]` PAR POINT, PAS
  par paire — ARP n'est jamais relayé par un routeur, justification
  explicite du catalogue) reproduit la même forme que
  `tls_cert_invalid_dates` (Session 61) : condition `n <= 0: continue`
  (comme `loss_per_segment`, forme inverse de `if n > 0:` mais
  logiquement équivalente), `evidence` à TROIS arguments via
  `_evidence()` (`arp_ip_conflict_examples` + `arp_ip_conflict_frames`),
  sévérité UNIQUE lue depuis `rule.severity` (`anomalie`). **Point
  notable** : le seuil `rule.thresholds["min_distinct_macs"]` (2.0)
  déclaré au catalogue N'EST PAS consommé par ce bloc — vérifié qu'il
  documente un seuil DÉJÀ appliqué en amont, côté
  `analysis.py::_analyse_arp_ip_conflict` (`len(macs) < 2`, littéral,
  avant même la construction de `Report.arp_ip_conflict`), à la
  différence de `loss_per_segment` (Session 55, seule autre règle à
  seuil pilotée à ce jour) dont le bloc source LIT bien
  `rule.thresholds["anomalie_rate_pct"]` — première fois que ce pilote
  rencontre un seuil catalogue non consommé par son propre évaluateur,
  documenté explicitement dans la docstring de fonction plutôt que
  silencieusement ignoré. `tests/test_rule_engine.py` : 5 nouveaux
  tests (déclenche/absent/nul/evidence/équivalence), plus mise à jour
  de `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation`, rôle inchangé depuis
  la Session 63, `arp_ip_conflict` n'étant pas ce rôle) : `pytest`
  1086/1086 → **1091/1091** (+5 net). `ruff check .` propre, `ruff
  format --check .` propre du premier coup. `lint-imports` inchangé en
  fichiers (66) ET en dépendances (169 — aucun nouvel import, cet
  évaluateur ne consomme que `Report.arp_ip_conflict` et ses deux
  listes d'accompagnement, déjà exposées). `mypy` sur les deux fichiers
  modifiés : 0 erreur imputable (27 erreurs préexistantes visibles sur
  le même sous-ensemble de 7 fichiers, reproduites uniquement SANS
  `PYTHONPATH=src` — même précision que les Sessions 63-64) ; baseline
  `src/` entier reconfirmée inchangée (49 erreurs/9 fichiers). Détail
  complet : `docs/sessions/session-65.md`.
- **Session 64** : suite du chantier ouvert par les Sessions 55-63
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` à `vlan_change` (**vingt-neuf règles au total, sur
  41**), la PREMIÈRE des treize règles jamais auditées identifiées par
  la Session 63 à recevoir un évaluateur (les douze autres, dont les
  cinq à `correlation_rule` non `None`, restent à faire — voir
  « Prochaine feature »). Vérifiée bloc par bloc dans `synthesis.py`
  (bloc `-- VLAN --`) ET `netcross_core/models.py` avant rédaction, pas
  supposée simple malgré l'absence de seuil dans son entrée du
  catalogue (`expert_rules.py`) : `Report.vlan_change`
  (`dict[tuple[str, str], int]` PAR PAIRE de points adjacents) reproduit
  EXACTEMENT la forme déjà pilotée par `hop_delta_outliers` (Session 56)
  et `pcp_change` (Session 60) — condition `n > 0`, segment
  `f"{a} -> {b}"`, aucune `evidence`, aucun seuil dans
  `rule.thresholds` (dict vide, vérifié), sévérité UNIQUE lue depuis
  `rule.severity` (`a_surveiller`). Choisie en priorité parmi les huit
  règles sans `correlation_rule` parce qu'elle s'est révélée, une fois
  lue, de la forme la plus simple déjà rencontrée par ce pilote :
  aucune brique nouvelle n'a été nécessaire (ni fonction privée à
  copier, ni nouvelle forme de compteur). `tests/test_rule_engine.py` :
  3 nouveaux tests (déclenche/silencieux/équivalence), plus mise à jour
  de `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation`, rôle inchangé depuis la
  Session 63, `vlan_change` n'étant pas ce rôle) : `pytest` 1083/1083 →
  **1086/1086** (+3 net). `ruff check .` propre, `ruff format --check .`
  propre du premier coup. `lint-imports` inchangé en fichiers (66) ET en
  dépendances (169 — aucun nouvel import, cet évaluateur ne consomme
  que `Report.vlan_change` déjà exposé). `mypy` sur les deux fichiers
  modifiés : 0 erreur imputable (27 erreurs préexistantes visibles sur
  le même sous-ensemble de 7 fichiers atteint par le graphe d'import de
  `rule_engine.py`, reproduites uniquement SANS `PYTHONPATH=src` — même
  précision que la Session 63) ; baseline `src/` entier reconfirmée
  inchangée (49 erreurs/9 fichiers). Détail complet :
  `docs/sessions/session-64.md`.
- **Session 63** : suite du chantier ouvert par les Sessions 55-62
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` aux DEUX DERNIERS candidats déjà audités bloc par bloc
  (audit Session 60, confirmé inchangé Sessions 61/62) — `dhcp_issues`
  et `sip_issues` (**vingt-huit règles au total, sur 41**). Écartés
  jusque-là parce qu'ils fusionnent sous un même `rule_id` des
  compteurs `Report` de formes DIFFÉRENTES entre eux (contrairement à
  `tcp_options_stripped`/`icmp_fragmentation_needed`, dont les
  compteurs fusionnés partagent la même forme) : leur coût réel était
  un **choix de conception**, pas une brique technique manquante —
  aucune fonction privée supplémentaire n'a eu à être copiée,
  `_evidence()` (Session 57) suffit. Chaque bloc re-vérifié dans
  `synthesis.py`, `netcross_core/models.py` ET `expert_rules.py` avant
  rédaction. `dhcp_issues` fusionne `Report.dhcp_nak_count`
  (`dict[str, int]` PAR POINT, `n > 0`, sans `evidence` — forme de
  `tcp_zero_window`) et `Report.dhcp_missing`
  (`dict[tuple[str, str], list[str]]` PAR PAIRE, `if missing:`,
  `evidence` à DEUX arguments — forme de `dns_missing` ; absence de
  `dhcp_missing_frames` sur `Report` vérifiée, volontaire côté source).
  `sip_issues` reprend cette dernière forme pour `Report.sip_missing`
  et introduit la **TROISIÈME forme de source de tout ce pilote**,
  jamais rencontrée en 26 règles : `Report.sip_failed_calls` est une
  `list[str]` de messages déjà formatés par `analysis.py` — pas un
  `dict` compteur du tout —, un `Finding` par entrée via une
  compréhension, sur le segment littéral `"global"`, sans condition de
  garde (une liste vide ne produit rien par construction) ni `evidence`
  (choix commenté côté procédural : le message EST déjà la preuve —
  reproduit tel quel, ce pilote ne corrige pas le chemin procédural).
  Sévérité UNIQUE lue depuis `rule.severity` (`anomalie` pour les deux,
  sur TOUS leurs sites de construction), aucun seuil dans
  `rule.thresholds` (dict vide, vérifié). **Choix de conception
  tranché** (le seul restant, ouvert depuis la Session 60) : UN seul
  évaluateur par règle produisant les deux formes, `_EVALUATORS` étant
  clé par `Rule.id` et le catalogue ne portant qu'UNE `Rule` par id —
  scinder exigerait d'inventer un `rule_id` absent du catalogue,
  exactement ce que ce pilote s'interdit depuis la Session 55.
  **Découverte non anticipée** : le test d'équivalence de `sip_issues` a
  échoué au premier passage — `build_findings()` TRIE sa liste complète
  avant de la renvoyer (`findings.sort(key=(SEVERITY_ORDER, category,
  segment))`, dernière ligne), alors qu'`evaluate()` renvoie dans
  l'ordre de CONSTRUCTION ; pour les 26 règles précédentes les deux
  ordres coïncidaient par HASARD, ce qu'aucun test n'avait explicité.
  `evaluate()` ne reproduit délibérément PAS ce tri (étape de
  présentation appliquée aux 41 règles à la fois, pas propriété d'une
  règle isolée) : le test d'équivalence compare par CONTENU, un test
  dédié fige la divergence d'ordre, et la comparaison positionnelle
  restée possible pour `dhcp_issues` est annotée comme une coïncidence.
  `tests/test_rule_engine.py` : 15 nouveaux tests (7 + 8, avec tests
  dédiés à CHAQUE compteur source séparément), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees` et de
  `test_regle_connue_sans_evaluateur_leve_not_implemented_error`
  (`dhcp_issues` devenant pilotée, ce rôle passe à `saturation`, l'une
  des cinq règles à `correlation_rule` non `None` — le rôle le plus
  STABLE disponible, ses deux titulaires précédents étant devenus
  pilotés dès la session suivante) : `pytest` 1068/1068 →
  **1083/1083** (+15 net). `ruff check .` propre, `ruff format --check .`
  propre du premier coup sur le code et les tests (seul le journal
  `docs/sessions/session-63.md` a été reformaté — `ruff format` traite
  aussi les blocs Python inclus dans le Markdown, jamais relevé
  jusqu'ici). `lint-imports` inchangé
  en fichiers (66) ET en dépendances (169 — aucun nouvel import).
  `mypy` : 0 erreur imputable ; baseline `src/` reconfirmée inchangée
  (49 erreurs/9 fichiers, même répartition qu'à la Session 50). Avec ce
  lot, **plus aucun candidat audité ne reste en attente** — voir
  « Prochaine feature ». Détail complet : `docs/sessions/session-63.md`.
- **Session 62** : suite du chantier ouvert par les Sessions 55-61
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` aux DEUX derniers candidats déjà confirmés de forme
  directement reproductible depuis la Session 60 — `http_client_error`
  et `http_server_error` (**vingt-six règles au total, sur 41**),
  écartés du lot de la Session 61 car ils nécessitaient de copier une
  DEUXIÈME fonction privée de `synthesis.py` (`_http_error_evidence()`,
  filtrage des exemples par classe de statut HTTP 4xx/5xx), jamais fait
  jusque-là pour ce pilote (une seule fonction privée copiée jusqu'à la
  Session 61, `_evidence()`). Chacune vérifiée bloc par bloc dans
  `synthesis.py` ET `netcross_core/models.py` avant rédaction (pas
  supposée reproductible par ressemblance) : les deux reproduisent la
  forme du bloc `-- HTTP --` — `Report.http_client_error_count`/
  `Report.http_server_error_count`, `dict[str, int]` PAR POINT,
  condition `n > 0` — mais avec un `Finding.evidence` construit à
  partir de textes/frames FILTRÉS par `_http_error_evidence()` (copie
  locale, corps identique à l'original vérifié ligne à ligne) depuis le
  champ PARTAGÉ `Report.http_error_examples`/`Report.http_error_frames`
  (mélange volontaire 4xx/5xx à la collecte côté `analysis.py`,
  distinction faite uniquement au filtrage, sur le suffixe "-> NNN" de
  chaque exemple, classe de statut 4 ou 5 selon la règle). Sévérité
  UNIQUE lue depuis `rule.severity` pour chacune (`info` pour
  `http_client_error`, `anomalie` pour `http_server_error`, vérifié
  dans `expert_rules.py`), aucune des deux ne porte de seuil dans
  `rule.thresholds` (dict vide, également vérifié dans le catalogue).
  `tests/test_rule_engine.py` : 10 nouveaux tests (5 par règle —
  déclenche/silencieux/compteur-nul/evidence-filtrée/équivalence), plus
  mise à jour de `test_available_rule_ids_ne_contient_que_les_regles_
  pilotees` (étendu aux deux nouveaux ids ; `test_regle_connue_sans_
  evaluateur_leve_not_implemented_error` utilisait déjà `dhcp_issues`
  comme exemple de « règle connue mais non pilotée », aucun changement
  nécessaire, ce candidat restant hors de ce lot — voir « Prochaine
  feature ») : `pytest` 1058/1058 → **1068/1068** (+10 net). `ruff
  check .` propre ; `ruff format .` a reformaté `rule_engine.py` (deux
  lignes d'appel à `_http_error_evidence()` dépassant 120 caractères,
  repliées automatiquement — même type de reformatage occasionnel que
  les Sessions 58/59), `ruff format --check .` propre ensuite.
  `lint-imports` inchangé en fichiers (66) ET en dépendances (169 —
  aucun nouvel import, ces deux évaluateurs ne consomment que des
  compteurs `Report` déjà exposés). `mypy` sur les deux fichiers
  modifiés : 0 erreur imputable (27 erreurs préexistantes visibles sur
  le même sous-ensemble de 7 fichiers atteint par le graphe d'import de
  `rule_engine.py` que les sessions précédentes ; `test_rule_engine.py`
  propre) ; baseline `src/` entier reconfirmée inchangée (49
  erreurs/9 fichiers). Avec ce lot, TOUS les candidats de forme
  directement reproductible identifiés depuis la Session 59 sont
  désormais pilotés — voir « Prochaine feature » pour ce qu'il reste
  (`dhcp_issues`/`sip_issues`, formes hétérogènes, et les ~13 règles
  jamais auditées). Détail complet : `docs/sessions/session-62.md`.
- **Session 61** : suite du chantier ouvert par les Sessions 55-60
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` aux SIX candidats confirmés de forme directement
  reproductible nommés explicitement par CLAUDE.md/« Prochaine
  feature » depuis la Session 60 (**vingt-quatre règles au total, sur
  41**) — `tls_cert_invalid_dates`, `tls_handshake_no_reply`,
  `tls_handshake_incomplete` (chacune `Report.<nom>`, `dict[str, int]`
  PAR POINT, vérifié dans `models.py`), `tls_cert_mismatch`
  (`Report.tls_cert_mismatch`, `dict[tuple[str, str], int]` PAR PAIRE),
  `http_timeout` (`Report.http_timeout`, `dict[str, list[str]]` PAR
  POINT — un compteur en LISTE, condition `if timeouts:` et non
  `n > 0`) et `http_missing` (`Report.http_missing`,
  `dict[tuple[str, str], list[str]]` PAR PAIRE, condition `if missing:`).
  Chacune vérifiée bloc par bloc dans `synthesis.py` ET
  `netcross_core/models.py` avant rédaction (pas supposée reproductible
  par ressemblance malgré l'audit déjà fait Session 60) : les quatre
  premières reproduisent exactement la forme déjà pilotée par
  `tcp_mss_clamped` (Session 59, compteur entier + `evidence` à trois
  arguments) ; `http_timeout` reproduit exactement la forme de
  `dns_timeout` (Session 57) ; `http_missing` reproduit celle de
  `dns_missing` (Session 57), y compris l'absence de troisième argument
  `frames` à `_evidence()` (`Report` n'expose pas de
  `http_missing_frames`, vérifié dans `models.py`). Sévérité UNIQUE lue
  depuis `rule.severity` pour chacune : `anomalie` pour les CINQ
  premières (TLS ×4 + `http_timeout`), `a_surveiller` pour
  `http_missing` seule (vérifié dans `expert_rules.py`) ; aucune des
  six ne porte de seuil dans `rule.thresholds` (dict vide, également
  vérifié dans le catalogue). `tests/test_rule_engine.py` : 29 nouveaux
  tests (5 par règle — déclenche/silencieux/nul-ou-liste-vide/evidence/
  équivalence — sauf `http_missing`, 4 tests, sans notion de compteur
  « nul » pour une liste), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees` (étendu
  aux six nouveaux ids ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` utilisait déjà `dhcp_issues` comme exemple de
  « règle connue mais non pilotée », aucun changement nécessaire) :
  `pytest` 1029/1029 → **1058/1058** (+29 net). `ruff check .` propre,
  `ruff format --check .` propre du premier coup. `lint-imports`
  inchangé en fichiers (66) ET en dépendances (169 — aucun nouvel
  import, ces six évaluateurs ne consomment que des compteurs `Report`
  déjà exposés). `mypy` sur les deux fichiers modifiés : 0 erreur
  imputable (27 erreurs préexistantes visibles sur le même sous-ensemble
  de 7 fichiers atteint par le graphe d'import de `rule_engine.py` que
  les sessions précédentes) ; baseline `src/` entier reconfirmée
  inchangée (49 erreurs/9 fichiers). Les QUATRE candidats de forme plus
  éloignée nommés depuis la Session 59 (`dhcp_issues`, `sip_issues`,
  `http_client_error`, `http_server_error`) restent hors de ce lot, voir
  « Prochaine feature ». Détail complet : `docs/sessions/session-61.md`.
- **Session 60** : suite du chantier ouvert par les Sessions 55-59
  (moteur d'exécution, `netcross_report/rule_engine.py`) : extension de
  `_EVALUATORS` à TROIS règles supplémentaires (**dix-huit au total**,
  sur 41) — `ttl_variation`, `pcp_change` et `icmp_fragmentation_needed`,
  trois des TREIZE candidats « de forme simple mais NON vérifiés bloc
  par bloc » nommés explicitement par CLAUDE.md/« Prochaine feature »
  depuis la Session 59 (le bloc `-- TCP avancé --` étant désormais
  épuisé). Chacun vérifié bloc par bloc dans `synthesis.py` ET
  `netcross_core/models.py` avant rédaction (pas supposé simple par
  ressemblance) : `ttl_variation` (`Report.ttl_unstable`,
  `dict[str, int]` PAR POINT) reproduit exactement la forme déjà
  pilotée par `tcp_zero_window` (Session 56) ; `pcp_change`
  (`Report.pcp_change`, `dict[tuple[str, str], int]` PAR PAIRE)
  reproduit exactement la forme déjà pilotée par `hop_delta_outliers`
  (Session 56) — aucune des deux ne porte d'`evidence` ni de seuil dans
  `rule.thresholds` (dict vide, vérifié dans le catalogue), sévérité
  UNIQUE lue depuis `rule.severity` (`a_surveiller` pour les deux).
  `icmp_fragmentation_needed` est la DEUXIÈME règle de ce pilote (après
  `tcp_options_stripped`, Session 59) à fusionner DEUX compteurs
  `Report` DISTINCTS sous un seul `rule_id` catalogue —
  `Report.icmp_frag_needed` (IPv4) et `Report.icmpv6_too_big` (IPv6),
  tous deux `dict[str, int]` PAR POINT (vérifié dans `models.py`) —
  mais plus simple que `tcp_options_stripped` : par point (pas par
  paire), aucune `evidence` ; une seule `Rule` du catalogue couvre les
  deux compteurs (même sévérité `info` pour les deux, vérifié dans
  `expert_rules.py`), donc un seul `rule_id` sur les deux boucles comme
  côté procédural. `tests/test_rule_engine.py` : 11 nouveaux tests (3
  pour `ttl_variation`, 3 pour `pcp_change`, 5 pour
  `icmp_fragmentation_needed` — dont deux tests dédiés à chacun des
  deux compteurs sources séparément, même discipline que
  `tcp_options_stripped`, Session 59), plus mise à jour de deux tests
  préexistants : `test_regle_connue_sans_evaluateur_leve_not_implemented_error`
  utilisait `ttl_variation` comme exemple de « règle connue mais non
  pilotée » — remplacé par `dhcp_issues` (voir « Prochaine feature ») ;
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees` étendu
  aux trois nouveaux ids : `pytest` 1018/1018 → **1029/1029** (+11
  net). `ruff check .` propre, `ruff format --check .` propre du
  premier coup (aucun reformatage nécessaire, contrairement aux
  Sessions 58/59). `lint-imports` inchangé en fichiers (66) ET en
  dépendances (169 — aucun nouvel import, ces trois évaluateurs ne
  consomment que des compteurs `Report` déjà exposés). `mypy` sur les
  deux fichiers modifiés : 0 erreur imputable (27 erreurs préexistantes
  visibles sur le sous-ensemble de 7 fichiers atteint par le graphe
  d'import de `rule_engine.py`, même sous-ensemble que la Session 57) ;
  les 49 erreurs préexistantes (Session 50) hors périmètre reconfirmées
  inchangées sur l'intégralité de `src/` (toujours 49/9). Les DIX
  autres candidats nommés depuis la Session 59 sont désormais tous
  audités (bloc par bloc, cette session) : quatre confirmés de forme
  DIFFÉRENTE (voir « Prochaine feature » pour le détail — `dhcp_issues`/
  `sip_issues` fusionnent des compteurs de formes hétérogènes entre eux,
  `http_client_error`/`http_server_error` nécessitent de copier une
  deuxième fonction privée de `synthesis.py`) et six confirmés de forme
  DIRECTEMENT reproductible avec les briques déjà en place
  (`tls_cert_invalid_dates`, `tls_cert_mismatch`, `tls_handshake_no_reply`,
  `tls_handshake_incomplete`, `http_timeout`, `http_missing`) — candidats
  naturels pour la session suivante. Détail complet :
  `docs/sessions/session-60.md`.
- **Session 59** : « uv/poetry » et « corriger toutes les erreurs
  ruff » redemandées explicitement — re-vérifiées, aucun changement :
  `grep -ril poetry .` (hors caches) ne remonte que des commentaires
  historiques documentant l'absence de `poetry` (`requirements.txt`,
  `pyproject.toml`, `CLAUDE.md`, `docs/`) — jamais une trace réelle ;
  `ruff check .` → `All checks passed!`, `ruff format --check .` → 0
  erreur avant tout nouveau code (état inchangé depuis la Session 50).
  Vérification complémentaire cette session (jamais faite avant) :
  `ruff check --select ALL --statistics .` remonte 6495 signalements
  sur ~63 règles hors du `select` configuré (`pyproject.toml`
  `[tool.ruff.lint]` : `E,W,F,I,B,C4,UP,SIM,N,PERF,RUF,TID`) —
  docstrings manquantes (`D1xx`), en-tête de copyright (`CPY001`),
  complexité cyclomatique (`C901`), accès à des membres privés
  (`SLF001`), etc. : préférences stylistiques d'un ruleset bien plus
  large (`ALL`), jamais choisies par ce projet et hors de son
  `select` documenté (voir commentaire `pyproject.toml` sur
  `TID`/`RUF100`) — pas des « erreurs ruff » au sens de la
  configuration du projet, donc rien à corriger ici ; les activer
  serait un changement de politique de lint, pas une correction, hors
  périmètre d'une consigne « corriger toutes les erreurs ruff »
  (implicitement : sous la configuration existante du projet).
  Suite du chantier ouvert par les Sessions 55-58 (moteur d'exécution,
  `netcross_report/rule_engine.py`) : extension de `_EVALUATORS` aux
  DEUX derniers candidats du bloc source `-- TCP avance --` nommés
  explicitement depuis la Session 58 — `tcp_options_stripped` (fusionne
  DEUX compteurs `Report` distincts, `wscale_stripped`/`sack_stripped`,
  sous un seul `rule_id` catalogue, première fois pour ce pilote — même
  sévérité `a_surveiller` pour les deux, vérifié dans `expert_rules.py`)
  et `tcp_mss_clamped` (clé par paire de points comme
  `tcp_options_stripped`, mais `Finding.evidence` non vide via
  `_evidence()` — comme `dns_timeout`/`dns_missing`, Session 57 —,
  sévérité `info`). **QUINZE règles pilotées sur 41** désormais.
  `tests/test_rule_engine.py` : 10 nouveaux tests (5 par règle —
  `tcp_options_stripped` avec en plus deux tests dédiés à chaque
  compteur source séparément, jamais fait jusqu'ici pour une règle à
  deux boucles sources), plus correction de deux tests préexistants
  cassés par ce lot (`tcp_options_stripped` servait d'exemple de règle
  « connue mais non pilotée » — remplacé par `ttl_variation` ; liste
  `available_rule_ids` étendue) : `pytest` 1008/1008 → **1018/1018**
  (+10 net). `ruff check .` propre ; `ruff format --check .` a signalé
  une ligne vide surnuméraire dans `tests/test_rule_engine.py`,
  corrigée par `ruff format .` (1018/1018 rejoué après reformatage).
  `lint-imports` inchangé (66 fichiers, 169 dépendances). `mypy` sur
  les deux fichiers modifiés : 0 erreur imputable ; baseline `src/`
  reconfirmée inchangée (49/9). Détail complet :
  `docs/sessions/session-59.md`.
- **Session 58** : suite du chantier ouvert par les Sessions 55-57
  (moteur d'exécution, `netcross_report/rule_engine.py`) — extension de
  `_EVALUATORS` à SIX règles supplémentaires (**treize au total**, sur
  41), toutes issues du même bloc source `-- TCP avance --` de
  `synthesis.py::build_findings()` déjà entamé par `tcp_zero_window`
  (Session 56) : `tcp_retransmission_rto`, `tcp_retransmission_spurious`
  (`Report.retrans_rto`/`retrans_spurious`, sévérité `a_surveiller` les
  deux), `tcp_retransmission_fast` (`Report.retrans_fast`, sévérité
  `info` — seule sévérité `info` de ce lot), `tcp_rst_localized`
  (`Report.rst_localized`, `anomalie`), `tcp_syn_no_synack`
  (`Report.syn_no_synack`, `anomalie`), `syn_reply_missing`
  (`Report.syn_reply_missing`, `anomalie`). Forme identique aux sept
  règles déjà pilotées : compteur `dict[str, int]` sur `Report`,
  itération directe (pas `report.points`), sévérité UNIQUE lue depuis
  `rule.severity` (aucune des six ne porte de seuil dans
  `rule.thresholds` — dict vide, vérifié avant rédaction), aucune
  `evidence` — contrairement à `dns_timeout`/`dns_missing` (Session
  57), aucun besoin de `_evidence()` pour ce lot. Vérifié bloc par bloc
  dans `synthesis.py` avant rédaction (pas supposé uniforme malgré la
  ressemblance visuelle), même discipline que les lots précédents.
  Deux dernières règles du même bloc source explicitement écartées
  pour forme différente : `tcp_options_stripped` (deux compteurs
  distincts fusionnés sous un seul `rule_id`) et `tcp_mss_clamped`
  (`evidence` non vide, clé par paire de points) — voir « Prochaine
  feature ». `tests/test_rule_engine.py` : 18 nouveaux tests (3 par
  règle — déclenche/silencieux/équivalence avec `build_findings()`,
  filtrée par `rule_id` : la catégorie « TCP » porte désormais NEUF
  `rule_id` distincts dans ce pilote), plus correction de deux tests
  préexistants cassés par ce lot (`tcp_rst_localized` servait
  d'exemple de règle « connue mais non pilotée » — remplacé par
  `tcp_options_stripped` ; liste `available_rule_ids` étendue) :
  `pytest` 989/989 → **1008/1008** (+19 net). `ruff check .` propre ;
  `ruff format --check .` a signalé une ligne vide surnuméraire dans
  `tests/test_rule_engine.py`, corrigée par `ruff format .` (1008/1008
  rejoué après reformatage). `lint-imports` inchangé en fichiers (66)
  ET en dépendances (169 — aucun nouvel import cette fois, contrairement
  à la Session 57 : ces six évaluateurs n'ont pas besoin
  d'`EvidenceLink`/`PacketEvidence`). `mypy` sur les deux fichiers
  modifiés : 0 erreur imputable ; les 49 erreurs préexistantes (Session
  50) hors périmètre reconfirmées inchangées sur l'intégralité de
  `src/` (toujours 49/9). Détail complet : `docs/sessions/session-58.md`.
- **Session 57** : « remplacer poetry par uv » et « corriger toutes les
  erreurs ruff » redemandées explicitement — vérifiées, pas
  ré-effectuées : aucune trace de `poetry` dans le projet (toujours vrai
  depuis la Session 55, qui avait déjà fait la migration réelle
  pip+requirements.txt → uv — voir son paragraphe ci-dessous) ;
  `uv run ruff check .`/`uv run ruff format --check .` toujours propres
  (`ruff==0.16.4`, version épinglée inchangée). Suite du chantier ouvert
  par les Sessions 55/56 (`netcross_report/rule_engine.py`) : les DEUX
  candidats nommés explicitement par la Session 56 comme « premiers
  candidats naturels si ce chantier continue » — `dns_timeout` et
  `dns_missing` (`_EVALUATORS` passe de cinq à **sept** entrées sur 41).
  Forme différente du lot précédent, comme annoncé Session 56 :
  `Report.dns_timeout`/`dns_missing` portent des LISTES
  (`dict[str, list[str]]`/`dict[tuple[str, str], list[str]]`), pas des
  entiers — `if timeouts`/`if missing` (troncation de liste),
  `len(...)` dans le message plutôt qu'un compteur direct — et leur
  bloc source dans `synthesis.py::build_findings()` construit un
  `Finding.evidence` non vide via `_evidence()` (fonction PRIVÉE de
  `synthesis.py`), jamais fait jusqu'ici par ce pilote (les sept règles
  précédentes — Sessions 55/56 — n'utilisaient aucune le kwarg
  `evidence`). `_evidence()` copiée localement dans `rule_engine.py`,
  même discipline déjà appliquée à `_pct` depuis la Session 55 (jamais
  importée telle quelle à travers une frontière de module, corps
  vérifié ligne à ligne identique à l'original — nécessite l'import de
  `EvidenceLink`/`PacketEvidence` depuis `netcross_core.expert_model`,
  nouveau dans ce module). `dns_timeout` reste par POINT (comme
  `dns_nxdomain`/`dns_servfail`), avec en plus `frames`
  (`report.dns_timeout_frames.get(p, [])`, même mécanisme
  `PacketEvidence` que le reste du projet depuis la Session 35).
  `dns_missing` est clé par une PAIRE de points adjacents (comme
  `hop_delta_outliers`), mais SANS `frames` : vérifié dans `models.py`
  avant rédaction — aucun champ `dns_missing_frames` sur `Report`,
  absence volontaire côté source (`_evidence(seg, missing)` à deux
  arguments seulement côté procédural), pas un oubli de ce pilote.
  Sévérité UNIQUE pour les deux règles (aucun seuil dans
  `rule.thresholds`), lue depuis `rule.severity` comme le lot de la
  Session 56. `tests/test_rule_engine.py` : 9 nouveaux tests
  (déclenchement/silence-absent/silence-liste-vide/contenu d'`evidence`/
  équivalence avec `build_findings()` incluant l'`evidence` terme à
  terme — première vérification de ce champ pour ce pilote) : `pytest`
  980/980 → **989/989** (+9 net). `ruff check .`/`ruff format
  --check .` propres, `lint-imports` inchangé en fichiers (66), 169
  dépendances (+1 : nouvel import `netcross_core.expert_model` dans
  `rule_engine.py`, sens autorisé `netcross_report -> netcross_core`).
  `mypy` sur les deux fichiers modifiés : 0 erreur imputable ; les 49
  erreurs préexistantes (Session 50) hors périmètre reconfirmées
  inchangées (sous-ensemble de 27 sur 7 fichiers visible depuis le
  graphe d'import de `rule_engine.py`, qui n'atteint pas
  `tls_diagnostics.py`/`quic_diagnostics.py` — mêmes 49/9 sur
  l'intégralité de `src/`, non re-décomptées cette session, aucun de
  ces deux fichiers modifié). `dns_timeout`/`dns_missing` restent les
  seuls candidats nommés explicitement ; les ~31 autres règles sans
  évaluateur ne sont pas individuellement auditées pour leur
  simplicité (voir « Prochaine feature »). Détail complet :
  `docs/sessions/session-57.md`.
- **Session 56** : suite du chantier ouvert par la Session 55 (moteur
  d'exécution, `netcross_report/rule_engine.py`) — option (a) de
  « Prochaine feature » retenue : extension de `_EVALUATORS` à QUATRE
  règles supplémentaires (**cinq au total**, sur 41) — les candidats à
  « seuil unique simple, sans corrélation » nommés explicitement par
  cette section depuis la Session 55 : `tcp_zero_window`,
  `hop_delta_outliers`, `dns_nxdomain`, `dns_servfail`. Chaque nouvel
  évaluateur reproduit EXACTEMENT son bloc source dans
  `synthesis.py::build_findings()` (vérifié bloc par bloc avant
  rédaction, pas supposé uniforme) : ces quatre blocs itèrent
  directement `Report.<compteur>.items()`, PAS `report.points` comme le
  fait `loss_per_segment`. Différence avec `loss_per_segment` : aucune
  des quatre nouvelles règles ne porte de seuil dans `rule.thresholds`
  (dict vide dans le catalogue) — sévérité UNIQUE par règle, lue depuis
  `rule.severity` plutôt que recopiée en dur une seconde fois (pièce
  pilotée par le catalogue pour ce lot, au même titre que
  `rule.thresholds["anomalie_rate_pct"]` pour `loss_per_segment` —
  égalité avec la constante procédurale vérifiée par le test
  d'équivalence de chaque règle, pas seulement supposée). **Correction
  apportée cette session** : la Session 55 groupait « les compteurs DNS
  bruts » comme un candidat homogène unique ; vérifié dans
  `netcross_core/models.py` avant rédaction que ce n'est pas le cas —
  `dns_nxdomain_count`/`dns_servfail_count` sont de simples
  `dict[str, int]` (retenus ici), tandis que `dns_timeout`/`dns_missing`
  portent des LISTES (`dict[str, list[str]]`/
  `dict[tuple[str, str], list[str]]`), leur bloc procédural passant par
  `_evidence()` — forme différente, laissés de côté cette session (voir
  « Prochaine feature »). `hop_delta_outliers` est clé par une PAIRE de
  points adjacents (`(a, b)`, segment `f"{a} -> {b}"`), seule des quatre
  dans ce cas — le mode statistique nommé par `Rule.preconditions` est
  déjà précalculé en amont (`netcross_core.analysis`, directement dans
  `Report.hop_delta_outliers`), donc pas plus complexe à reproduire ici
  qu'un compteur simple par point. `tests/test_rule_engine.py` : 12
  nouveaux tests (3 par règle — déclenche/silencieux/équivalence avec
  `build_findings()`, cette dernière filtrée par `rule_id` et non
  `category` cette fois : contrairement à « Pertes », les catégories
  TCP/DNS/Routage portent chacune plusieurs `rule_id` distincts, un
  filtre par seule catégorie fausserait la comparaison) : `pytest`
  968/968 → **980/980** (+12 net). `ruff check .`/`ruff format
  --check .` propres, `lint-imports` inchangé (66 fichiers, 168
  dépendances — aucun nouveau module créé, contrat toujours respecté).
  `mypy` sur les deux fichiers modifiés : 0 erreur ; les 49 erreurs
  préexistantes (Session 50) hors périmètre reconfirmées inchangées sur
  l'intégralité de `src/` (toujours 49/9). Câblage à un CLI/GUI réel,
  extension aux règles restantes (dont `dns_timeout`/`dns_missing`,
  forme différente — voir ci-dessus), et bascule effective de
  `build_findings` vers ce moteur : toujours hors périmètre, voir
  « Prochaine feature ». Détail complet : `docs/sessions/session-56.md`.
- Feuille de route de la comparaison OmniPeek (`docs/features-backlog.md`
  section 13.3) : **Session 0** (contrats analytiques communs — neuf objets
  dans `netcross_core/expert_model.py`) et **Session 1** (ingestion de
  l'expertise Wireshark/TShark) terminées. **Session 2** (moteur
  d'événements d'expertise) : `ExpertEvent` porte ses onze champs cible
  depuis la Session 45. Bibliothèque de règles déclarative (§6.2,
  `netcross_core/expert_rules.py`) : **41 règles** au total — les treize
  « déjà présentes » (Session 46), cinq des six « nouvelles » listées par
  §6.2 (Session 47 — DNS lent, PMTUD black hole, NAT/FW silencieux,
  anomalies L2 [ARP + STP + VLAN], options TCP incompatibles [+ MSS
  clamped en bonus, même détecteur]), huit règles supplémentaires
  (Session 49 — voir ci-dessous), une règle pour « Reseau/Serveur »
  (Session 51), cinq règles pour « HTTP » (Session 52), deux règles
  pour « TLS » (certificat, Session 53 — voir plus bas) et deux règles
  pour « TLS » (négociations incomplètes, Session 54 — voir plus bas).
  « Négociations TLS incomplètes » (§6.2), un concept DIFFÉRENT du
  signal certificat (voir Session 53 ci-dessous, qui revient sur cette
  distinction), a rejoint ce catalogue en Session 54 : décision
  architecturale tranchée, plus aucun signal nommé par la section 6.2
  n'est hors du système `Finding`/`rule_id`. **Session
  48** : premier câblage réel du catalogue à un consommateur — champ
  `rule_id` (`str | None`) sur
  `Finding` (`netcross_report/synthesis.py`) et `ExpertEvent`
  (`expert_model.py`), audité point par point sur les ~44 sites de
  construction de `Finding` (jamais une correspondance approximative par
  seule `category`) : les 23 règles d'alors toutes utilisées au moins une
  fois, dix-sept signaux distincts restés volontairement `rule_id=None`.
  **Session 49** : huit règles supplémentaires ajoutées au catalogue
  (23 → 31) et câblées (`rule_id`) sur les neuf sites de `Finding`
  correspondants — les CINQ paires « signal isolé à côté d'une règle déjà
  existante dans la même catégorie » identifiées en Session 48 :
  `hop_delta_outliers` (Routage), `pcp_change` (QoS),
  `icmp_frag_needed`/`icmpv6_too_big` (Fragmentation — FUSIONNÉS en une
  seule règle `icmp_fragmentation_needed`, même signal fonctionnel
  IPv4/IPv6, même sévérité), `syn_reply_missing` (TCP), et les QUATRE
  compteurs DNS bruts `dns_nxdomain_count`/`dns_servfail_count`/
  `dns_timeout`/`dns_missing` (gardés comme quatre règles distinctes,
  sévérités différentes — même discipline que les trois sous-types de
  retransmission TCP). À l'époque de la Session 49, restaient
  volontairement `rule_id=None` les TROIS catégories entières encore
  sans règle (`"Reseau/Serveur"`, `"TLS"`, `"HTTP"`, 8 sites) — aucune
  n'était nommée par §6.2, contrairement aux cinq paires ci-dessus ;
  PLUS AUCUNE catégorie de `Finding` n'est dans ce cas depuis la Session
  53 (voir plus bas).
  **Découverte notable de la Session 49** :
  `netcross_core/tls_diagnostics.py` (module indépendant, déjà câblé aux
  trois CLI/GUI et documenté en README) suit DÉJÀ l'état complet d'un
  handshake TLS (`HandshakeStatus.verdict` distingue explicitement
  « client_hello_no_reply »/« server_hello_no_data », très proche en
  esprit de « négociations incomplètes ») mais produit son PROPRE type
  `TlsFinding`, jamais un `synthesis.Finding` — `rule_id` ne s'applique
  qu'à ce dernier. Ce module reste inchangé et indépendant à ce jour
  (Session 54 ne l'a ni modifié ni réutilisé, voir plus bas). Catalogue
  toujours purement DESCRIPTIF : ne remplace ni ne
  pilote la détection existante (`analysis.py`/`synthesis.py` non
  modifiés dans leur logique pour les règles Sessions 46-53, seulement
  annotés ; Session 54 introduit en revanche un détecteur ENTIÈREMENT
  nouveau, voir plus bas), toujours aucun moteur d'exécution qui
  évaluerait une `Rule` contre un `Report`.
- Sessions 3 à 11 de cette feuille de route (corrélation causale, Flow
  enrichi, timeline, référentiels, conformité, forensic, dashboard,
  applicatif, alarmes) entièrement à faire.
- **Session 50 (audit qualité, hors feuille de route OmniPeek)** :
  demande explicite d'auditer le projet avec Context7 (vérifier l'usage
  à jour de `cryptography`, PyGObject/GTK4 et `networkx`) et de corriger
  toute erreur `ruff`. **Aucune erreur `ruff` trouvée** (`ruff check .`
  et `ruff format --check .` propres, vérifié avec `ruff==0.16.4` — la
  version épinglée dans `requirements-dev.txt`/
  `.pre-commit-config.yaml`, pas seulement la dernière disponible) :
  rien à corriger de ce côté. Les trois audits Context7 confirment un
  usage courant, non déprécié : `AESGCM`/`Cipher(algorithms.AES,
  modes.ECB())` dans `quic_diagnostics.py` correspondent exactement aux
  exemples officiels `pyca/cryptography` (l'ECB en en-tête QUIC est la
  construction attendue par la RFC 9001, pas un usage générique
  douteux) ; `netcross_gtk4/app.py` utilise déjà `Gtk.FileDialog` (pas
  `Gtk.FileChooserDialog`/`Gtk.Dialog`, dépréciés depuis GTK 4.10) et
  n'appelle jamais `.show()` sur un widget (déprécié aussi depuis 4.10
  au profit de `set_visible`) ; `topological_generations`/
  `NetworkXUnfeasible` (`netcross_report/charts.py`) sont l'API stable
  documentée de `networkx`. **Découverte réelle, non planifiée** :
  premier passage `mypy --ignore-missing-imports` sur l'intégralité de
  `src/` depuis l'introduction de l'outil (jusqu'ici toujours limité aux
  fichiers modifiés d'une session, par construction incapable de
  détecter une dérive sur un fichier non touché) — révèle **49 erreurs
  sur 9 fichiers**, pas 27 sur 7 : `tls_diagnostics.py` (18 erreurs) et
  `quic_diagnostics.py` (4 erreurs) n'avaient jamais été comptés, aucune
  session depuis leur création ne les ayant modifiés (donc jamais inclus
  dans un `mypy <fichiers modifiés>` ad hoc). Même nature d'erreurs que
  les 27 déjà connues (annotations manquantes, `str | None`/`int | None`
  remontant de `RawPacket` vers des dataclasses plus strictes, `**dict`
  non typé vers un constructeur typé) — pas une régression introduite
  par du code applicatif, un angle mort de suivi. Décompte corrigé
  ci-dessous (Commandes qualité) ; correction du code lui-même toujours
  hors périmètre (même décision que la Session 38, jamais remise en
  cause depuis). `pytest` (916/916) et `lint-imports` (65 fichiers, 164
  dépendances, contrat respecté) rejoués à l'identique : aucune
  régression. Détail complet : `docs/sessions/session-50.md`.
- **Session 51** : extension du catalogue de règles (§6.2) à une des
  trois catégories entièrement sans règle laissées par la Session 49 —
  `"Reseau/Serveur"` (décomposition applicatif/réseau), retenue en
  priorité sur `"TLS"`/`"HTTP"` car elle ne recoupe aucune décision
  architecturale en suspens et ne compte qu'un seul site de `Finding`.
  Nouvelle règle `server_processing_dominant` (31 → 32 règles),
  câblée (`rule_id`) sur l'unique site correspondant dans
  `synthesis.py::build_findings()`. `"TLS"`/`"HTTP"` restent
  entièrement sans règle, décision explicitement reportée comme après
  la Session 49. `pytest` 916/916 → **919/919** (+3 net), `ruff
  check`/`ruff format --check` propres, `lint-imports` inchangé (65
  fichiers, 164 dépendances — aucun nouveau fichier source), `mypy` sur
  les deux fichiers modifiés : 0 erreur imputable, les 49 erreurs
  préexistantes (Session 50) hors périmètre reconfirmées inchangées.
  Détail complet : `docs/sessions/session-51.md`.
- **Session 52** : extension du catalogue de règles (§6.2) à la
  deuxième des trois catégories laissées ouvertes par la Session 49 —
  `"HTTP"` (codes de statut, Session 17, CINQ sites de `Finding`),
  retenue avant `"TLS"` (seule catégorie encore ouverte après cette
  session) pour la même raison qu'en Session 51 (pas de décision
  architecturale en suspens), son report initial en Session 51 tenant
  uniquement au nombre de sites (cinq), pas à une difficulté de fond.
  Cinq nouvelles règles (32 → 37) : `http_client_error`/
  `http_server_error`/`http_timeout`/`http_missing`/
  `http_slow_response`, câblées (`rule_id`) sur les cinq sites
  correspondants dans `synthesis.py::build_findings()` (bloc
  « -- HTTP -- »). `pytest` 919/919 → **925/925** (+6 net), `ruff
  check`/`ruff format --check` propres (4 lignes reformulées pour la
  limite de 120 caractères), `lint-imports` inchangé (65 fichiers, 164
  dépendances), `mypy` sur les fichiers modifiés : 0 erreur imputable,
  les 49 erreurs préexistantes (Session 50) hors périmètre reconfirmées
  inchangées. Validation bout en bout avec un vrai serveur HTTP et
  `tshark`/`dumpcap` réels (200/404/500 capturés sur loopback, `rule_id`
  confirmé correct sur `findings`/`expert_events`). Détail complet :
  `docs/sessions/session-52.md`.
- **Session 53** : extension du catalogue de règles (§6.2) à la
  DERNIÈRE catégorie laissée ouverte par la Session 49 — `"TLS"`
  (certificat hors validité/pas encore valide, certificat substitué,
  Session 26, DEUX sites de `Finding`). **Correction apportée cette
  session** au raisonnement tenu depuis la Session 49 (repris tel quel
  par les Sessions 51/52, voir leurs paragraphes ci-dessus et
  `docs/sessions/session-51.md`/`session-52.md`) : contrairement à ce
  qui était affirmé, cataloguer le signal *certificat* ne « recoupe »
  PAS la décision architecturale sur « négociations TLS incomplètes »
  — vérifié dans le code avant rédaction, ce second signal ne produit
  AUCUN `synthesis.Finding` (il vit exclusivement dans `TlsFinding`,
  type séparé de `netcross_core/tls_diagnostics.py`, jamais relié à
  `Finding.category`), donc il n'a jamais été, et ne devient pas
  maintenant, candidat à une entrée de ce catalogue. Les deux signaux
  partagent la même étiquette « TLS » en langage naturel mais ne
  partageaient déjà aucun code, aucun type, aucun site de `Finding`
  commun. Deux nouvelles règles (37 → 39) : `tls_cert_invalid_dates`
  et `tls_cert_mismatch`, câblées (`rule_id`) sur les deux sites
  correspondants dans `synthesis.py::build_findings()` (bloc
  « -- certificat TLS -- »). À l'issue de cette session, PLUS AUCUNE
  catégorie de `Finding` n'est entièrement sans règle — mais
  « négociations TLS incomplètes » reste, comme documenté depuis la
  Session 49, un signal ENTIÈREMENT hors du système Finding/rule_id
  (décision architecturale toujours ouverte, voir « Prochaine
  feature »). `pytest` 925/925 → **930/930** (+5 net), `ruff
  check`/`ruff format --check` propres, `lint-imports` inchangé (65
  fichiers, 164 dépendances), `mypy` sur les quatre fichiers modifiés :
  0 erreur imputable, les 49 erreurs préexistantes (Session 50) hors
  périmètre reconfirmées inchangées (vérifié aussi sur l'intégralité de
  `src/`, toujours 49/9). Pas de validation avec capture réelle cette
  session (contrairement à la Session 52) : le détecteur
  (`_analyse_tls_certificate`, Session 26) est déjà testé de longue
  date (`test_analysis.py`, `test_report_text.py`,
  `test_baseline_diff.py`) et n'est pas modifié, même situation que les
  Sessions 46-51. **`README.md` à nouveau volontairement NON modifié**,
  même raison qu'aux Sessions 46-52. Détail complet :
  `docs/sessions/session-53.md`.
- **Session 54** : la décision architecturale ouverte depuis la Session
  49 — « négociations TLS incomplètes » (§6.2) — **enfin tranchée**,
  **option (a) retenue** : le signal rejoint `Report`/`analysis.py`
  pour rejoindre pleinement le pipeline `Finding`/`rule_id`, plutôt que
  (b) l'isoler dans `tls_diagnostics.py` sans jamais le cataloguer. Le
  coût redouté de (a) (dupliquer le parsing manuel de
  `tls_diagnostics.py`, ou casser son indépendance délibérée) s'est
  révélé, une fois vérifié dans le code, **ne pas exister** : le
  pipeline principal (`pcap_parser.protocols`, déjà utilisé pour le
  certificat) lit tshark en mode `-T ek` sans restriction de champs — la
  dissection TLS native y est déjà intégralement présente, il suffisait
  de lire deux champs EK supplémentaires (confirmés empiriquement par
  une vraie capture TLS 1.2 sur loopback, tshark 4.2.2, openssl
  s_server/curl, voir `docs/sessions/session-54.md`), exactement comme
  `extract_tls_certificate` le fait déjà. Nouvelle fonction
  `pcap_parser.protocols.extract_tls_handshake`, détecteur
  `netcross_core.analysis._analyse_tls_handshake` — **entièrement
  nouveau**, PAS une réutilisation de `tls_diagnostics.py`, qui reste
  inchangé et indépendant. Deux nouvelles règles (39 → **41**) :
  `tls_handshake_no_reply` (ClientHello sans ServerHello, PAR POINT) et
  `tls_handshake_incomplete` (ServerHello sans données applicatives, PAR
  POINT), câblées (`rule_id`) dès leur création. À l'issue de cette
  session, **tous les signaux nommés par la section 6.2 sont couverts**
  par le catalogue — plus aucune décision architecturale en suspens sur
  ce périmètre. `pytest` 930/930 → **959/959** (+29 net, répartis sur
  cinq fichiers de test : `test_expert_rules.py`/`test_analysis.py`/
  `test_synthesis.py`/`test_report_text.py`/`test_baseline_diff.py`),
  `ruff check .`/`ruff format --check .` propres (1 fichier reformaté :
  `report_text.py`), `lint-imports` inchangé (65 fichiers, 164
  dépendances — aucun nouveau module créé), `mypy` sur les neuf fichiers
  source modifiés : 1 erreur introduite puis corrigée dans la même
  session (annotation de type sur `extract_tls_handshake`, voir
  `docs/sessions/session-54.md`), 0 erreur imputable au final ; les 49
  erreurs préexistantes (Session 50) hors périmètre reconfirmées
  inchangées sur l'intégralité de `src/` (toujours 49/9 — le fichier
  modifié `pcap_parser/protocols.py` n'en fait PAS partie). **Validation
  bout en bout avec une vraie capture TLS 1.2** générée sur loopback
  (`openssl s_server`/`s_client`/`curl` + `tshark` réels, tous
  réinstallés via `apt-get` dans cet environnement) : un ClientHello
  seul sans réponse détecté comme `tls_handshake_no_reply=1` (0 faux
  positif sur `tls_handshake_incomplete`) et un handshake complet réel
  (via `curl`) ne déclenche NI l'un NI l'autre signal — vérifié à la
  fois via le pipeline `parse_capture`/`correlate`/`analyse` direct et
  via le CLI complet (`cross_capture_analyzer_cli.py`, sortie texte
  confirmée). Détail complet : `docs/sessions/session-54.md`.
- **Session 55** : deux chantiers indépendants demandés explicitement,
  aucun des deux ne fait partie de la feuille de route OmniPeek
  (§13.3) elle-même.
  1. **Migration `pip` → `uv`** (gestionnaire de dépendances). Recherche
     préalable : **aucune trace de `poetry`** dans le projet avant cette
     session (`pyproject.toml` n'avait que `[tool.ruff]`/
     `[tool.importlinter]`, jamais de `[tool.poetry]` ; aucun
     `poetry.lock` livré) — la consigne « remplacer poetry » est donc
     interprétée comme la migration réellement présente à remplacer :
     `pip install -r requirements.txt(+ -dev.txt)`. Ajout de
     `[project]`/`[project.optional-dependencies.dev]`/`[tool.uv]
     package = false` dans `pyproject.toml` (mêmes bornes de version que
     les fichiers `requirements*.txt` existants) et génération de
     `uv.lock` (49 paquets résolus, `uv sync --extra dev` opérationnel).
     `requires-python` relevé de `>=3.9` à `>=3.10` : `import-linter>=2.13`
     (dépendance dev) exige lui-même Python≥3.10, `uv lock` échouait sinon
     sur la résolution de l'extra `dev` — aucun changement de syntaxe
     nécessaire dans `src/` pour cette bascule, le code applicatif reste
     compatible 3.9. `requirements.txt`/`requirements-dev.txt` **conservés**
     (pas supprimés) comme repli documenté pour les environnements sans
     `uv` — référencés par les messages d'erreur d'`install.sh`, qui
     privilégie de toute façon les paquets système et ne change pas cette
     session — mais volontairement **non régénérés** via `uv export`
     (qui produirait un pin transitif complet, différent du style borne
     basse `>=` déjà en place) : à tenir à jour manuellement en miroir de
     `pyproject.toml` si les dépendances changent, comme documenté en
     en-tête de ces deux fichiers. Ajout d'un `.gitignore` (absent avant
     cette session, zip livré sans `.git`) couvrant `.venv/` (nouveau,
     créé par `uv sync`) et les caches d'outillage déjà présents
     (`.mypy_cache/`, `.ruff_cache/`, `.import_linter_cache/`,
     `.pytest_cache/`). `pytest`/`ruff check`/`ruff format --check`/
     `lint-imports` rejoués via `uv run`/`PYTHONPATH=src uv run
     lint-imports` après la migration : tous verts, aucune régression
     (959/959 à ce stade, avant l'ajout de la feature ci-dessous).
  2. **Correction de toutes les erreurs `ruff`** : **aucune trouvée**
     (`uv run ruff check .` et `uv run ruff format --check .` propres,
     `ruff==0.16.4` — version épinglée, identique à la Session 50, qui
     avait déjà conclu à 0 erreur) : rien à corriger, état inchangé.
  3. **Nouvelle feature** (choix explicite entre les deux chantiers
     laissés ouverts par la Session 54, voir « Prochaine feature »
     ci-dessous à l'époque) : premier PILOTE du moteur d'**exécution**
     de règles plutôt que la bascule vers la Session 3 (corrélation
     causale, difficulté 5/5, chantier bien plus large et sans brique
     préalable) — retenu car c'est la suite directe et déjà nommée par
     CLAUDE.md depuis la Session 54 (« l'utiliser [le catalogue] pour
     PILOTER la détection, pas seulement l'annoter après coup »), et un
     premier pilote borné à une seule règle est vérifiable de bout en
     bout dans une seule session (même discipline que le pilote
     `PacketEvidence`/PMTUD de la Session 35 ou le premier lot
     `ExpertEvent` de la Session 40). Nouveau module
     `netcross_report/rule_engine.py::evaluate(rule_id, report) ->
     list[Finding]` — **une seule règle pilotée** : `loss_per_segment`
     (la plus simple du catalogue, un seul seuil numérique nommé dans
     `Rule.thresholds`, aucune corrélation entre deux signaux). Placé
     dans `netcross_report` et PAS `netcross_core` : produire un
     `Finding` (`netcross_report.synthesis`) depuis `netcross_core`
     violerait le contrat de couches (`netcross_gtk4 -> netcross_report
     -> netcross_core -> pcap_parser`, `[tool.importlinter]`) — vérifié
     avec `PYTHONPATH=src lint-imports` après l'ajout (66 fichiers, 168
     dépendances, contrat toujours respecté). Les 40 autres règles du
     catalogue n'ont PAS d'évaluateur enregistré : `evaluate()` lève
     `NotImplementedError` pour elles plutôt que d'inventer un mapping
     non vérifié — distinct de `KeyError` pour un `rule_id` inconnu du
     catalogue. Ce module ne remplace ni ne pilote encore
     `synthesis.py::build_findings` (inchangé, reste l'unique chemin de
     production en CLI/GUI) : c'est un second consommateur du même
     `Report`, ajouté pour démontrer par construction que le catalogue
     déclaratif peut PILOTER une détection réelle. `tests/
     test_rule_engine.py` (9 tests, dont une vérification d'équivalence
     explicite avec `build_findings()` sur plusieurs points) :
     `pytest` 959/959 → **968/968** (+9 net). `mypy` sur les deux
     fichiers ajoutés : 0 erreur imputable ; les 49 erreurs préexistantes
     (Session 50) hors périmètre reconfirmées inchangées sur
     l'intégralité de `src/` (toujours 49/9). Câblage à un CLI/GUI réel,
     extension à d'autres règles du catalogue, et bascule effective de
     `build_findings` vers ce moteur : hors périmètre de ce pilote, voir
     « Prochaine feature ». Détail complet : `docs/sessions/session-55.md`.

### Pipeline de sécurité — `--security-report` (issues #139, #216, #218, #259)

**Flags CLI** :

| Flag | Rôle |
|---|---|
| `--security-report` | rapport de sécurité consolidé : services détectés, tentatives d'exploitation, anomalies Expert Info corrélées, CVE confirmées, tableau de bord avec score de risque 0-100. Relit les fichiers `--capture` pour chercher les signatures dans la charge utile BRUTE (même discipline que `--tls`). Incompatible avec `--live` et `--redact`. |
| `--cve-db CHEMIN` | base CVE SQLite locale (construite par `scripts/import_nvd.py`) pour la corrélation version → CVE. Exige `--security-report`. Doit désigner un fichier existant. Sans elle, les services sont listés et **l'absence de base est annoncée** — jamais présentée comme une absence de vulnérabilité. |
| `--security-html CHEMIN` | rendu HTML autonome du rapport de sécurité (#218). Fichier unique, aucune ressource externe, aucune dépendance supplémentaire. Exige `--security-report`. |

Les constats de sécurité alimentent aussi `--json-report` (clé
`security_report`, avec la forme lisible des empreintes NON tronquée) et
`--pdf-report` (section dédiée). Sans `--security-report`, le JSON écrit
`"security_report": null` **plus** `security_report_absent` avec le
motif : un consommateur doit pouvoir distinguer « non demandé » de
« demandé, rien trouvé ».

**Modules** :

- `netcross_core/security/findings.py` — agrégation CVE-1..4 via
  `apply_security_findings(report, packets, detections=..., cve_conn=...)`,
  plus les détecteurs voisins du même paquet (beaconing, DGA, fast flux,
  exfiltration, mouvement latéral, tunnel DNS, audit TLS, incohérence de
  protocole).
- `netcross_core/security/cve_db.py`, `cpe_match.py` — base CVE et
  correspondance CPE.
- `netcross_core/fingerprint/` — JA4 (TLS) et HASSH (SSH), **vérifiés
  identiques à l'implémentation de référence de Wireshark** (#259) ;
  `known_fingerprints.json` contient 7 empreintes réelles.
- `netcross_report/security_report.py` — consolidation, rendu texte et
  `security_report_to_dict()`, **socle unique** des sorties JSON, HTML et
  PDF : trois rendus divergeraient au premier champ ajouté, ce qui est
  exactement ce qui a produit #259.
- `netcross_report/security_html.py` — rendu HTML (#218).

**Documentation** : `docs/security-report.md`,
`docs/fingerprints-ja4-hassh.md`.

**État du chantier CVE** : CVE-1 à CVE-5 sont **tous livrés et clos**,
y compris #135 (extraction des bannières de versions, clos le
2026-09-20). Le corps de l'issue #216 affirmait #135 encore ouvert :
information périmée, vérifiée le 2026-09-22. `application/banners.py`
est couvert à 94 %.

## Prochaine feature

Depuis la Session 54, la bibliothèque de règles déclarative (§6.2) est
COMPLÈTE : 41 règles, toutes les catégories de `Finding` couvertes,
tous les signaux nommés par la section 6.2 sont désormais catalogués
(y compris « négociations TLS incomplètes », dont la décision
architecturale était ouverte depuis la Session 49 — voir État
courant). Il ne reste plus de travail de type « ajout mécanique au
catalogue » sur ce périmètre. Le moteur d'EXÉCUTION
(`netcross_report/rule_engine.py`), ouvert Session 55 et étendu Session
56, reste un chantier ouvert :

- **moteur d'EXÉCUTION** (chantier ouvert depuis la Session 55, étendu
  Sessions 56 à 69) : le pilote couvre aujourd'hui
  TRENTE-NEUF règles sur 41 — `loss_per_segment` (Session 55),
  `tcp_zero_window`, `hop_delta_outliers`, `dns_nxdomain`,
  `dns_servfail` (Session 56), `dns_timeout`, `dns_missing` (Session
  57), `tcp_retransmission_rto`, `tcp_retransmission_spurious`,
  `tcp_retransmission_fast`, `tcp_rst_localized`, `tcp_syn_no_synack`,
  `syn_reply_missing` (Session 58), `tcp_options_stripped`,
  `tcp_mss_clamped` (Session 59 — le bloc source `-- TCP avance --` de
  `synthesis.py` est désormais ENTIÈREMENT pilotée, les huit règles
  qu'il contenait sont toutes couvertes), `ttl_variation`,
  `pcp_change`, `icmp_fragmentation_needed` (Session 60),
  `tls_cert_invalid_dates`, `tls_cert_mismatch`, `tls_handshake_no_reply`,
  `tls_handshake_incomplete`, `http_timeout`, `http_missing` (Session
  61), `http_client_error`, `http_server_error` (Session 62 — voir État
  courant ; avec ce lot, le bloc source `-- HTTP --` de `synthesis.py`
  est lui aussi ENTIÈREMENT pilotée, les quatre règles qu'il contenait
  sont toutes couvertes, même complétude que `-- TCP avancé --` depuis
  la Session 59), `dhcp_issues`, `sip_issues` (Session 63 — les DEUX
  DERNIERS candidats déjà audités), `vlan_change` (Session 64 —
  PREMIÈRE des treize règles jamais auditées à recevoir un
  évaluateur), `arp_ip_conflict` (Session 65 — voir État courant ;
  DEUXIÈME), `stp_instability` (Session 66 — voir État courant ;
  TROISIÈME), `nat_fw_silent_drop` (Session 67 — voir État courant ;
  QUATRIÈME, seule des cinq règles sans corrélation restantes à s'être
  révélée, une fois auditée, de forme directement reproductible),
  `dns_slow_resolution`/`http_slow_response` (Session 68 — voir État
  courant ; lot groupé, PREMIÈRE forme entièrement NOUVELLE de ce
  pilote, agrégation `statistics.mean()` sur liste plate),
  `qos_dscp_remarking`, `fragmentation_new`, `saturation`,
  `bufferbloat`, `pmtud_blackhole` (Session 69 — voir État courant ;
  les CINQ règles à `correlation_rule` non `None`, auditées bloc par
  bloc pour la première fois et TOUTES directement reproductibles, à
  l'inverse de l'audit symétrique de la Session 67).

  **Changement de nature apporté par la Session 63, poursuivi par les
  Sessions 64-69** : plus aucun candidat n'attend d'être audité — les
  DEUX règles encore sans évaluateur sont toutes deux déjà AUDITÉES par
  la Session 67 (voir État courant pour le détail de leur forme
  respective) et confirmées de forme entièrement nouvelle, sans brique
  réutilisable — `rtp_quality_mos` (source liste de dicts avec sévérité
  à deux seuils calculée dynamiquement, sans brique commune avec celle
  introduite en Session 68 ni avec les cinq formes de la Session 69) et
  `server_processing_dominant` (corrèle deux moyennes avec un ratio ET
  un seuil absolu). Quatre enseignements des Sessions 65/66/68/69
  restent valables pour toute extension future : un seuil catalogue
  n'est pas toujours consommé par le bloc source lui-même (Session 65,
  `arp_ip_conflict` ; confirmé à nouveau Session 67,
  `nat_fw_silent_drop`, puis Session 69, `saturation`/`bufferbloat`/
  `pmtud_blackhole` — trois occurrences supplémentaires en une seule
  session, la première fois avec PLUSIEURS seuils à la fois pour une
  même règle, `saturation` en portant cinq), deux compteurs fusionnés
  sous un même `rule_id` peuvent partager la MÊME granularité malgré
  une forme a priori proche de `dhcp_issues` (Session 66,
  `stp_instability`), une forme entièrement nouvelle pour ce pilote
  peut malgré tout rester triviale à reproduire une fois auditée sans
  `evidence` associée (Session 68, liste plate agrégée par
  `statistics.mean()`), et un lot audité pour la première fois peut se
  révéler ENTIÈREMENT reproductible d'un coup, sans qu'aucune règle
  n'exige de décision de conception nouvelle (Session 69, à l'inverse
  de l'audit symétrique de la Session 67 où quatre candidats sur cinq
  en exigeaient une).

  Extensions possibles, par ordre de coût croissant :
  (a) piloter enfin `rtp_quality_mos`/`server_processing_dominant`,
  malgré l'absence de brique réutilisable pour l'une comme pour
  l'autre (chacune exigerait une forme nouvelle propre — dernier
  reliquat de ce chantier, 2 règles sur 41) ;
  (b) un jour,
  câbler `evaluate()`/`available_rule_ids()` à un CLI ou au GTK4, en
  complément (pas en remplacement) de `build_findings()` ; (c) le
  chantier le plus large, non entamé : faire un jour BASCULER
  `build_findings()` lui-même vers ce moteur plutôt que de garder deux
  chemins parallèles — nécessiterait d'abord (a) (il ne reste plus que
  DEUX règles, contre sept avant la Session 69 — la décision sur les
  CINQ règles à `correlation_rule` non `None`, saturation, bufferbloat,
  remarquage QoS, fragmentation, PMTUD black hole, est désormais
  tranchée par la pratique, voir ci-dessus), **et** une décision sur
  l'ORDONNANCEMENT des `Finding` mise au jour par la Session 63 :
  `build_findings()` trie sa liste complète en sortie, `evaluate()`
  renvoie dans l'ordre de construction et ne reproduit délibérément pas
  ce tri (étape de présentation appliquée aux 41 règles à la fois) —
  c'est ce tri final, et non les évaluateurs, qui devra rester le point
  unique d'ordonnancement après bascule ;
- cause probable/impact — bascule en réalité vers la **Session 3**
  (corrélation et causalité, difficulté 5/5), toujours entièrement à
  faire.

Le choix précis se fait en début de session avec son propre raisonnement
(voir `docs/sessions/session-38.md` à `session-62.md` pour la méthode
suivie jusqu'ici, y compris la correction de raisonnement apportée en
Session 53, la décision architecturale tranchée en Session 54, le choix
du pilote d'exécution plutôt que la Session 3 en Session 55, son
extension à quatre règles supplémentaires en Session 56, à
`dns_timeout`/`dns_missing` en Session 57, à six règles TCP
supplémentaires en Session 58, aux deux dernières règles du bloc
`-- TCP avance --` en Session 59, qui l'épuise entièrement, puis à trois
règles supplémentaires en Session 60 — `ttl_variation`, `pcp_change`,
`icmp_fragmentation_needed` — après audit bloc par bloc des treize
candidats restants, aux six candidats confirmés de forme directement
reproductible en Session 61 — `tls_cert_invalid_dates`,
`tls_cert_mismatch`, `tls_handshake_no_reply`,
`tls_handshake_incomplete`, `http_timeout`, `http_missing` — et enfin
aux deux derniers candidats de cette même forme en Session 62 —
`http_client_error`, `http_server_error`, qui épuise le bloc `-- HTTP
--`, et enfin aux deux dernières règles auditées en Session 63 —
`dhcp_issues`, `sip_issues` —, qui épuise la réserve de candidats
identifiés et fait basculer le coût dominant de l'écriture vers
l'audit, puis aux trois premières règles jamais auditées lues bloc par
bloc en Sessions 64-66 — `vlan_change`, `arp_ip_conflict` et enfin
`stp_instability`, dernière à être déjà connue comme mieux comprise
que les autres parmi les six candidats sans corrélation identifiés par
la Session 63 ; puis à l'audit bloc par bloc des cinq derniers
candidats sans corrélation en Session 67, dont un seul,
`nat_fw_silent_drop`, s'est révélé directement reproductible ; puis au
lot groupé `dns_slow_resolution`/`http_slow_response` en Session 68,
seule paire de forme identique parmi les quatre candidats restants
audités par la Session 67 ; puis à l'audit bloc par bloc, pour la
première fois, des CINQ règles à `correlation_rule` non `None` en
Session 69 — `qos_dscp_remarking`, `fragmentation_new`, `saturation`,
`bufferbloat`, `pmtud_blackhole` —, les CINQ se révélant directement
reproductibles, à l'inverse de l'audit symétrique de la Session 67).
Détail complet et champs restants du schéma cible :
@docs/features-backlog.md sections 13.3 et 6.2.

Item indépendant de cette feuille de route (n'a rien à voir avec la
comparaison OmniPeek) : les 49 erreurs `mypy` remises à jour en Session
50 (voir État courant) sont DÉSORMAIS RÉSOLUES (Session 71, issue #28) :
`PYTHONPATH=src uv run mypy --ignore-missing-imports src/` renvoie
`Success: no issues found in 36 source files`.

## Décision d'architecture : bascule build_findings() → moteur d'exécution

**Issue #27 — décision documentée, pas de code.**

### Constat

`build_findings()` (`synthesis.py`) trie sa liste complète en sortie par
`(SEVERITY_ORDER, category, segment)` — une étape de PRÉSENTATION
appliquée à l'ensemble des 41 règles à la fois. `evaluate()`
(`rule_engine.py`) renvoie ses `Finding` dans l'ordre de CONSTRUCTION
du bloc source et ne reproduit délibérément PAS ce tri. Cette divergence
a été mise au jour par la Session 63 (`sip_issues`, premier cas où les
deux ordres diffèrent réellement).

### Décision

1. **`evaluate()` ne triera jamais ses propres `Finding`.** Le tri par
   `(SEVERITY_ORDER, category, segment)` est une étape de présentation
   globale, pas une propriété d'une règle prise isolement. Un
   évaluateur qui trierait ses propres `Finding` donnerait de toute
   façon un ordre différent du tri global dès que deux règles se
   mélangent.

2. **La bascule de `build_findings()` vers le moteur d'exécution est
   RETENUE** comme objectif à long terme, mais pas exécutée maintenant.
   Les deux chemins coexistent : `build_findings()` reste l'unique
   source de vérité en production (CLI/GUI), `evaluate()` est un
   consommateur indépendant vérifiant par construction que le catalogue
   déclaratif peut piloter une détection réelle.

### Plan de migration (à exécuter quand (a) sera complété)

Prérequis : les 41 règles doivent avoir un évaluateur (2 restantes :
`rtp_quality_mos`, `server_processing_dominant` — formes entièrement
nouvelles, voir « Prochaine feature » (a)).

Étapes :

1. Créer une fonction `evaluate_all(report) -> list[Finding]` dans
   `rule_engine.py` qui itère sur `available_rule_ids()`, appelle
   `evaluate()` pour chaque règle, concatène les résultats.
2. Appliquer le tri `(SEVERITY_ORDER, category, segment)` à la liste
   concaténée — point UNIQUE d'ordonnancement, équivalent au tri final
   actuel de `build_findings()`.
3. Remplacer l'appel à `build_findings()` dans le CLI/GUI par
   `evaluate_all()`. `build_findings()` devient code mort, conservé
   temporairement pour comparaison.
4. Vérifier l'équivalence : `evaluate_all(report)` doit produire les
   MÊMES `Finding` (même contenu, même ordre) que `build_findings(report)`
   sur les jeux de tests existants (`tests/test_synthesis.py`).
5. Supprimer `build_findings()` et ses tests d'équivalence une fois la
   parité vérifiée sur plusieurs sessions.

**Risque identifié** : les 2 règles sans évaluateur produisent
actuellement des `Finding` via `build_findings()`. La bascule sans
les avoir pilotées créerait une régression silencieuse (perte de
2 détections). D'où le prérequis (a).

## Commandes qualité

Depuis la Session 55, `uv` est le gestionnaire de dépendances canonique
du projet (`pyproject.toml` [project]/[project.optional-dependencies]
+ `uv.lock` -- voir État courant ; `requirements*.txt` restent un repli
pip documenté, non régénéré automatiquement).

```bash
uv sync --extra dev             # une fois par clone/mise a jour des dependances -- cree/actualise .venv
uv run pytest                   # 2205/2205 attendu, pythonpath=src via pytest.ini
uv run pytest --cov --cov-report=term-missing   # couverture (issue #224) : source=[tool.coverage.run] dans pyproject.toml ; ajouter --cov-report=xml:coverage.xml pour le format CI ; --cov-report=html pour un rapport navigable dans htmlcov/ ; pas de seuil bloquant tant que la base de reference n'est pas calibree
uv run ruff check .
uv run ruff format --check .
PYTHONPATH=src uv run lint-imports     # contrat de couches netcross_gtk4 -> netcross_report -> netcross_core -> pcap_parser
python3 scripts/generate_class_diagram.py           # (re)genere docs/class-diagram.md depuis src/ (hook pre-commit `class-diagram`) ; `--check` = verifie sans ecrire
pre-commit run --all-files      # necessite un depot git local (absent du zip livre) ; a defaut, ruff check/ruff format/lint-imports/generate_class_diagram.py ci-dessus couvrent les memes 4 hooks configures dans .pre-commit-config.yaml
uv run mypy --ignore-missing-imports <fichiers modifiés>   # ad hoc, pas encore dans pre-commit (mypy pas dans l'extra dev -- installer ponctuellement avec `uv pip install mypy`) ; decompte corrige a la Session 50 (premier passage sur l'integralite de src/) : 49 erreurs preexistantes hors perimetre sur 9 fichiers -- analysis.py 10, tls_diagnostics.py 18, triage.py 9, quic_diagnostics.py 4, packet.py 2, history.py 2, netcross_report/__init__.py 2, ek_source.py 1, parsing.py 1 (inchange depuis la Session 50, reconfirme Sessions 55 a 67 ; tls_diagnostics.py et quic_diagnostics.py absents du decompte precedent de 27/7 fichiers suivi depuis la Session 38 -- jamais modifies par une session donc jamais inclus dans un `mypy <fichiers modifies>` ad hoc). ATTENTION, precision relevee Session 63 : cette commande se lance bien SANS `PYTHONPATH=src` (contrairement a `lint-imports` ci-dessus) -- c'est la convention suivie depuis toujours mais jamais explicitee, et elle seule reproduit le chiffre de 27 erreurs/7 fichiers suivi depuis la Session 58 ; avec `PYTHONPATH=src`, mypy resout les imports autrement, ne remonte pas dans le sous-graphe et renvoie `Success` sur les memes fichiers. Les deux invocations s'accordent sur le point qui compte (0 erreur imputable aux fichiers modifies). Pour la baseline complete, utiliser `PYTHONPATH=src uv run mypy --ignore-missing-imports src/` (49 erreurs/9 fichiers)
```

**Diagramme de classes (issue #140)** : `docs/class-diagram.md` est un fichier GENERE depuis `src/`
par `scripts/generate_class_diagram.py` (analyse `ast`, stdlib seule) -- ne jamais l'editer a la
main, il n'y a plus de section « diagramme de classes » a relire dans `docs/features-backlog.md`
(la section 3 n'est plus qu'un renvoi). Le hook pre-commit `class-diagram` le regenere des qu'un
`src/**/*.py` change (le commit echoue alors une fois : `git add docs/class-diagram.md` et
recommiter) ; `tests/test_class_diagram.py::test_docs_class_diagram_est_a_jour` echoue si le fichier
versionne est en retard sur le code.

**tshark/editcap/capinfos en CI et en session (issues #261 et #262)** :
jusqu'à la Session 68, ces binaires n'étaient installés dans AUCUN
environnement de développement du projet ni en CI. Toute la suite
`@requires_tshark` / `@requires_editcap` était donc **sautée**, et deux
bugs bien réels ont survécu des mois à une CI verte : `export_filtered()`
combinait `-f` avec `-r` (interdit par tshark, donc tout `bpf_filter`
levait `TsharkError`) et ni `export_filtered()` ni `adjust_timestamps()`
ne passaient `-F`, si bien qu'un `path_out` en `.pcap` contenait en
réalité du pcapng. Le workflow `ci.yml` installe désormais `tshark`
(étape « Installation de Wireshark CLI ») **et vérifie qu'aucun test ne
reste sauté pour cette raison** : un test sauté est une vérification qui
n'a pas eu lieu, pas un succès. En local : `sudo apt-get install -y
tshark` (répondre « non » à la question sur les droits de capture, ou
pré-répondre via `debconf-set-selections` comme le fait la CI).

Leçon à généraliser : un `skipif` sur la disponibilité d'un outil externe
ne protège le code que si l'outil est présent **quelque part**. Sinon il
convertit silencieusement une absence de test en test vert.

**Outils disponibles en session** : le connecteur MCP Context7 est
accessible dans cet environnement (`mcp__Context7__resolve-library-id`
/ `mcp__Context7__query-docs`) — noté à la demande explicite en
Session 59. À interroger au besoin pour vérifier la documentation à
jour d'une bibliothèque tierce (`cryptography`, `reportlab`,
`matplotlib`, `networkx`, `import-linter`, `ruff`, `pytest`...) avant
d'écrire du code qui en dépend, plutôt que de se fier uniquement à la
connaissance interne (potentiellement datée) — même prudence que les
recherches web déjà pratiquées ponctuellement dans ce projet
(vérification de versions, changelogs). Pas utilisé à ce jour dans une
session : aucune tâche jusqu'ici ne l'a rendu nécessaire (le pilote du
moteur d'exécution, par exemple, ne consomme que le code interne du
projet lui-même — `expert_rules.py`/`synthesis.py`/`models.py` —, pas
de documentation externe).

## Couverture par PR (delta vs dev)

Depuis le 21/09/2026 (suite de #224), le workflow
`.github/workflows/pr-coverage.yml` commente chaque PR vers `dev` avec la
couverture totale et le delta vs la base (`dev`) : pytest --cov exécuté sur
le ref de fusion puis sur le SHA de base, comparaison par
`scripts/pr_coverage_comment.py` (stdlib seule, commente via l'API GitHub,
tests dans `tests/test_pr_coverage_comment.py`). Aucun seuil bloquant : la
base de référence du 2026-09-21 est de 76,7 % (voir #224).

## Workflow d'intégration (dev → main)

Depuis le 21/09/2026, `main` est protégée : toute fusion vers `main` passe
obligatoirement par une PR depuis `dev` (workflow
`.github/workflows/guard-main.yml` = required status check « Garde : PR vers
main doit venir de dev » + protection de branche). Le flux est :
feature → PR vers `dev` (CI Qualité) → fusion dans `dev` → PR `dev` → `main`
(CI Qualité + Garde) → fusion. Les PR directes feature → `main` sont rejetées
par le garde-fou.

## Consigne récurrente

« Continue les features à faire de la comparaison avec OmniPeek. Fais
évoluer les fichiers de suivi, de tests et de documentation. Tu livres
juste après le `netcross-{YYYYMMDD-HHMMSS}.zip` sans passer à la
suite. » — à chaque session : mettre à jour ce `CLAUDE.md` (état courant +
prochaine feature) et `docs/features-backlog.md`, ajouter le journal
détaillé dans un nouveau `docs/sessions/session-NN.md`, puis livrer le zip
horodaté sans enchaîner sur la feature suivante.

## Instructions reçues dans le chat (issue #931)

Toute instruction reçue dans le chat (Perplexity Computer, Claude Code ou autre) devient une issue. Une phrase ne reste pas en l'air.

- Avant de commencer le travail, créer l'issue dans le dépôt concerné, en citant l'instruction mot pour mot avec sa date.
- Une demande qui touche plusieurs dépôts donne une issue par dépôt, chacune liée aux autres.
- Une question posée dans le chat sans réponse immédiate devient elle aussi une issue, ou un commentaire « Question pour Mathilde » sur l'issue existante.
- La PR ferme ou cite l'issue (`Closes #n`). Une instruction abandonnée est fermée avec sa raison (« not planned »).
- En fin de session, vérifier que chaque instruction du chat a son issue, ouverte ou fermée.
