# Parité GUI / CLI / API

Réponse à #330 : « est-ce que toutes les fonctions de l'appli GTK4 sont
accessibles en CLI et API, et inversement ? ».

Cette matrice est **mesurée sur le code**, et non déclarée à la main :
`tests/test_parite_surfaces.py` extrait les options réellement définies par
chaque CLI (argparse), les routes et paramètres de l'API (FastAPI) et les
cases à cocher de la GUI (AST de `netcross_gtk4/`), puis échoue si l'un
d'eux n'apparaît pas dans cette page. Ajouter une option sans la classer
ici fait donc échouer la CI.

État mesuré le 26/09/2026 sur `dev` :

| Surface | Points d'entrée | Capacités |
|---|---|---|
| CLI | `cross_capture_analyzer_cli.py` (110 options), `cross_capture_diff_cli.py` (27), `cross_capture_batch_cli.py` (11), `cross_history_cli.py`, `netcross_lua_doc_cli.py`, `netcross_ai_models_cli.py` | Surface de référence : tout y est |
| GUI | `netcross_gtk4` : 3 pages, 32 cases à cocher, 24 réglages numériques | Analyse interactive et exploration visuelle |
| API | 29 routes FastAPI | Analyse avec sécurité ; options NAT, TLS, QUIC, anonymisation ; exports texte, PDF, CSV (issue #670) ; options avancées (#672) ; comparaison baseline/courant (#669) ; recherche forensic, extraction, comparaison de postes, NetFlow (#675) |

Légende : **oui** = disponible ; **non** = absent ; **auto** = toujours
actif, non réglable.

## Réponse courte

- **Non, la parité n'est pas complète, et c'est en partie voulu.** La CLI
  est la surface complète. La GUI couvre l'analyse et le diagnostic
  interactifs, et ajoute des vues d'exploration sans équivalent CLI. L'API
  expose l'analyse avec les options qui changent le résultat (NAT, TLS,
  QUIC, anonymisation), sans les réglages fins ni l'automatisation.
- Le rapport JSON de l'API est désormais celui de la CLI :
  `GET /analyses/{analysis_id}/report` (constats, triage, score de santé).
  `GET /analyses/{analysis_id}` reste la copie brute des mesures.
- Les écarts à combler sont listés à la fin, dans
  [Écarts à traiter](#ecarts-a-traiter).

## Analyse croisée

| Fonction | GUI | CLI | API |
|---|---|---|---|
| Captures en fichiers, un nom par point | oui (liste + « Ajouter une capture ») | `--capture` | `POST /captures` (`file`, `label`), `POST /captures/multi` (`files`, `labels`) |
| Capture unique (tout sauf la corrélation multi-points) | oui, une ligne suffit (issue #474) | un seul `--capture` | `POST /captures/multi` avec un fichier |
| Plusieurs fichiers pour un même point (rotation) | deux lignes de même nom (issue #671) | `--capture NOM=a,b` | `extra_files` (issue #671) |
| Plusieurs captures dans un seul fichier pcapng (une par interface ou section) | case « Séparer les interfaces d'un pcapng » (issue #474) | `--split-interfaces` | `split_interfaces` (issue #671) |
| Ordre des points imposé | oui (ordre de la liste) | `--order` | `points_order` |
| Topologie déduite automatiquement | oui (case « Deduire la topologie automatiquement ») | oui (sans `--order`) | oui (sans `points_order`) |
| Tolérance NAT | oui (« Correlation tolérante au NAT ») | `--nat-tolerant`, `--nat-window-ms` (fenêtre : les trois surfaces, « Fenêtre NAT (ms) » dans la GUI) | `nat_tolerant`, `nat_window_ms` |
| Doublons inter-captures | oui (« Détecter... », « Exclure... », seuil) | `--detect-duplicates`, `--exclude-duplicates`, `--duplicate-threshold-ms` | `detect_duplicates`, `exclude_duplicates`, `duplicate_threshold_ms` (#330, #841) |
| Lecture parallèle | oui (« Lecture parallele des captures », nombre « Lecteurs paralleles » en analyse simple, issue #672) | `--parallel`, `--parallel-workers` | `parallel_workers` (issue #672) |
| Fenêtre temporelle du débit | oui | `--bucket-ms` | `bucket_ms` (#330, #841) |
| Cadence RTP | oui | `--rtp-clock-rate` | `rtp_clock_rate` (#330, #841) |
| Seuil de coupure NAT/pare-feu silencieuse | oui (« Coupure silencieuse (s) », 0 = défaut 60 s) | `--idle-timeout-seconds` | `idle_timeout_seconds` (#330, #841) |
| Limiter ou échantillonner les paquets | oui (« Paquets max. », « Echantillonnage 1/N » en analyse simple, troncature annoncée dans le rapport ; issue #672) | `--max-packets`, `--sample` | `max_packets`, `sample` (issue #672) |
| Noms logiques des hôtes | oui (« Table des noms... », exports CSV détaillé et JSON) | `--names` | `names` (fichier joint, issue #672) |
| Plages TEST-NET traitées comme externes | oui (case « Plages TEST-NET externes », avec « Rapport de securite » ; issue #672) | `--test-net-external` | `test_net_external` (issue #672) |
| Anonymisation IP/MAC | oui (« Anonymiser les adresses IP/MAC ») | `--redact`, `--redact-map` | `redact` (sans sécurité, refusé avec `tls`/`quic`, comme la CLI) ; table : `GET /analyses/{analysis_id}/redact-map` (issue #876) |

## Diagnostics et triage

| Fonction | GUI | CLI | API |
|---|---|---|---|
| Triage et score de santé | oui (case « Triage » + « Top ») | `--triage`, `--triage-top-n` | `GET /analyses/{analysis_id}/report` (clés `triage`, `health_score`) |
| Diagnostic TLS | oui (« Diagnostic TLS ») | `--tls` | `tls` (clé `tls_findings` de `/report`) |
| Diagnostic QUIC/HTTP3 | oui (« Diagnostic QUIC/HTTP3 ») | `--quic` | `quic` (clé `quic_findings` de `/report`) |
| Rapport de sécurité (détecteurs, signatures d'exploit, CVE) | oui (« Rapport de securite ») | `--security-report` | auto (toujours exécuté, sauf avec `redact`), `GET /analyses/{analysis_id}/security` |
| Base CVE complète (NVD) | oui (« Base CVE... », avec « Rapport de securite » ; issue #672) | `--cve-db` | variable de serveur `NETCROSS_CVE_DB`, sinon base embarquée (issue #672) |
| Destinations et hôtes connus (sécurité) | oui (« Destinations connues... », « Hotes connus... », avec « Rapport de securite » ; issue #672) | `--known-destinations`, `--known-hosts` | `known_destinations`, `known_hosts` (fichiers joints, issue #672) |
| Moteur de règles | oui (case « Moteur de regles », section du rapport ; issue #673) | `--rule-engine` | `rule_engine` (clé `rule_engine` de `/report`, issue #673) |
| Section expertise détaillée | oui (case « Section expertise », section du rapport ; issue #673) | `--expert-section` | `expert_section` (issue #673) |
| Qualité média (VoIP/vidéo) | oui (case « Qualite media », section du rapport, analyse de fichiers ; issue #673) | `--media-quality` | `media_quality` : renvoie seulement vers `POST /analyses/{analysis_id}/extract` (issue #673) |
| Statistiques tshark natives | oui (case « Statistiques tshark », export JSON du panneau « Expertise (exports JSON) », même document ; issue #673) | `--tshark-stats` | `tshark_stats` (clé `tshark_stats` de `/report`, issue #673) |
| Chronologie des flux | oui (case « Chronologie des flux » et « Fenetre (s) », export JSON du panneau « Expertise (exports JSON) », même document ; issue #673) | `--flow-timeline`, `--flow-timeline-window` | `flow_timeline`, `flow_timeline_window` (clé `flow_timelines` de `/report`, issue #673) |
| Recherche forensic | oui (case « Index de recherche forensic », panneau « Recherche forensic » de la page Résultats : mêmes critères, export JSON identique, résultat cliquable vers la trame (filtre Wireshark, annotation, ouverture dans Wireshark) ; issue #675) | `--forensic-search`, `--search-text`, `--search-address`, `--search-point`, `--search-protocol`, `--search-port`, `--search-field`, `--search-value` | `POST /analyses/{analysis_id}/search` (issue #675), `body` |
| Extraction des contenus | oui (panneau « Contenus (extraction) » de la page Résultats : audio, vidéo, documents, dossier vide, même manifeste et même rappel d'usage ; après une analyse de fichiers non anonymisée, issue #675) | `--extract-contents`, `--extract-kinds` | `POST /analyses/{analysis_id}/extract` (issue #675), `kinds` |
| Comparaison de postes | oui (champs « Postes a comparer » et « Reference » de la configuration, section du rapport, panneau « Comparaison de postes » de la page Résultats avec export CSV ; issue #675) | `--client-group`, `--client-reference`, `--client-diff-csv` | `POST /analyses/{analysis_id}/client-diff` (issue #675), `body` |
| NetFlow / sFlow | oui, NetFlow v5 (panneau « NetFlow v5 (resume d'exports) » de la page Résultats : exports ajoutés, Top, même résumé texte, export JSON ; autonome comme la CLI, issue #675) | `--netflow`, `--netflow-top` | `POST /analyses/{analysis_id}/netflow` (issue #675), `exporters`, `top` |
| Module IA local | non | `--ai-baseline-save`, `--ai-baseline-label`, `--ai-anomalies`, `--ai-training-export`, `--ai-classify`, `--ai-summary`, `--ai-endpoint`, `--ai-report` ; `netcross-ai-models` | non |
| Plugins | non | `--plugins`, `--plugin-path`, `--plugin-export`, `--list-plugins` | non |

## Formats de sortie

| Sortie | GUI | CLI | API |
|---|---|---|---|
| Rapport texte | oui (page Résultats) | sortie standard | `GET /analyses/{id}/text` (issue #670) |
| PDF | oui (« Exporter en PDF ») | `--pdf-report` | `GET /analyses/{id}/pdf?topn=N` (issue #670) |
| JSON structuré | oui (« Exporter en JSON », mêmes clés que la CLI) | `--json-report` | `GET /analyses/{analysis_id}/report` (mêmes clés) ; `GET /analyses/{analysis_id}` sert le format brut, voir ci-dessous |
| Markdown | oui (« Exporter en Markdown », analyse simple, même document ; issue #864) | `--md-report` | `GET /analyses/{analysis_id}/markdown` (issue #864) |
| CSV du détail par flux | oui (« Exporter en CSV ») | `--detail-csv` | `GET /analyses/{id}/detail.csv` (issue #670) |
| Graphiques Top-N du PDF | oui (« Top-N graphiques ») | `--topn-charts` | `topn` de `GET /analyses/{analysis_id}/pdf` (issue #865) |
| Rapport de sécurité HTML / JSON | oui (section Sécurité, 2 boutons) | `--security-html` ; clé `security_report` de `--json-report` | `GET /analyses/{analysis_id}/security` (liste simplifiée) |
| Diagramme de séquence | oui (« Diagramme de sequence » de la configuration, dans l'export PDF ; issue #674) | `--sequence-diagram` | `GET /analyses/{analysis_id}/sequence` (issue #674), `format`, `max_flows` |
| Export SIEM (CEF, LEEF, STIX) | oui (panneau « SIEM, ticket de support, historique » de la page Résultats, après un rapport de sécurité, même fichier ; issue #674) | `--siem-export`, `--siem-output` | `GET /analyses/{analysis_id}/siem` (issue #674), `format` |
| Historique SQLite | oui (« Historique... » et « Etiquette » de la configuration, derniers runs dans le panneau « SIEM, ticket de support, historique » ; issue #674) | `--history-db`, `--history-label`, `--history-show` ; `netcross-history` | persistance propre (`NETCROSS_DB_PATH`), `GET /analyses` |
| Ticket de support anonymisé | oui (case de consentement et « Ticket de support... » du panneau « SIEM, ticket de support, historique », ticket « diagnostic », toutes portées ; issue #674) | `--support-ticket`, `--support-consent`, `--support-scope`, `--support-map`, `--support-marker` | `POST /analyses/{analysis_id}/support-ticket` (issue #674), `consent`, `kind` |

### Deux JSON côté API

`GET /analyses/{analysis_id}/report` renvoie le document de
`netcross_report.json_report.build_json_report_document`, celui que
`--json-report` écrit : mêmes clés, mêmes constats, même score de santé
(`tests/test_api_rapport_structure.py`). Le rapport de sécurité y est
toujours présent, car l'API le calcule à chaque analyse.

`GET /analyses/{analysis_id}` renvoie `report_document(report)`
(`netcross_api/store.py`) : la **copie brute de chaque champ** de l'objet
`Report`, soit 146 clés sur les captures d'exemple. `--json-report`, et
l'export JSON de la GUI, passent par `netcross_report.json_report`, qui
calcule 23 clés structurées. Mesuré sur les mêmes captures, 15 clés de la
CLI sont absentes de ce dump brut : `findings`, `triage`, `health_score`,
`health_label`, `flows`, `conversations`, `expert_events`, `diagnoses`,
`compliance`, `wireshark_expert_events`, `security_report`,
`security_report_absent`, `meta`, `title`, `generated_at`. Un client de
cette route reçoit donc les mesures brutes, sans constats ni triage : elle
est conservée telle quelle pour les clients existants.

## Capture en direct

| Fonction | GUI | CLI | API |
|---|---|---|---|
| Capture sur interfaces, un filtre BPF par point | oui (case « Capture en direct ») | `--live` | non |
| Durée maximale | oui | `--live-duration` | non |
| Arrêt manuel puis analyse | oui (« Arreter et analyser ») | Ctrl+C | non |
| Rotation de capture (ring buffer) | oui (« Rotation de capture », nombre de fichiers, durée par fichier) : même enregistreur que la CLI, répertoires et fichiers conservés indiqués dans le journal | `--ring-buffer N:SECONDES` : enregistre la capture brute de chaque point en pcapng tournants (ring buffer natif de tshark), incompatible avec `pipe://` (issue #676) | non |
| Bibliothèque de filtres BPF enregistrés | oui (enregistrer, choisir) | `--bpf-library NOM` (lit `~/.netcross/bpf_filters.json`, issue #676) | non |
| Rapport HTML rafraîchi en continu | oui (« Rapport HTML en continu », répertoire, intervalle, « Servir la page » et port ; issue #676) | `--live-report`, `--live-report-interval`, `--live-report-serve` | non |
| Notifications (webhook, Slack, e-mail) | oui (« Notifier si », webhook, Slack, courriel, « Detail complet » ; avec « Rapport de securite », issue #676) | `--notify-on`, `--notify-webhook`, `--notify-slack`, `--notify-email`, `--notify-detail`, `--notify-silence`, `--notify-state` | `notify_on`, `notify_webhook`, `notify_slack`, `notify_email`, `notify_detail` (trace dans `security_report.notifications` de `/report`, URL jamais conservées ; issue #875) |

**API : hors périmètre (issue #676).** Aucune route ne lance de capture en
direct : elle exigerait les droits de capture sur la machine du serveur et
une session longue (démarrage, arrêt, rapport rafraîchi), alors que l'API
travaille en requête/réponse sur des fichiers téléversés. Rotation de
capture, bibliothèque BPF, rapport en continu et courant capturé en direct
restent donc en GUI et en CLI ; les notifications portent sur le rapport
de sécurité, déjà produit par `POST /analyses`.

## Comparaison avant/après

| Fonction | GUI | CLI (`cross_capture_diff_cli.py`) | API |
|---|---|---|---|
| Baseline et courant en fichiers | oui (case « Mode comparaison ») | `--baseline`, `--current` | `POST /comparisons` (issue #669) |
| Courant capturé en direct | oui (« Mode comparaison » + « Capture en direct » : le panneau live remplace le courant en fichiers, durée maximale ; sans TLS/QUIC ni lecture parallèle du courant, issue #676) | `--live-current`, `--live-duration` | non |
| Seuils de régression | oui (pertes, latence) | `--loss-threshold-pp`, `--latency-threshold-ms` | `loss_threshold_pp`, `latency_threshold_ms` (issue #669) |
| TLS / QUIC de chaque côté | oui | `--tls`, `--quic` | `tls`, `quic` (issue #669) |
| Triage des écarts | oui (« Triage des ecarts (classement des segments) », Top) | `--triage`, `--triage-top-n` | `triage_top_n` (issue #669) |
| Exports | oui (PDF, CSV, JSON) | `--pdf-report`, `--diff-csv`, `--json-report` | `GET /comparisons/{id}/csv` (issue #669) |
| Anonymisation partagée | oui | `--redact`, `--redact-map` | `redact` (un seul pseudonyme par adresse pour baseline et courant), table : `GET /comparisons/{comparison_id}/redact-map` (issues #669, #876) |
| Historique | non | `--history-db`, `--history-label`, `--history-show` | non |
| Code de sortie 1 sur régression | sans objet | oui | `regression: true` dans la réponse (issue #669) |

Options de la CLI de comparaison reprises de l'analyse principale, avec
le même sens : `--order`, `--nat-tolerant`, `--nat-window-ms`,
`--bucket-ms`, `--rtp-clock-rate`, `--idle-timeout-seconds`,
`--parallel`, `--parallel-workers`, `--debug`.

Paramètres de l'API de comparaison (issue #669) : `baseline_files`,
`current_files` (fichiers pcap), `baseline_labels`, `current_labels`
(étiquettes), `points_order`, `nat_tolerant`, `nat_window_ms`, `tls`,
`quic`, `redact`, `loss_threshold_pp`, `latency_threshold_ms`,
`triage_top_n`, `wait`.

## Manipulation de captures (CLI uniquement, par choix)

Ces options transforment des fichiers et ne lancent pas d'analyse. Elles
n'ont pas leur place dans une interface d'analyse ni dans une API
d'analyse.

| Fonction | CLI |
|---|---|
| Fusion | `--merge`, `--merge-dedup` |
| Découpage | `--split`, `--split-output-dir` |
| Conversion de format | `--convert`, `--convert-format` |
| Export d'un sous-ensemble filtré | `--export-pcap`, `--export-bpf`, `--export-time-start`, `--export-time-end`, `--export-endpoints` |
| Recalage temporel | `--adjust-time-output`, `--time-offset`, `--normalize-time`, `--align-to` |
| Rejeu sur une interface | `--replay`, `--replay-speed`, `--replay-loop` |

## Autres points d'entrée

| Fonction | GUI | CLI | API |
|---|---|---|---|
| Dossier entier de captures | non | `cross_capture_batch_cli.py` : `--input`, `--output`, `--recursive`, `--no-group`, `--group-window`, `--min-overlap`, `--min-common-ips`, `--jobs`, `--skip-existing`, `--security-report` | `POST /batches` (`files`, captures ou archive ZIP ; `no_group`, `group_window`, `min_overlap`, `min_common_ips`, `jobs`, `security_report`), `GET /batches/{batch_id}` (avancement, groupes, échecs), `/index`, `/reports/{name}` ; `--skip-existing` sans objet (issue #872) |
| Documentation de l'API Lua de Wireshark | non | `netcross-lua-doc` (`--class`, `--classes`, `--full`, `--limit`, `--json`, `--source`, `--db`), `netcross lua-doc` | non |
| Historique des analyses | non | `cross_history_cli.py` : `--db`, `--label`, `--run-type`, `--limit` | `GET /analyses` |
| Mode debug | `--debug` au lancement | `--debug` (toutes les CLI) | `NETCROSS_DEBUG=1` |

## Vues propres à la GUI (sans équivalent CLI ni API)

| Vue | Rôle |
|---|---|
| Cartographie des communications (filtres protocole, Top-N, « Anomalies seulement ») | Qui parle à qui, anomalies en rouge |
| Annotations / signets | Étiquettes sur des trames, enregistrées à côté de la capture |
| Dashboard analytique | Sélection croisée segments / flux / hôtes / protocoles / événements |
| Exploration statistique (export CSV et JSON) | Top-N, tri, regroupement, drill-down |

Ce sont des vues d'exploration interactives. Leur calcul vit déjà hors de
la GUI (`netcross_report/comm_map.py`, `netcross_gtk4/stats_view.py`,
`netcross_gtk4/dashboard_context.py`), ce qui permettrait de les exposer
ailleurs si le besoin apparaissait.

## Inventaire des cases de la GUI

Libellés exacts, contrôlés par le test. Chacune est rattachée plus haut à
son équivalent CLI ou API.

| Case | Page | Équivalent |
|---|---|---|
| Mode comparaison (baseline / courant) -- equivalent de cross_capture_diff_cli.py | Configuration | `cross_capture_diff_cli.py` |
| Capture en direct (interfaces reseau, au lieu de fichiers) | Configuration | `--live`, `--ring-buffer`, `--bpf-library` |
| Rotation de capture (ring buffer) | Configuration | `--ring-buffer` |
| Rapport HTML en continu (--live-report) | Configuration (capture en direct) | `--live-report`, `--live-report-interval` |
| Servir la page (--live-report-serve) | Configuration (capture en direct) | `--live-report-serve` |
| Correlation tolérante au NAT | Configuration | `--nat-tolerant` |
| Détecter les doublons inter-captures | Configuration | `--detect-duplicates` |
| Exclure les doublons des statistiques | Configuration | `--exclude-duplicates` |
| Lecture parallele des captures | Configuration | `--parallel` |
| Anonymiser les adresses IP/MAC (--redact) | Configuration | `--redact` |
| Deduire la topologie automatiquement (ignore l'ordre de la liste) | Configuration | absence de `--order` |
| Séparer les interfaces d'un pcapng (--split-interfaces) | Configuration | `--split-interfaces` |
| Triage (classement des segments) | Configuration | `--triage` |
| Triage des ecarts (classement des segments) | Configuration (mode comparaison) | `--triage` (CLI de comparaison) |
| Diagnostic TLS | Configuration (2 cases : analyse et comparaison) | `--tls` |
| Diagnostic QUIC/HTTP3 | Configuration (2 cases : analyse et comparaison) | `--quic` |
| Rapport de securite | Configuration | `--security-report` |
| Index de recherche forensic (--forensic-search) | Configuration | `--forensic-search` |
| Moteur de regles (--rule-engine) | Configuration (analyse simple) | `--rule-engine` |
| Section expertise (--expert-section) | Configuration (analyse simple) | `--expert-section` |
| Qualite media (--media-quality) | Configuration (analyse de fichiers) | `--media-quality` |
| Statistiques tshark (--tshark-stats) | Configuration (analyse de fichiers) | `--tshark-stats` |
| Chronologie des flux (--flow-timeline) | Configuration (analyse simple) | `--flow-timeline` |
| Plages TEST-NET externes (--test-net-external) | Configuration (analyse simple) | `--test-net-external` |
| Audio (voix RTP) | Résultats (contenus) | `--extract-kinds audio` |
| Video (RTP) | Résultats (contenus) | `--extract-kinds video` |
| Documents (HTTP, SMB, courriel, TFTP, FTP) | Résultats (contenus) | `--extract-kinds documents` |
| Detail complet (--notify-detail complet) | Configuration | `--notify-detail complet` |
| J'autorise la remontee d'un ticket anonymise (--support-consent) | Résultats (SIEM, ticket, historique) | `--support-consent` |
| Anomalies seulement | Résultats (cartographie) | aucun |

## API : routes et réglages

| Route | Rôle |
|---|---|
| `GET /health` | Santé du service (sans authentification) |
| `POST /captures` | Un pcap : `file`, `label`, `extra_files`, `wait` | Une capture ; `wait` pour attendre le résultat |
| `POST /captures/multi` | Plusieurs captures : `files`, `labels`, `points_order`, `split_interfaces`, `wait` |

Options d'analyse des deux routes `POST` (champs de formulaire, sens de
l'option CLI de même nom) : `nat_tolerant`, `nat_window_ms`, `tls`,
`quic`, `redact`, `max_packets`, `sample`, `test_net_external`,
`parallel_workers`, `notify_on`, `notify_webhook`, `notify_slack`,
`notify_email`, `notify_detail` (issue #875), `names`,
`known_destinations`, `known_hosts` (issue #672), `rule_engine`,
`expert_section`, `media_quality`, `tshark_stats`, `flow_timeline`,
`flow_timeline_window` (issue #673), `bucket_ms`, `rtp_clock_rate`,
`idle_timeout_seconds`, `detect_duplicates`, `exclude_duplicates`,
`duplicate_threshold_ms` (issue #330, lot 1 de #841).
| `GET /analyses` | Liste des analyses |
| `GET /analyses/{analysis_id}` | Mesures brutes (voir plus haut) |
| `GET /analyses/{analysis_id}/report` | Rapport structuré, identique à `--json-report` |
| `GET /analyses/{analysis_id}/status` | État d'une analyse en tâche de fond |
| `GET /analyses/{analysis_id}/security` | Constats de sécurité |
| `GET /analyses/{analysis_id}/text` | Rapport texte (issue #670) |
| `GET /analyses/{analysis_id}/markdown` | Rapport Markdown (issue #864) |
| `GET /analyses/{analysis_id}/pdf` | Rapport PDF, `topn` (issue #670) |
| `GET /analyses/{analysis_id}/detail.csv` | CSV du détail par flux (issue #670) |
| `GET /analyses/{analysis_id}/redact-map` | Table adresse réelle -> pseudonyme, `redact=true` (issue #876) |
| `POST /comparisons` | Comparaison baseline/courant (issue #669) |
| `GET /comparisons/{comparison_id}` | Résultat d'une comparaison (issue #669) |
| `GET /comparisons/{comparison_id}/csv` | CSV des écarts (issue #669) |
| `POST /batches` | Lot de captures, équivalent de `cross_capture_batch_cli.py` (issue #872) |
| `GET /batches` | Lots conservés en mémoire (issue #872) |
| `GET /batches/{batch_id}` | Avancement et résultat d'un lot (issue #872) |
| `GET /batches/{batch_id}/index` | Index du lot, `index.txt` (issue #872) |
| `GET /batches/{batch_id}/reports/{name}` | Rapport d'une capture ou d'un groupe (issue #872) |
| `GET /comparisons/{comparison_id}/redact-map` | Table d'anonymisation commune baseline/courant (issue #876) |

Réglages par variables d'environnement (`NETCROSS_API_TOKEN` pour
l'en-tête `X-API-Key`, `NETCROSS_MAX_UPLOAD_MB`, `NETCROSS_API_MAX_FILES`,
`NETCROSS_API_WORKERS`, `NETCROSS_DB_PATH`, `NETCROSS_CVE_DB`) : voir
[API REST](api-rest.md).

## Écarts à traiter

Classés par impact pour un utilisateur :

1. ~~**API : JSON différent de celui de la CLI**~~ : traité,
   `GET /analyses/{analysis_id}/report` sert le document de
   `--json-report` ; le dump brut reste sur `GET /analyses/{analysis_id}`.
2. ~~**API : aucune option d'analyse.**~~ : traité, `nat_tolerant`,
   `nat_window_ms`, `tls`, `quic` et `redact` sur les deux routes `POST`,
   avec les mêmes incompatibilités que la CLI. Le triage n'est pas une
   option : il est toujours dans `GET /analyses/{analysis_id}/report`.
3. ~~**GUI : réglages d'analyse absents.**~~ : traité, « Fenêtre NAT (ms) »
   (réglable avec la corrélation tolérante au NAT), « Coupure silencieuse
   (s) » et « Table des noms... », valables en analyse simple, en
   comparaison et en capture en direct.
4. ~~**GUI : triage des écarts en mode comparaison**~~ : traité, case
   « Triage des ecarts » et nombre de segments (« Top ») dans les options
   de comparaison, même rendu que `--triage` / `--triage-top-n`.
5. Le reste (manipulation de captures, notifications, plugins, IA, SIEM,
   batch) relève de l'automatisation et reste en CLI **par choix**.

Correctifs apportés à l'audit du 24/09 (commentaire de #330) :

- l'analyseur compte 106 options, et non 90 ;
- le triage, TLS, QUIC et le rapport de sécurité **sont** dans la GUI,
  alors que l'audit les rangeait parmi les fonctions CLI seules ;
- « Rapport JSON : `GET /analyses/{id}` » n'est pas un équivalent de
  `--json-report` (voir plus haut) ;
- les annotations ne sont plus « non raccordées » (#363, fermée) ;
- la GUI a des fonctions que l'audit n'avait pas relevées : rotation de
  capture, bibliothèque de filtres BPF, cartographie, dashboard,
  exploration statistique.
