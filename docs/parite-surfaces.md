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
| CLI | `cross_capture_analyzer_cli.py` (106 options), `cross_capture_diff_cli.py` (27), `cross_capture_batch_cli.py` (11), `cross_history_cli.py`, `netcross_lua_doc_cli.py`, `netcross_ai_models_cli.py` | Surface de référence : tout y est |
| GUI | `netcross_gtk4` : 3 pages, 16 cases à cocher, 12 réglages numériques | Analyse interactive et exploration visuelle |
| API | 8 routes FastAPI | Analyse de base avec sécurité, sans aucune option |

Légende : **oui** = disponible ; **non** = absent ; **auto** = toujours
actif, non réglable.

## Réponse courte

- **Non, la parité n'est pas complète, et c'est en partie voulu.** La CLI
  est la surface complète. La GUI couvre l'analyse et le diagnostic
  interactifs, et ajoute des vues d'exploration sans équivalent CLI. L'API
  n'expose que l'analyse de base, sans aucune option.
- Le rapport JSON de l'API est désormais celui de la CLI :
  `GET /analyses/{analysis_id}/report` (constats, triage, score de santé).
  `GET /analyses/{analysis_id}` reste la copie brute des mesures.
- Les écarts à combler sont listés à la fin, dans
  [Écarts à traiter](#ecarts-a-traiter).

## Analyse croisée

| Fonction | GUI | CLI | API |
|---|---|---|---|
| Captures en fichiers, un nom par point | oui (liste + « Ajouter une capture ») | `--capture` | `POST /captures` (`file`, `label`), `POST /captures/multi` (`files`, `labels`) |
| Plusieurs fichiers pour un même point (rotation) | non | `--capture NOM=a,b` | non |
| Ordre des points imposé | oui (ordre de la liste) | `--order` | `points_order` |
| Topologie déduite automatiquement | oui (case « Deduire la topologie automatiquement ») | oui (sans `--order`) | oui (sans `points_order`) |
| Tolérance NAT | oui (« Correlation tolérante au NAT ») | `--nat-tolerant`, `--nat-window-ms` (fenêtre : CLI seule) | non |
| Doublons inter-captures | oui (« Détecter... », « Exclure... », seuil) | `--detect-duplicates`, `--exclude-duplicates`, `--duplicate-threshold-ms` | non |
| Lecture parallèle | oui (« Lecture parallele des captures ») | `--parallel`, `--parallel-workers` (nombre : CLI seule) | non |
| Fenêtre temporelle du débit | oui | `--bucket-ms` | non |
| Cadence RTP | oui | `--rtp-clock-rate` | non |
| Seuil de coupure NAT/pare-feu silencieuse | non | `--idle-timeout-seconds` | non |
| Limiter ou échantillonner les paquets | non | `--max-packets`, `--sample` | non |
| Noms logiques des hôtes | non | `--names` | non |
| Plages TEST-NET traitées comme externes | non | `--test-net-external` | non |
| Anonymisation IP/MAC | oui (« Anonymiser les adresses IP/MAC ») | `--redact`, `--redact-map` (table de correspondance : CLI seule) | non |

## Diagnostics et triage

| Fonction | GUI | CLI | API |
|---|---|---|---|
| Triage et score de santé | oui (case « Triage » + « Top ») | `--triage`, `--triage-top-n` | `GET /analyses/{analysis_id}/report` (clés `triage`, `health_score`) |
| Diagnostic TLS | oui (« Diagnostic TLS ») | `--tls` | non |
| Diagnostic QUIC/HTTP3 | oui (« Diagnostic QUIC/HTTP3 ») | `--quic` | non |
| Rapport de sécurité (détecteurs, signatures d'exploit, CVE) | oui (« Rapport de securite ») | `--security-report` | auto (toujours exécuté), `GET /analyses/{analysis_id}/security` |
| Base CVE complète (NVD) | non (base embarquée seule) | `--cve-db` | non (base embarquée seule) |
| Destinations et hôtes connus (sécurité) | non | `--known-destinations`, `--known-hosts` | non |
| Moteur de règles | non | `--rule-engine` | non |
| Section expertise détaillée | non | `--expert-section` | non |
| Qualité média (VoIP/vidéo) | non | `--media-quality` | non |
| Statistiques tshark natives | non | `--tshark-stats` | non |
| Chronologie des flux | non | `--flow-timeline`, `--flow-timeline-window` | non |
| Recherche forensic | non | `--forensic-search`, `--search-text`, `--search-address`, `--search-point`, `--search-protocol`, `--search-port`, `--search-field`, `--search-value` | non |
| Extraction des contenus | non | `--extract-contents`, `--extract-kinds` | non |
| Comparaison de postes | non | `--client-group`, `--client-reference`, `--client-diff-csv` | non |
| NetFlow / sFlow | non | `--netflow`, `--netflow-top` | non |
| Module IA local | non | `--ai-baseline-save`, `--ai-baseline-label`, `--ai-anomalies`, `--ai-training-export`, `--ai-classify`, `--ai-summary`, `--ai-endpoint`, `--ai-report` ; `netcross-ai-models` | non |
| Plugins | non | `--plugins`, `--plugin-path`, `--plugin-export`, `--list-plugins` | non |

## Formats de sortie

| Sortie | GUI | CLI | API |
|---|---|---|---|
| Rapport texte | oui (page Résultats) | sortie standard | non |
| PDF | oui (« Exporter en PDF ») | `--pdf-report` | non |
| JSON structuré | oui (« Exporter en JSON », mêmes clés que la CLI) | `--json-report` | `GET /analyses/{analysis_id}/report` (mêmes clés) ; `GET /analyses/{analysis_id}` sert le format brut, voir ci-dessous |
| CSV du détail par flux | oui (« Exporter en CSV ») | `--detail-csv` | non |
| Graphiques Top-N du PDF | oui (« Top-N graphiques ») | `--topn-charts` | non |
| Rapport de sécurité HTML / JSON | oui (section Sécurité, 2 boutons) | `--security-html` ; clé `security_report` de `--json-report` | `GET /analyses/{analysis_id}/security` (liste simplifiée) |
| Diagramme de séquence | non | `--sequence-diagram` | non |
| Export SIEM (CEF, LEEF, STIX) | non | `--siem-export`, `--siem-output` | non |
| Historique SQLite | non | `--history-db`, `--history-label`, `--history-show` ; `netcross-history` | persistance propre (`NETCROSS_DB_PATH`), `GET /analyses` |
| Ticket de support anonymisé | non | `--support-ticket`, `--support-consent`, `--support-scope`, `--support-map`, `--support-marker` | non |

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
| Rotation de capture (ring buffer) | oui (« Rotation de capture », nombre de fichiers, durée) | non | non |
| Bibliothèque de filtres BPF enregistrés | oui (enregistrer, choisir) | non (`--live LABEL:IF:FILTRE` sans bibliothèque) | non |
| Rapport HTML rafraîchi en continu | non | `--live-report`, `--live-report-interval`, `--live-report-serve` | non |
| Notifications (webhook, Slack, e-mail) | non | `--notify-on`, `--notify-webhook`, `--notify-slack`, `--notify-email`, `--notify-detail`, `--notify-silence`, `--notify-state` | non |

## Comparaison avant/après

| Fonction | GUI | CLI (`cross_capture_diff_cli.py`) | API |
|---|---|---|---|
| Baseline et courant en fichiers | oui (case « Mode comparaison ») | `--baseline`, `--current` | non |
| Courant capturé en direct | non (modes exclusifs) | `--live-current`, `--live-duration` | non |
| Seuils de régression | oui (pertes, latence) | `--loss-threshold-pp`, `--latency-threshold-ms` | non |
| TLS / QUIC de chaque côté | oui | `--tls`, `--quic` | non |
| Triage des écarts | non | `--triage`, `--triage-top-n` | non |
| Exports | oui (PDF, CSV, JSON) | `--pdf-report`, `--diff-csv`, `--json-report` | non |
| Anonymisation partagée | oui | `--redact`, `--redact-map` | non |
| Historique | non | `--history-db`, `--history-label`, `--history-show` | non |
| Code de sortie 1 sur régression | sans objet | oui | sans objet |

Options de la CLI de comparaison reprises de l'analyse principale, avec
le même sens : `--order`, `--nat-tolerant`, `--nat-window-ms`,
`--bucket-ms`, `--rtp-clock-rate`, `--idle-timeout-seconds`,
`--parallel`, `--parallel-workers`, `--debug`.

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
| Dossier entier de captures | non | `cross_capture_batch_cli.py` : `--input`, `--output`, `--recursive`, `--no-group`, `--group-window`, `--min-overlap`, `--min-common-ips`, `--jobs`, `--skip-existing`, `--security-report` | non |
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
| Capture en direct (interfaces reseau, au lieu de fichiers) | Configuration | `--live` |
| Rotation de capture (ring buffer) | Configuration | aucun |
| Correlation tolérante au NAT | Configuration | `--nat-tolerant` |
| Détecter les doublons inter-captures | Configuration | `--detect-duplicates` |
| Exclure les doublons des statistiques | Configuration | `--exclude-duplicates` |
| Lecture parallele des captures | Configuration | `--parallel` |
| Anonymiser les adresses IP/MAC (--redact) | Configuration | `--redact` |
| Deduire la topologie automatiquement (ignore l'ordre de la liste) | Configuration | absence de `--order` |
| Triage (classement des segments) | Configuration | `--triage` |
| Diagnostic TLS | Configuration (2 cases : analyse et comparaison) | `--tls` |
| Diagnostic QUIC/HTTP3 | Configuration (2 cases : analyse et comparaison) | `--quic` |
| Rapport de securite | Configuration | `--security-report` |
| Anomalies seulement | Résultats (cartographie) | aucun |

## API : routes et réglages

| Route | Rôle |
|---|---|
| `GET /health` | Santé du service (sans authentification) |
| `POST /captures` | Une capture ; `wait` pour attendre le résultat |
| `POST /captures/multi` | Plusieurs captures : `files`, `labels`, `points_order`, `wait` |
| `GET /analyses` | Liste des analyses |
| `GET /analyses/{analysis_id}` | Mesures brutes (voir plus haut) |
| `GET /analyses/{analysis_id}/report` | Rapport structuré, identique à `--json-report` |
| `GET /analyses/{analysis_id}/status` | État d'une analyse en tâche de fond |
| `GET /analyses/{analysis_id}/security` | Constats de sécurité |

Réglages par variables d'environnement (`NETCROSS_API_TOKEN` pour
l'en-tête `X-API-Key`, `NETCROSS_MAX_UPLOAD_MB`, `NETCROSS_API_MAX_FILES`,
`NETCROSS_API_WORKERS`, `NETCROSS_DB_PATH`) : voir
[API REST](api-rest.md).

## Écarts à traiter

Classés par impact pour un utilisateur :

1. ~~**API : JSON différent de celui de la CLI**~~ : traité,
   `GET /analyses/{analysis_id}/report` sert le document de
   `--json-report` ; le dump brut reste sur `GET /analyses/{analysis_id}`.
2. **API : aucune option d'analyse.** Au minimum `nat_tolerant`, `tls`,
   `quic`, `redact` et `triage`, qui changent le résultat. Sans `nat_tolerant`, une
   analyse à travers un NAT par l'API compte comme perdus des paquets
   simplement traduits.
3. **GUI : réglages d'analyse absents.** `--idle-timeout-seconds`,
   `--nat-window-ms` et `--names` changent le résultat sans pouvoir être
   réglés dans la GUI.
4. **GUI : triage des écarts en mode comparaison**, disponible en CLI
   (`--triage` de la CLI de comparaison).
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
