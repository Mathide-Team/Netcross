# Changelog

Tous les changements notables du projet Netcross sont documentés dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et le projet adhère au [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

### Ajouté
- `netcross_gtk4/bpf_panel.py` — décisions du panneau de filtres BPF de la
  capture live extraites de `app.py` et couvertes à **100 %** (62 tests) :
  conversion indice de menu ↔ filtre, infobulle, désolidarisation du menu sur
  édition manuelle, validation d'enregistrement, bornes de déplacement (#285)
- `tests/test_history_cli.py` et `tests/test_cli_entrypoints.py` — première
  couverture des points d'entrée : `cross_history_cli.py` **0 % → 100 %**,
  analyzer 54,5 % → 61,3 %, diff 60,6 % → 62,4 %. Inventaire des codes de
  retour documenté dans le module de test (#287)
- `tests/test_pdf_report.py` et `tests/test_charts.py` — première couverture
  dédiée du rendu : `pdf.py` 63,1 % → 77,9 %, `charts.py` 41,2 % → 93,5 %. Le
  texte est réextrait des PDF produits (`pdftotext`) plutôt qu'inspecté avant
  rendu, et `generate_diff_pdf` — le rapport du mode comparaison — passe de
  zéro test à une couverture de bout en bout (#286)
- `netcross_gtk4/panel_state.py` — visibilité des panneaux, état du bouton
  Lancer, filtres de cartographie et sélection au tableau de bord, sortis de
  `app.py` (#285, troisième lot)
- Le bouton Lancer explique en infobulle pourquoi il est inactif — combien de
  captures manquent, et en mode live le compte porte sur les points **après**
  éclatement des interfaces, ce que l'utilisateur ne pouvait pas deviner (#285)
- `netcross_gtk4/run_outcome.py` — état de résultat de la GUI en structure
  unique et gelée : les quatorze champs `last_*` étaient réécrits séparément
  par l'analyse et par la comparaison, sans garantie qu'elles restent
  synchronisées, ce qui exposait à un affichage de données du run précédent
  (#285, deuxième lot)
- `netcross_gtk4/row_labels.py` — les douze fonctions de libellé et de clé de
  tri des lignes de la GUI, sorties de `app.py` pour devenir testables :
  elles étaient à 0 % non par difficulté mais parce que leur fichier
  `import gi` en tête, intestable en CI (#285, premier lot)
- Le rapport de sécurité alimente désormais le JSON (`security_report`), le
  PDF (section dédiée) et un nouveau rendu HTML autonome `--security-html` —
  il n'existait qu'en sortie texte (#218)
- `netcross_report/security_report.py::security_report_to_dict()` — socle de
  sérialisation unique des quatre rendus (#218)
- `netcross_report/security_html.py` — fichier HTML unique, sans ressource
  externe, tableaux filtrables, mode sombre et impression (#218)
- `--security-report`, `--cve-db` et `--security-html` documentés dans
  `CLAUDE.md`, avec les modules du pipeline de sécurité (#216)
- Les empreintes JA4/HASSH sont enfin affichées dans le rapport de sécurité
  (`JA4=…` / `HASSH=…` + forme lisible tronquée) : elles étaient calculées
  puis silencieusement jetées avant l'affichage (#259)
- `known_fingerprints.json` peuplé de 7 empreintes réelles (curl TLS 1.2 et
  1.3, wget, `openssl s_client`, `python ssl`, OpenSSH client et serveur),
  chacune vérifiée identique à celle calculée par Wireshark (#259)
- `scripts/capture_reference_fingerprints.py` — génère la base depuis du
  trafic réel en boucle locale et rejette toute empreinte en désaccord avec
  tshark (#259)
- `docs/fingerprints-ja4-hassh.md` (#259)

### Corrigé
- Le tableau de bord analytique, la vue statistiques et la sélection de flux
  de la GUI plantaient silencieusement (`AttributeError` dans un callback
  `GLib.idle_add`) dès qu'un flux existait : les deux threads d'analyse
  transmettent le dict brut de `correlate()`, que ces vues orientées objets
  ne savent pas lire. `RunOutcome` porte désormais `flow_objects`, la
  `list[Flow]` dérivée du dict au seul point par lequel les deux chemins
  passent, et les vues concernées la consomment ; `last_flows` reste le dict
  brut pour le détail CSV, la cartographie et les objets de session, qui
  lisent les paquets (#453)
- Le bouton « Descendre » d'une ligne de capture n'avait pas la borne que
  « Monter » avait : il insérait au-delà de la fin sur la dernière ligne et ne
  restait en place que parce que GTK ajoute silencieusement en fin de liste.
  Les deux sens partagent désormais la même borne explicite (#285)
- Une base d'historique invalide (`--history-db` / `--db` pointant sur un
  fichier qui n'est pas du SQLite) faisait remonter `sqlite3.DatabaseError` en
  trace Python. Sur l'analyzer et le diff, l'historique étant écrit **à la fin**
  du run, toute l'analyse était perdue. Message nommant le chemin et code 1
  via `HistoryDatabaseError` (#287)
- Une capture introuvable n'était plus signalée sur la **branche de chargement
  par défaut** : `[A] 0 paquets chargés` était indistinguable d'une capture
  sans trafic IP, et l'avertissement « résultat incomplet » n'existait que sur
  `--parallel`. Les deux CLI rapportent désormais `ECHEC` par fichier dans les
  deux branches (#287)
- Un clic sur une vue du tableau de bord dont le type était mal orthographié
  n'avait aucun effet, sans message ni trace : la cascade de `elif` de
  `_dashboard_select` n'avait pas de branche finale. Un type inconnu lève
  désormais `UnknownViewTypeError` (#285)
- Avec les deux modes actifs, la page de configuration affichait le panneau de
  capture live **et** ceux de comparaison ; la priorité va au live, alignée sur
  l'ordre d'évaluation de `on_run_analysis` (#285)
- `CLAUDE.md` annonçait « 1150/1150 tests » et `mypy` intégré à l'outillage :
  la suite en compte 2958 et `mypy` n'est pas configuré dans le projet (#216)
- Le JSON écrit `security_report` dans tous les cas, avec le motif de
  l'absence : « non demandé », « rien trouvé » et « clé non produite par
  cette version » étaient indistinguables (#218)
- Journal de `apply_security_findings` : le compteur annoncé comme
  « fingerprints » comptait en réalité les incohérences de protocole (#259)
- Rapport texte : l'encapsulation au niveau fichier (lue par capinfos) est
  enfin affichée, et le code DLT par interface est traduit en nom lisible
  (`linktype 1 (Ethernet)`) (#263)
- `export_filtered()` : `bpf_filter` est replié dans le filtre d'affichage
  `-Y` au lieu de `-f`, que tshark refuse en relecture de fichier — tout
  appel avec ce paramètre échouait systématiquement (#261)
- `export_filtered()` et `adjust_timestamps()` imposent `-F pcap`/`-F pcapng`
  selon l'extension de sortie : sans cela tshark et editcap écrivaient du
  pcapng dans un fichier nommé `.pcap` (#262)
- CI : `tshark`/`editcap` sont installés et la CI échoue si un test
  `@requires_tshark` reste sauté — 6 tests n'avaient jamais pu s'exécuter (#262)
- 3 assertions de test erronées, révélées par leur première exécution réelle

### Ajouté
- Dockerfile et .dockerignore pour déploiement conteneurisé (#170)
- CONTRIBUTING.md — guide de contribution (#170)
- SECURITY.md — politique de sécurité et reporting CVE (#170)
- `netcross_core/config.py` — loader de configuration `.netcross.toml` (#170)
- `netcross_report/siem_export.py` — export CEF pour intégration SIEM (#170)
- `netcross_core/support/` — remontée de tickets anonymisés avec consentement
  explicite : crash, erreurs de traitement, journal et contexte (#269)
- `netcross_core/support/scrubber.py` — anonymisation de texte libre (IP, MAC,
  emails, URL, FQDN, noms de capture, répertoires personnels, secrets), en
  complément de `redact.py` qui ne traite que les champs structurés (#269)
- Options CLI `--support-ticket`, `--support-consent`, `--support-scope`,
  `--support-map`, `--support-marker` (#269)
- `docs/support-tickets.md` — documentation de la remontée de tickets (#269)
- `scripts/generate_openapi.py --check` + vérification en CI de la fraîcheur de
  `docs/openapi.yaml` (#209)

## [1.0.0] — 2026-09-22

### Ajouté
- Analyse croisée multi-points de captures Wireshark (.pcap/.pcapng)
- Corrélation de flux entre points (pertes, latence, QoS, retransmissions)
- Détection de signatures d'exploits (CVE-1 à CVE-5)
- Empreintes de services et versions (bannières, JA4, HASSH)
- Détection de tunneling DNS, beaconing C2, mouvements latéraux
- Détection DGA et fast flux DNS
- Extraction de fichiers (file carving) depuis captures
- Rapports PDF, JSON, CSV, texte
- Interface GTK4
- API REST FastAPI + spécification OpenAPI (#209)
- Logging structuré via loguru (#245)
- Pipeline CI/CD complet (lint, tests, coverage, guard main)
- Statistiques de flux et conversation (#145)
- Audit TLS (#153), découverte d'actifs (#151)
- Conversion de formats (#169), exfiltration de données (#148)

### Sécurité
- Politique de sécurité et procédure de reporting CVE (SECURITY.md)

---

Les versions antérieures ne sont pas trackées dans ce fichier.
Le projet utilisait des releases GitHub ad-hoc avant la version 1.0.0.
