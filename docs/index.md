# Netcross

Netcross est un outil d'analyse croisée de captures réseau multi-points.
Il exploite tshark pour la dissection, fournit un moteur de corrélation
et d'analyse (`netcross_core`), un générateur de rapports (`netcross_report`),
des CLI (`cross_capture_analyzer_cli`, `cross_capture_diff_cli`,
`cross_history_cli`), une API REST FastAPI, et une interface GTK4.

## Par où commencer

- **Utiliser Netcross** : le [guide utilisateur](guide/index.md), de
  l'installation à la lecture du rapport, avec des captures d'exemple
- **Première analyse** : `cross_capture_analyzer_cli.py --capture LAN=lan.pcapng --capture WAN=wan.pcapng`
  (voir [Première analyse](guide/premiere-analyse.md))
- **Comparaison de runs** : `cross_capture_diff_cli.py --baseline LAN=avant.pcapng --current LAN=apres.pcapng`
- **API REST** : voir la spec OpenAPI (`docs/openapi.yaml`)

## Ce que Netcross fait

- Capture multi-points (fichiers `.pcap`/`.pcapng` ou live via dumpcap)
- Dissection complète via tshark (TCP, UDP, TLS, QUIC, DNS, HTTP, SIP…)
- Empreintes JA4 (TLS) et HASSH (SSH) vérifiées contre tshark
- Détection de beaconing C2, tunneling DNS, exfiltration, mouvements latéraux
- Rapport de sécurité structuré (PDF, JSON, CSV)
- Export SIEM (CEF), historique SQLite, comparaison de runs (diff)
- Corrélation CVE (base NVD locale, hors-ligne au runtime)

## Ce que Netcross ne fait pas

- Inspection de paquets en temps réel sur le backbone (outil d'analyse post-capture)
- Remplacement d'un IDS/IPS (pas de mitigation automatique)
- Gestion de politiques réseau (pas de règles de pare-feu)
