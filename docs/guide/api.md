# Automatiser avec l'API

L'API REST permet d'envoyer des captures à Netcross depuis un autre outil :
supervision, ticketing, script de collecte. Elle produit les mêmes analyses
que la ligne de commande. Cette page présente l'essentiel. La référence
complète (déploiement, persistance, limites de taille, schéma OpenAPI) est
dans [API REST](../api-rest.md).

## Démarrer le service

```bash
pip install -e ".[api]"
NETCROSS_API_TOKEN=$(openssl rand -hex 32) \
  uvicorn netcross_api.app:app --host 127.0.0.1 --port 8000
```

Avec `NETCROSS_API_TOKEN`, chaque requête doit porter l'en-tête
`X-API-Key` avec ce jeton. Sans ce jeton, l'API est ouverte : réservez ce
cas à un poste local.

## Envoyer des captures

Une capture :

```bash
curl -X POST "http://localhost:8000/captures?wait=true" \
  -H "X-API-Key: $NETCROSS_API_TOKEN" \
  -F "file=@lan.pcap" -F "label=LAN"
```

Plusieurs points, comme `--capture LAN=... --capture WAN=... --order LAN,WAN` :

```bash
curl -X POST "http://localhost:8000/captures/multi?wait=true" \
  -H "X-API-Key: $NETCROSS_API_TOKEN" \
  -F "files=@lan.pcap" -F "files=@wan.pcap" \
  -F "labels=LAN,WAN" -F "points_order=LAN,WAN"
```

Sans `?wait=true`, la réponse arrive tout de suite (`202`), avec une
adresse `status_url` à consulter jusqu'à ce que l'état passe à
`completed`. Le résumé donne, pour chaque segment, les pertes et le délai.

Un pcapng pris sur plusieurs interfaces peut être envoyé seul, avec
`split_interfaces=true` : chaque interface devient un point, nommé
`ETIQUETTE:INTERFACE`, comme avec `--split-interfaces`. `points_order`, s'il est
fourni, cite alors ces étiquettes (`SW:eth0,SW:eth1`) ; il est vérifié après
la séparation.

```bash
curl -X POST "http://localhost:8000/captures/multi?wait=true" \
  -H "X-API-Key: $NETCROSS_API_TOKEN" \
  -F "files=@switch.pcapng" -F "labels=SW" -F "split_interfaces=true"
```

## Options d'analyse

Ce sont des champs de formulaire, qui ont le même sens que l'option de même
nom dans la ligne de commande :

| Champ | Effet | Ligne de commande |
|---|---|---|
| `nat_tolerant`, `nat_window_ms` | Corrélation à travers un NAT, et fenêtre en ms (défaut : 200) | `--nat-tolerant`, `--nat-window-ms` |
| `tls`, `quic` | Diagnostics TLS et QUIC | `--tls`, `--quic` |
| `redact` | Anonymise les adresses (le rapport de sécurité n'est alors pas calculé, et `redact` est refusé avec `tls` ou `quic`) | `--redact` |
| `bucket_ms` | Fenêtre de mesure du débit en ms (défaut : 1000) | `--bucket-ms` |
| `rtp_clock_rate` | Horloge RTP en Hz pour la gigue voix/vidéo (défaut : 8000) | `--rtp-clock-rate` |
| `idle_timeout_seconds` | Seuil de coupure NAT/pare-feu silencieuse (défaut : 60 s) | `--idle-timeout-seconds` |
| `detect_duplicates`, `exclude_duplicates`, `duplicate_threshold_ms` | Doublons inter-captures : compter, exclure, seuil en ms | `--detect-duplicates`, `--exclude-duplicates`, `--duplicate-threshold-ms` |
| `split_interfaces` | Un point par interface d'un pcapng (`/captures/multi` uniquement) | `--split-interfaces` |
| `extra_files` | Segments suivants d'une capture en rotation, pour le même point (`/captures` uniquement ; avec `/captures/multi`, répétez l'étiquette dans `labels`) | `--capture NOM=a,b` |

Une valeur hors bornes (fenêtre nulle ou négative, par exemple) est
refusée avec un code `422`. Une combinaison incompatible (`redact` avec
`tls`) est refusée avec un code `400`. Dans les deux cas, la réponse
contient un message explicite.

## Récupérer les résultats

| Besoin | Requête |
|---|---|
| État d'une analyse | `GET /analyses/{id}/status` |
| Rapport complet, identique à `--json-report` (constats, triage, score de santé) | `GET /analyses/{id}/report` |
| Constats de sécurité | `GET /analyses/{id}/security` |
| Liste des analyses | `GET /analyses` |

La comparaison avant/après et les exports PDF, CSV ou SIEM ne sont pas
encore disponibles par l'API. Utilisez pour cela la ligne de commande
(voir [Comparer deux situations](comparer.md)). Le tableau complet des
écarts entre surfaces est dans [Parité GUI / CLI / API](../parite-surfaces.md).

## Capturer en direct sur le serveur

L'API peut capturer elle-même sur les interfaces du serveur, un filtre BPF
par point, comme `netcross --live`. C'est désactivé par défaut :
l'administrateur l'active et choisit les interfaces autorisées.

```bash
export NETCROSS_API_TOKEN=un-secret          # obligatoire pour la capture
export NETCROSS_API_LIVE=1
export NETCROSS_API_LIVE_INTERFACES=eth0,eth1
export NETCROSS_API_LIVE_MAX_DURATION=300    # secondes, 300 par défaut
```

Le compte du service doit avoir le droit de capturer (par exemple
`sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap`, ou le groupe
`wireshark`).

```bash
curl -X POST -H "X-API-Key: $NETCROSS_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"points": [{"name": "LAN", "interface": "eth0", "bpf": "tcp port 443"},
                  {"name": "WAN", "interface": "eth1"}],
       "duration": 60, "options": {"nat_tolerant": true}}' \
  http://localhost:8000/live-captures
curl -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/live-captures/$CAPTURE_ID
curl -X POST -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/live-captures/$CAPTURE_ID/stop
curl -X DELETE -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/live-captures/$CAPTURE_ID
```

L'état passe de `capturing` à `analysing` puis `completed` ; il donne alors
`analysis_id`, et le résultat se lit sous `/analyses/{analysis_id}` comme
pour des fichiers envoyés. Une seule capture à la fois par serveur.

`/stop` arrête la capture avant la fin de `duration` et renvoie aussitôt
l'`analysis_id` de l'analyse qui démarre. `DELETE` abandonne au contraire
la capture sans l'analyser : les fichiers sont supprimés et l'état passe à
`cancelled`.

Au lieu d'écrire un filtre, un point peut prendre un filtre enregistré de
la bibliothèque (`GET /bpf-filters`) : `{"name": "LAN", "interface": "eth0",
"bpf_library": "web"}`.

Pour garder aussi la capture brute, comme `--ring-buffer N:SECONDES`,
ajoutez `"ring_buffer": {"files": 5, "seconds": 60}`. Chaque point enregistre
alors en parallèle au plus 5 fichiers pcapng de 60 s, les plus anciens étant
écrasés ; l'analyse, elle, porte sur toute la capture. Ces fichiers restent
sur le serveur après l'analyse :

```bash
curl -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/live-captures/$CAPTURE_ID/files
curl -OJ -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/live-captures/$CAPTURE_ID/files/LAN/LAN_00001_20261013120000.pcapng
curl -X DELETE -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/live-captures/$CAPTURE_ID/files
```

Ils ne sont supprimés que par ce `DELETE`, par l'abandon de la capture,
ou par le nettoyage du répertoire temporaire du système. Le ring buffer
est refusé pour une source `pipe://`, comme en CLI.

## Annoter une analyse

```bash
curl -X POST -H "X-API-Key: $NETCROSS_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"point": "point-A", "frame_number": 42, "tag": "suspect", "comment": "RST inattendu"}' \
  http://localhost:8000/analyses/$ID/annotations
curl -H "X-API-Key: $NETCROSS_API_TOKEN" "http://localhost:8000/analyses/$ID/annotations?tag=suspect"
```

Le serveur ne garde pas les captures téléversées : les annotations sont
rangées dans l'analyse, par point, au format du fichier
`<capture>.annotations.json` de la GUI. Recopier une liste dans ce fichier,
à côté de votre capture, la fait apparaître dans la GUI et dans
`netcross annotations`.
