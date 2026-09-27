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
`ETIQUETTE:INTERFACE`, comme avec `--split-interfaces`.

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
