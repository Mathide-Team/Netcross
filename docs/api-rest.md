# API REST Netcross (issue #209)

## Démarrage

```bash
# Installer les dépendances optionnelles
pip install -e ".[api]"

# Lancer le service
uvicorn netcross_api.app:app --reload --port 8000
```

Le service est accessible sur `http://localhost:8000`.

## Déploiement (issue #356)

Réglages par variables d'environnement, lues au démarrage :

| Variable | Défaut | Effet |
|----------|--------|-------|
| `NETCROSS_API_TOKEN` | absent | Jeton exigé dans l'en-tête `X-API-Key` sur toutes les routes sauf `/health` (401 sinon). Absent : authentification désactivée, **usage local uniquement**. |
| `NETCROSS_MAX_UPLOAD_MB` | `100` | Taille maximale d'un fichier (413). |
| `NETCROSS_API_MAX_FILES` | `16` | Fichiers par requête `/captures/multi` (400 au-delà). |
| `NETCROSS_API_WORKERS` | `2` | Analyses simultanées en tâche de fond. |
| `NETCROSS_DB_PATH` | absent | Base SQLite : analyses conservées et rechargées au redémarrage. Absent : tout reste en mémoire. |

```bash
NETCROSS_API_TOKEN=$(openssl rand -hex 32) NETCROSS_DB_PATH=/var/lib/netcross/api.db \
  uvicorn netcross_api.app:app --host 0.0.0.0 --port 8000
```

- **Upload** : chaque fichier est copié sur disque par blocs de 1 Mo, et
  jamais chargé en entier en mémoire. Le 413 tombe dès que la limite est
  franchie. Une requête dont le `Content-Length` dépasse déjà
  `NETCROSS_MAX_UPLOAD_MB × NETCROSS_API_MAX_FILES` est refusée avant la
  lecture du corps. Les fichiers temporaires sont supprimés après l'analyse,
  ou dès le refus.
- **Tâche de fond** : `POST /captures` et `POST /captures/multi` répondent
  `202` avec `status: "pending"` et `status_url`. Le parsing tshark et
  l'analyse tournent dans un pool de threads, hors de la boucle asyncio.
  `GET /analyses/{id}/status` passe ensuite à `completed` (avec le résumé)
  ou à `failed` (avec `error`). Tant que l'analyse n'est pas terminée,
  `GET /analyses/{id}` et `/security` répondent `409`. Avec `?wait=true`,
  la route attend la fin de l'analyse et renvoie directement le résumé
  (`201`), ou `400` en cas d'échec.
- **Persistance** : le store garde le document JSON du rapport, celui que
  sert `GET /analyses/{id}`, et le relit tel quel au redémarrage. Une
  analyse encore `pending` à l'arrêt du service repasse en `failed`
  (« analyse interrompue par un redemarrage du service »). Une base créée
  par la première version est migrée : ses anciennes lignes, non
  relisibles, sont marquées `failed`.

La spécification OpenAPI est disponible sur :
- `http://localhost:8000/openapi.json` (JSON)
- `http://localhost:8000/docs` (Swagger UI interactif)
- `http://localhost:8000/redoc` (ReDoc)

## Endpoints

| Méthode | Path | Description |
|---------|------|-------------|
| `POST` | `/captures` | Upload d'un pcap, lance l'analyse |
| `POST` | `/captures/multi` | Plusieurs pcaps étiquetés, analyse croisée entre points ; un seul pcapng multi-interfaces suffit avec `split_interfaces=true` (#474) |
| `GET` | `/analyses/{id}/status` | Statut `pending` / `completed` / `failed` (+ résumé) |
| `GET` | `/analyses/{id}` | Mesures brutes (copie de chaque champ du `Report`) |
| `GET` | `/analyses/{id}/report` | Rapport structuré, identique à `--json-report` : constats, triage, score de santé (issue #330) |
| `GET` | `/analyses/{id}/security` | Constats de sécurité |
| `GET` | `/analyses/{id}/markdown` | Rapport Markdown, identique à `--md-report` (issue #864) ; liste complète des routes : [parité des surfaces](parite-surfaces.md) |
| `GET` | `/analyses` | Liste des analyses |
| `GET` | `/health` | Health check |

## Exemples curl

### Upload d'une capture

```bash
curl -X POST http://localhost:8000/captures \
  -H "X-API-Key: $NETCROSS_API_TOKEN" \
  -F "file=@capture.pcapng" \
  -F "label=point-A"
```

Réponse `202` :
```json
{
  "analysis_id": "a1b2c3d4e5f6",
  "status": "pending",
  "status_url": "/analyses/a1b2c3d4e5f6/status"
}
```

Puis `GET /analyses/a1b2c3d4e5f6/status` jusqu'à :
```json
{
  "analysis_id": "a1b2c3d4e5f6",
  "status": "completed",
  "error": null,
  "summary": {"point_count": 1, "packet_count": 1247, "security_finding_count": 3}
}
```

Avec `POST /captures?wait=true`, la réponse est directement le résumé
(`201`, `"status": "completed"`).

### Analyse multi-points (issue #354)

Équivalent de `netcross -f LAN=lan.pcap -f DC=dc.pcap --order LAN,DC` :

```bash
curl -X POST http://localhost:8000/captures/multi \
  -F "files=@lan.pcap" -F "files=@dc.pcap" \
  -F "labels=LAN,DC" \
  -F "points_order=LAN,DC"
```

- `labels` : une étiquette par fichier, dans l'ordre des fichiers ; une
  étiquette manquante ou dupliquée est refusée (400).
- `points_order` (facultatif) : ordre amont -> aval. S'il est fourni, il
  doit citer chaque étiquette exactement une fois ; absent, l'ordre est
  déduit du trafic comme la CLI sans `--order` (`order_source: "auto"`).
- Chaque fichier est soumis à la même limite de taille (413) et au même
  jeton que `POST /captures`.

Résumé (`?wait=true`, ou `summary` de `/status`), avec les pertes comptées
au point aval comme dans le tableau « Qualité par segment » des rapports :
```json
{
  "analysis_id": "b2c3d4e5f6a1",
  "status": "completed",
  "point_count": 2,
  "packet_count": 2493,
  "security_finding_count": 0,
  "points": ["LAN", "DC"],
  "order_source": "points_order",
  "segments": [
    {
      "segment": "LAN -> DC",
      "upstream": "LAN",
      "downstream": "DC",
      "loss_count": 12,
      "loss_pct": 0.97,
      "seen_downstream": 1236,
      "off_path_count": 0,
      "latency_samples": 1224,
      "latency_avg_ms": 3.412
    }
  ]
}
```

Dans `GET /analyses/{id}`, les champs indexés par segment (`latency`,
`qos_change`, `hop_delta`...) ont pour clés `"amont -> aval"`.

### Récupérer le rapport complet

```bash
curl http://localhost:8000/analyses/a1b2c3d4e5f6
```

### Options d'analyse (issue #330)

Les deux routes `POST` acceptent, en champs de formulaire, les options de
la CLI qui changent le résultat :

| Champ | Défaut | Équivalent CLI |
|---|---|---|
| `nat_tolerant` | `false` | `--nat-tolerant` |
| `nat_window_ms` | `200` | `--nat-window-ms` (avec `nat_tolerant`) |
| `tls` | `false` | `--tls` (clé `tls_findings` du rapport structuré) |
| `quic` | `false` | `--quic` (clé `quic_findings` ; nécessite `cryptography`) |
| `redact` | `false` | `--redact` |

Mêmes règles que la CLI : `redact` avec `tls` ou `quic` est refusé (400),
car ces diagnostics relisent les fichiers d'origine avec les adresses
réelles ; avec `redact`, le rapport de sécurité n'est pas calculé
(`security_report_absent` l'indique). Les options retenues sont
enregistrées dans les métadonnées de l'analyse (`options`).

```bash
curl -X POST "http://localhost:8000/captures/multi?wait=true" \
  -F "files=@lan.pcap" -F "files=@dc.pcap" -F "labels=LAN,DC" \
  -F "nat_tolerant=true" -F "tls=true"
```

### Récupérer le rapport structuré (issue #330)

```bash
curl http://localhost:8000/analyses/a1b2c3d4e5f6/report
```

Même document que `netcross --json-report rapport.json --security-report`
et que l'export JSON de la GUI : `findings`, `triage`, `health_score`,
`health_label`, `security_report`... Le rapport de sécurité est toujours
calculé par l'API, la clé `security_report` n'est donc jamais vide. La
clé `meta` vaut `{"Source": "API REST"}` et `_analysis_id` est ajoutée.

Une analyse enregistrée (SQLite) avant cette route n'a pas de rapport
structuré : la route répond `409`, il faut relancer l'analyse.

### Récupérer les constats de sécurité

```bash
curl http://localhost:8000/analyses/a1b2c3d4e5f6/security
```

Réponse :
```json
{
  "analysis_id": "a1b2c3d4e5f6",
  "findings": [
    {
      "severity": "moyenne",
      "category": "anomalie",
      "detail": "mouvement lateral (port_scan) : ...",
      "point": "point-A"
    }
  ],
  "service_fingerprints": [],
  "lateral_movement_events": [],
  "dga_alerts": [],
  "fast_flux_alerts": []
}
```

### Health check

```bash
curl http://localhost:8000/health
```

## Génération de la spécification OpenAPI

```bash
python scripts/generate_openapi.py
```

La spec est écrite dans `docs/openapi.yaml`. En CI, on vérifie qu'elle est à
jour (même discipline que le diagramme de classes).

## Architecture

- `src/netcross_api/app.py` — application FastAPI, endpoints
- `src/netcross_api/models.py` — modèles Pydantic (requêtes/réponses)
- `src/netcross_api/store.py` — store des analyses (statut, document JSON, SQLite optionnel)
- `src/netcross_api/__init__.py` — exporte `app`

Le store en mémoire est un MVP. Pour la persistance, remplacer `AnalysesStore`
par une implémentation avec base de données sans changer les endpoints.
